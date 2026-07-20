package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

const (
	mcpFsReadDefaultMax = 1 * 1024 * 1024
	mcpFsWriteMaxSize   = 8 * 1024 * 1024
	mcpFsListMaxEntries = 5000
)

// mcpReply 把任意 result 结构序列化为 JSON 字符串，写入 pb.TaskResult.Data，并标 Successful。
// 任何序列化失败回退到一个明显的错误字符串，保证 dashboard 始终收到合法 JSON。
func mcpReply(result *pb.TaskResult, payload any) {
	b, err := json.Marshal(payload)
	if err != nil {
		result.Successful = false
		result.Data = `{"error":"agent: failed to marshal result"}`
		return
	}
	result.Successful = true
	result.Data = string(b)
}

// mcpReplyError 用于无法构造结构化结果（例如反序列化入参失败）的情况。
func mcpReplyError(result *pb.TaskResult, msg string) {
	result.Successful = false
	result.Data = msg
}

// ---------- fs helpers ----------

// resolveFsPath 校验 MCP fs.* 工具传入的目标路径。
//
// 契约（详见 mcp_fs_path_contract_test.go）：
//   - 只校验路径是 agent 宿主机上的绝对路径（filepath.IsAbs）。
//   - 不在 agent 进程内做 sandbox：调用方能动哪些路径完全取决于 agent
//     进程的文件系统权限。上层授权（PAT scope / server whitelist / MCP
//     kill switch）已经决定了某个调用方能不能命中"这台 agent"。
//   - root 形状路径（"/"、"C:\"、"\\srv\share"）由 mcp_fs_root_guard.go
//     的 isFilesystemRoot 单独拒绝，避免 os.RemoveAll("/") 这类灾难。
//
// 若未来要引入沙箱根目录，必须同步更新 mcp_fs_path_contract_test.go
// 里的契约测试。
func resolveFsPath(p string) (string, error) {
	if p == "" {
		return "", errors.New("path required")
	}
	if hasWindowsADSSuffix(p) {
		return "", errors.New("alternate data stream (ADS) paths are not supported")
	}
	clean := filepath.Clean(p)
	if !filepath.IsAbs(clean) {
		return "", errors.New("path must be absolute")
	}
	if hasWindowsADSSuffix(clean) {
		return "", errors.New("alternate data stream (ADS) paths are not supported")
	}
	return clean, nil
}

func fileTypeOf(mode os.FileMode) string {
	switch {
	case mode&os.ModeDir != 0:
		return "dir"
	case mode&os.ModeSymlink != 0:
		return "symlink"
	case mode&os.ModeDevice != 0, mode&os.ModeNamedPipe != 0, mode&os.ModeSocket != 0:
		return "special"
	default:
		return "file"
	}
}

func makeEntry(name string, info os.FileInfo, parent string) model.FsEntry {
	e := model.FsEntry{
		Name:        name,
		Type:        fileTypeOf(info.Mode()),
		Size:        info.Size(),
		Mode:        fmt.Sprintf("%#o", info.Mode().Perm()),
		ModTimeUnix: info.ModTime().Unix(),
	}
	if info.Mode()&os.ModeSymlink != 0 {
		e.IsSymlink = true
		full := filepath.Join(parent, name)
		if tgt, err := os.Readlink(full); err == nil {
			e.LinkTarget = tgt
		}
	}
	return e
}

// ---------- fs.list ----------

func handleFsListTaskWithConfig(gates taskFeatureGates, task *pb.Task, result *pb.TaskResult) {
	if gates.disableCommandExecute {
		mcpReply(result, model.FsListResult{Error: "agent disabled file operations"})
		return
	}
	var req model.FsListRequest
	if err := json.Unmarshal([]byte(task.GetData()), &req); err != nil {
		mcpReplyError(result, "invalid request: "+err.Error())
		return
	}
	clean, err := resolveFsPath(req.Path)
	if err != nil {
		mcpReply(result, model.FsListResult{Error: err.Error()})
		return
	}
	// Lstat-gate before os.Open: opening a FIFO/socket read-only blocks until
	// a peer appears, and this task has no timeout — a FIFO target would pin
	// the goroutine forever (remote DoS). Only directories are listable;
	// reject everything else up front (mirrors fs.read's IsRegular guard).
	li, err := os.Lstat(clean)
	if err != nil {
		mcpReply(result, model.FsListResult{Error: fsErrMsg(err)})
		return
	}
	if !li.IsDir() {
		mcpReply(result, model.FsListResult{Error: "path is not a directory"})
		return
	}
	// 流式读取目录而不是一次性 os.ReadDir(clean)：后者会在截断之前为整个目录
	// 分配 []DirEntry，目录里几十万条 entry 时直接吃光 agent 内存。改成按
	// 批 ReadDir(n) 读取，达到 mcpFsListMaxEntries 后仍继续计数（Total）但
	// 不再保留切片，O(返回上限) 内存而非 O(目录大小)。
	//
	// openDirNoFollow（非阻塞 + O_DIRECTORY + O_NOFOLLOW）取代 os.Open：消除
	// Lstat 确认目录后、打开前目标被换成 FIFO/symlink 的 TOCTOU——否则只读
	// 打开 FIFO 会永久阻塞这个无超时的 goroutine（远程 DoS）。
	dirf, err := openDirNoFollow(clean)
	if err != nil {
		mcpReply(result, model.FsListResult{Error: fsErrMsg(err)})
		return
	}
	defer dirf.Close()
	const fsListReadDirBatch = 256
	total := 0
	truncated := false
	out := make([]model.FsEntry, 0, mcpFsListMaxEntries)
	for {
		batch, readErr := dirf.ReadDir(fsListReadDirBatch)
		for _, de := range batch {
			name := de.Name()
			if !req.ShowHidden && strings.HasPrefix(name, ".") {
				continue
			}
			total++
			if len(out) >= mcpFsListMaxEntries {
				truncated = true
				continue
			}
			info, err := de.Info()
			if err != nil {
				continue
			}
			out = append(out, makeEntry(name, info, clean))
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			mcpReply(result, model.FsListResult{Error: fsErrMsg(readErr)})
			return
		}
	}
	mcpReply(result, model.FsListResult{Entries: out, Truncated: truncated, Total: total})
}

// ---------- fs.read ----------

func handleFsReadTaskWithConfig(gates taskFeatureGates, task *pb.Task, result *pb.TaskResult) {
	if gates.disableCommandExecute {
		mcpReply(result, model.FsReadResult{Error: "agent disabled file operations"})
		return
	}
	var req model.FsReadRequest
	if err := json.Unmarshal([]byte(task.GetData()), &req); err != nil {
		mcpReplyError(result, "invalid request: "+err.Error())
		return
	}
	clean, err := resolveFsPath(req.Path)
	if err != nil {
		_, msg := sanitizeFsError(err)
		mcpReply(result, model.FsReadResult{Error: msg})
		return
	}
	li, err := os.Lstat(clean)
	if err != nil {
		_, msg := sanitizeFsError(err)
		mcpReply(result, model.FsReadResult{Error: msg})
		return
	}
	if !li.Mode().IsRegular() {
		mcpReply(result, model.FsReadResult{Error: "path is not a regular file"})
		return
	}
	f, err := openRegularNoFollow(clean)
	if err != nil {
		_, msg := sanitizeFsError(err)
		mcpReply(result, model.FsReadResult{Error: msg})
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		_, msg := sanitizeFsError(err)
		mcpReply(result, model.FsReadResult{Error: msg})
		return
	}
	if !fi.Mode().IsRegular() {
		mcpReply(result, model.FsReadResult{Error: "path is not a regular file"})
		return
	}
	totalSize := fi.Size()

	if req.Offset > 0 {
		if _, err := f.Seek(req.Offset, io.SeekStart); err != nil {
			_, msg := sanitizeFsError(err)
			mcpReply(result, model.FsReadResult{Error: msg})
			return
		}
	}

	maxRead := req.Length
	if maxRead <= 0 || maxRead > mcpFsReadDefaultMax {
		maxRead = mcpFsReadDefaultMax
	}
	buf := make([]byte, maxRead)
	n, rerr := io.ReadFull(f, buf)
	if rerr != nil && !errors.Is(rerr, io.ErrUnexpectedEOF) && !errors.Is(rerr, io.EOF) {
		_, msg := sanitizeFsError(rerr)
		mcpReply(result, model.FsReadResult{Error: msg})
		return
	}
	data := buf[:n]
	truncated := req.Offset+int64(n) < totalSize

	encoding := req.Encoding
	if encoding == "" {
		encoding = "utf8"
	}
	var encoded string
	switch encoding {
	case "utf8":
		encoded = string(data)
	case "base64":
		encoded = base64.StdEncoding.EncodeToString(data)
	default:
		mcpReply(result, model.FsReadResult{Error: "unknown encoding: " + encoding})
		return
	}
	sum := sha256.Sum256(data)
	mcpReply(result, model.FsReadResult{
		Content:   encoded,
		Encoding:  encoding,
		Size:      int64(n),
		SHA256:    hex.EncodeToString(sum[:]),
		Truncated: truncated,
	})
}

// ---------- fs.write ----------

func handleFsWriteTaskWithConfig(gates taskFeatureGates, task *pb.Task, result *pb.TaskResult) {
	if gates.disableCommandExecute {
		mcpReply(result, model.FsWriteResult{Error: "agent disabled file operations"})
		return
	}
	var req model.FsWriteRequest
	if err := json.Unmarshal([]byte(task.GetData()), &req); err != nil {
		mcpReplyError(result, "invalid request: "+err.Error())
		return
	}
	clean, err := resolveFsPath(req.Path)
	if err != nil {
		mcpReply(result, model.FsWriteResult{Error: fsErrMsg(err)})
		return
	}
	if err := refuseFsTransferUploadAtRoot(clean); err != nil {
		mcpReply(result, model.FsWriteResult{Error: fsErrMsg(err)})
		return
	}

	// Serialise in-process writers on this path so the if_match_sha256
	// precondition check and the rename land atomically with respect to
	// other MCP callers (cross-process writers still need a platform
	// file lock — out of scope).
	unlockPath := fsPathMu.lock(clean)
	defer unlockPath()

	encoding := req.Encoding
	if encoding == "" {
		encoding = "utf8"
	}
	var data []byte
	switch encoding {
	case "utf8":
		data = fsWriteUTF8Data(req.Content)
	case "base64":
		b, decErr := base64.StdEncoding.DecodeString(req.Content)
		if decErr != nil {
			mcpReply(result, model.FsWriteResult{Error: "invalid base64: " + decErr.Error()})
			return
		}
		data = b
	default:
		mcpReply(result, model.FsWriteResult{Error: "unknown encoding: " + encoding})
		return
	}
	if len(data) > mcpFsWriteMaxSize {
		mcpReply(result, model.FsWriteResult{Error: "content exceeds max write size"})
		return
	}

	// 乐观锁：if_match_sha256 必须等于当前文件 sha256 才允许写。
	// 旧文件不存在且 if_match 非空 → 视为冲突。
	if req.IfMatchSHA256 != "" {
		li, lerr := os.Lstat(clean)
		if lerr != nil {
			if errors.Is(lerr, os.ErrNotExist) {
				mcpReply(result, model.FsWriteResult{Error: "if_match precondition failed: file does not exist"})
			} else {
				mcpReply(result, model.FsWriteResult{Error: fsErrMsg(lerr)})
			}
			return
		}
		if !li.Mode().IsRegular() {
			mcpReply(result, model.FsWriteResult{Error: "if_match precondition failed: target is not a regular file"})
			return
		}
		curHash, herr := sha256OfFile(clean)
		if herr != nil {
			mcpReply(result, model.FsWriteResult{Error: fsErrMsg(herr)})
			return
		}
		if curHash != req.IfMatchSHA256 {
			mcpReply(result, model.FsWriteResult{Error: "if_match precondition failed: sha256 mismatch"})
			return
		}
	}

	if req.CreateDirs {
		if err := os.MkdirAll(filepath.Dir(clean), 0o755); err != nil {
			mcpReply(result, model.FsWriteResult{Error: fsErrMsg(err)})
			return
		}
	}

	mode := os.FileMode(0o644)
	if req.Mode != "" {
		parsed, err := strconv.ParseUint(req.Mode, 8, 32)
		if err != nil {
			mcpReply(result, model.FsWriteResult{Error: "invalid mode: " + err.Error()})
			return
		}
		mode = os.FileMode(parsed) & os.ModePerm
	}

	tmp, err := os.CreateTemp(filepath.Dir(clean), ".mcp-write-*")
	if err != nil {
		mcpReply(result, model.FsWriteResult{Error: fsErrMsg(err)})
		return
	}
	tmpName := tmp.Name()
	cleanupTmp := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanupTmp()
		mcpReply(result, model.FsWriteResult{Error: fsErrMsg(err)})
		return
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		cleanupTmp()
		mcpReply(result, model.FsWriteResult{Error: fsErrMsg(err)})
		return
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanupTmp()
		mcpReply(result, model.FsWriteResult{Error: fsErrMsg(err)})
		return
	}
	if err := tmp.Close(); err != nil {
		cleanupTmp()
		mcpReply(result, model.FsWriteResult{Error: fsErrMsg(err)})
		return
	}
	if err := os.Rename(tmpName, clean); err != nil {
		if errors.Is(err, syscall.EXDEV) {
			if copyErr := copyFileFallback(tmpName, clean, mode); copyErr != nil {
				cleanupTmp()
				mcpReply(result, model.FsWriteResult{Error: fsErrMsg(copyErr)})
				return
			}
			cleanupTmp()
		} else {
			cleanupTmp()
			mcpReply(result, model.FsWriteResult{Error: fsErrMsg(err)})
			return
		}
	}
	// Flush the directory entry to stable storage before reporting OK so
	// a crash can't lose the rename even though the file contents were
	// fsynced.  POSIX guarantees data durability for fd.Sync but the
	// directory entry the rename created lives elsewhere. A failure here
	// means durability is not guaranteed, so it must be reported.
	if syncErr := fsyncDir(filepath.Dir(clean)); syncErr != nil {
		mcpReply(result, model.FsWriteResult{Error: fsErrMsg(syncErr)})
		return
	}
	sum := sha256.Sum256(data)
	mcpReply(result, model.FsWriteResult{
		Size:   int64(len(data)),
		SHA256: hex.EncodeToString(sum[:]),
	})
}

// copyFileFallback 跨设备 rename 失败时的兜底：复制到目标位置后删除源。
// 正常路径上 os.CreateTemp 已经把 tmp 放在目标同目录，理论上 EXDEV 不会
// 触发；保留作为防御性实现。
func copyFileFallback(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

// ---------- fs.delete ----------

func handleFsDeleteTaskWithConfig(gates taskFeatureGates, task *pb.Task, result *pb.TaskResult) {
	if gates.disableCommandExecute {
		mcpReply(result, model.FsDeleteResult{Error: "agent disabled file operations"})
		return
	}
	var req model.FsDeleteRequest
	if err := json.Unmarshal([]byte(task.GetData()), &req); err != nil {
		mcpReplyError(result, "invalid request: "+err.Error())
		return
	}
	clean, err := resolveFsPath(req.Path)
	if err != nil {
		mcpReply(result, model.FsDeleteResult{Error: fsErrMsg(err)})
		return
	}
	if isFilesystemRoot(clean) {
		mcpReply(result, model.FsDeleteResult{Error: "refusing to delete root"})
		return
	}
	count := 0
	if req.Recursive {
		_ = filepath.Walk(clean, func(_ string, _ os.FileInfo, err error) error {
			if err == nil {
				count++
			}
			return nil
		})
		if rmErr := os.RemoveAll(clean); rmErr != nil {
			mcpReply(result, model.FsDeleteResult{Error: fsErrMsg(rmErr)})
			return
		}
	} else {
		if rmErr := os.Remove(clean); rmErr != nil {
			if errors.Is(rmErr, syscall.EISDIR) {
				mcpReply(result, model.FsDeleteResult{Error: "is a directory; pass recursive=true to remove"})
				return
			}
			mcpReply(result, model.FsDeleteResult{Error: fsErrMsg(rmErr)})
			return
		}
		count = 1
	}
	mcpReply(result, model.FsDeleteResult{DeletedCount: count})
}
