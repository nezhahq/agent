package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

// gRPC Go ClientStream 不允许两个 goroutine 并发调用 SendMsg
// (https://pkg.go.dev/google.golang.org/grpc#ClientStream). MCP fs.transfer
// 在同一条 IOStream 上既要让 keepalive 周期发空帧，又要 upload/download 主
// 流程发协议帧，因此所有 Send 都必须经由 serialIOStreamSender 串行化。
type ioStreamSender interface {
	Send(*pb.IOStreamData) error
}

type serialIOStreamSender struct {
	mu     sync.Mutex
	stream pb.NezhaService_IOStreamClient
}

func newSerialIOStreamSender(stream pb.NezhaService_IOStreamClient) *serialIOStreamSender {
	return &serialIOStreamSender{stream: stream}
}

func (s *serialIOStreamSender) Send(d *pb.IOStreamData) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream.Send(d)
}

// serializedKeepAlive 是 fs.transfer 期间替代 ioStreamKeepAlive 的版本：
// 复用 serialIOStreamSender，保证心跳帧与协议帧共享同一串行化器，永远不会
// 与 NZTU / NZTD / NZTC / NZTO / NZTE 帧并发写入。
func serializedKeepAlive(ctx context.Context, sender *serialIOStreamSender, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sender.Send(&pb.IOStreamData{Data: []byte{}}); err != nil {
				printf("IOStream serializedKeepAlive failed: %v", err)
				return
			}
		}
	}
}

// MCP fs.upload / fs.download 走 IOStream 双向流而非 RequestTask 的一次性
// RPC，专为 ~100MB 量级大文件设计：避免 gRPC 默认 4MB 单消息上限，并且
// 不再一次性把整文件 base64 后塞进 JSON。
//
// 协议帧规格定义见 model.MCPFsXferMagic* 与 model.MCPFsTransferOp*。
//
// 上传时序（dashboard→agent）：
//
//	  agent ─▶ NZTU(magic+size)            // 通告"准备好接 size 字节"
//	  dashboard ─▶ chunk... (size bytes)   // 多帧任意大小的数据
//	  agent ─▶ NZTO(magic+sha256+size)     // 成功，附 sha256 校验
//	  agent ─▶ NZTE(magic+msg)             // 失败
//
// 下载时序（agent→dashboard）：
//
//	  agent ─▶ NZTD(magic+size+sha256)     // 通告"接下来会发 size 字节"
//	  agent ─▶ chunk... (size bytes)
//	  agent ─▶ NZTO(magic+sha256+size)     // 全部发完，附 sha256 终值
//	  agent ─▶ NZTE(magic+msg)             // 失败
//
// agent 任何分支失败都先发 NZTE 再关流，dashboard 据此把错误返回给调用方。

const (
	mcpFsTransferChunk      = 1 * 1024 * 1024 // 1MiB；与 fm.bufPool 同序，方便复用调试经验
	mcpFsTransferIOTimeout  = 5 * time.Minute // agent 单边阻塞最大时长（防止挂死）
	mcpFsTransferTempPrefix = ".mcp-xfer-"
)

// decideFsTransferEarlyError 把 fs.transfer 的 pre-IOStream 决策做成纯函数，
// 以便单测在不构造 gRPC 通道的前提下钉死契约。返回值含义：
//
//   - req:        成功解析的请求；JSON 解析失败时为 nil
//   - errMsg:     非空表示这是一个早退失败分支，应通过 NZTE 通知 dashboard
//   - hasStream:  errMsg 非空时还能不能 attach；只有同时拿到 stream_id 才有
//     可能走完 IOStream hello。stream_id 缺失 / JSON 完全解析失败时
//     hasStream=false，此时只能记录日志、放弃 attach（dashboard 侧会
//     在 30s WaitForAgent 超时兜底）。
//
// 没有任何错误时 errMsg=="" 且 hasStream=true，调用方按正常路径继续。
func decideFsTransferEarlyError(cfg model.AgentConfig, task *pb.Task) (*model.FsTransferRequest, string, bool) {
	var req model.FsTransferRequest
	if err := json.Unmarshal([]byte(task.GetData()), &req); err != nil {
		return nil, "FsTransfer 任务解析失败: " + err.Error(), false
	}
	if req.StreamID == "" {
		return &req, "FsTransfer 缺少必要参数: stream_id 为空", false
	}
	// stream_id 已知 → 失败分支仍可走完 IOStream hello + NZTE。
	if cfg.DisableCommandExecute {
		return &req, "FsTransfer 被 agent DisableCommandExecute 拒绝", true
	}
	if req.Path == "" {
		return &req, "FsTransfer 缺少必要参数: path 为空", true
	}
	switch req.Op {
	case model.MCPFsTransferOpUpload, model.MCPFsTransferOpDownload:
	default:
		return &req, "unknown op: " + req.Op, true
	}
	return &req, "", true
}

func handleFsTransferTask(task *pb.Task) {
	req, earlyErr, hasStream := decideFsTransferEarlyError(agentConfig, task)
	if earlyErr != "" && !hasStream {
		printf("%s", earlyErr)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), mcpFsTransferIOTimeout)
	// 不 defer cancel() — cancel 发 RST_STREAM 终止 stream，
	// 可能抢在 CloseSend 之前到达，dashboard 丢数据。

	stream, err := client.IOStream(ctx)
	if err != nil {
		cancel()
		printf("FsTransfer IOStream 拨号失败: %v", err)
		return
	}

	sender := newSerialIOStreamSender(stream)
	if err := sender.Send(&pb.IOStreamData{Data: append(
		[]byte{0xff, 0x05, 0xff, 0x05}, []byte(req.StreamID)...,
	)}); err != nil {
		cancel()
		printf("FsTransfer 发送 streamId 失败: %v", err)
		return
	}

	keepAliveCtx, stopKeepAlive := context.WithCancel(ctx)
	go serializedKeepAlive(keepAliveCtx, sender, 30*time.Second)

	runFsTransferOnStream(streamWithSerialSender{Stream: stream, sender: sender}, earlyErr, req)

	// 传输完成：先停 keepalive，再 CloseSend，等 dashboard 关流后 cancel。
	// 顺序保证 CloseSend 在 cancel 之前送达，drain 保证在 cancel 前收到对端确认。
	stopKeepAlive()
	stream.CloseSend()
	drainToEOF(stream)
	cancel()
}

// drainToEOF 丢弃空帧直到对端关闭。dashboard 读完所有数据后会通过
// CloseStream 关流，agent 端 Recv() 收到 io.EOF。
func drainToEOF(stream pb.NezhaService_IOStreamClient) {
	for {
		if _, err := stream.Recv(); err != nil {
			return
		}
	}
}

// streamWithSerialSender 让 runFsTransferOnStream 仍然按
// pb.NezhaService_IOStreamClient 的接口工作，但把 Send 全部走串行化器；
// CloseSend / Recv 等非写入侧方法仍直通底层 stream。
type streamWithSerialSender struct {
	pb.NezhaService_IOStreamClient
	Stream pb.NezhaService_IOStreamClient
	sender *serialIOStreamSender
}

func (s streamWithSerialSender) Send(d *pb.IOStreamData) error {
	return s.sender.Send(d)
}

func (s streamWithSerialSender) Recv() (*pb.IOStreamData, error) {
	return s.Stream.Recv()
}

func (s streamWithSerialSender) CloseSend() error {
	return s.Stream.CloseSend()
}

// runFsTransferOnStream 跑 attach 后的协议核心。早退分支只发一帧 NZTE
// 然后返回；正常分支按 op 派给 upload/download。抽出来是为了让单测能在
// 不构造 gRPC 通道的前提下钉死“早退即 NZTE”的契约，dashboard 端的
// readXferFixedHeader 会立即看到错误，而不是等到 30s WaitForAgent 超时。
func runFsTransferOnStream(stream pb.NezhaService_IOStreamClient, earlyErr string, req *model.FsTransferRequest) {
	if earlyErr != "" {
		sendXferErr(stream, earlyErr)
		return
	}
	switch req.Op {
	case model.MCPFsTransferOpUpload:
		fsTransferUpload(stream, req)
	case model.MCPFsTransferOpDownload:
		fsTransferDownload(stream, req)
	default:
		sendXferErr(stream, "unknown op: "+req.Op)
	}
}

// fsTransferUpload 接收 dashboard 推过来的 req.Size 字节并写入 req.Path。
// 写入策略与 fs.write 保持一致（先写临时文件再 rename），保证原子性，避免
// 半截内容覆盖目标文件。
func fsTransferUpload(stream pb.NezhaService_IOStreamClient, req *model.FsTransferRequest) {
	clean, err := resolveFsPath(req.Path)
	if err != nil {
		sendXferErr(stream, "invalid path: "+err.Error())
		return
	}
	if err := refuseFsTransferUploadAtRoot(clean); err != nil {
		sendXferErr(stream, fsErrMsg(err))
		return
	}
	if req.Size < 0 || req.Size > model.MCPFsTransferMaxSize {
		sendXferErr(stream, "size out of range: must be 0..100MiB")
		return
	}

	// The stripe lock must NOT span the network receive: a stalled caller
	// would otherwise block every in-process writer hashing to the same
	// stripe for the whole IO timeout (remotely triggerable DOS). We hold
	// it only across the if_match precondition and again across the rename;
	// the receive loop below writes to a private temp file and needs no lock.
	if req.IfMatchSHA256 != "" {
		unlockPre := fsPathMu.lock(clean)
		matchErr := checkIfMatchSHA256(clean, req.IfMatchSHA256)
		unlockPre()
		if matchErr != "" {
			sendXferErr(stream, matchErr)
			return
		}
	}

	if req.CreateDirs {
		if mkdirErr := os.MkdirAll(filepath.Dir(clean), 0o755); mkdirErr != nil {
			sendXferErr(stream, fsErrMsg(mkdirErr))
			return
		}
	}

	mode := os.FileMode(0o644)
	if req.Mode != "" {
		parsed, modeErr := strconv.ParseUint(req.Mode, 8, 32)
		if modeErr != nil {
			sendXferErr(stream, "invalid mode: "+modeErr.Error())
			return
		}
		mode = os.FileMode(parsed) & os.ModePerm
	}

	tmp, err := os.CreateTemp(filepath.Dir(clean), mcpFsTransferTempPrefix+"*")
	if err != nil {
		sendXferErr(stream, fsErrMsg(err))
		return
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	// 告诉 dashboard：我已经准备好了，请开始发 size 字节
	if sendErr := sendXferFixedHeader(stream, model.MCPFsXferMagicUploadHdr, uint64(req.Size), nil); sendErr != nil {
		_ = tmp.Close()
		cleanup()
		printf("FsTransfer 上传准备帧发送失败: %v", sendErr)
		return
	}

	h := sha256.New()
	recv := func() ([]byte, error) {
		data, recvErr := stream.Recv()
		if recvErr != nil {
			return nil, recvErr
		}
		return data.GetData(), nil
	}
	if _, bodyErr := receiveUploadBody(recv, tmp, h, req.Size); bodyErr != nil {
		_ = tmp.Close()
		cleanup()
		sendXferErr(stream, fsErrMsg(bodyErr))
		return
	}

	if expected := req.ExpectedSHA256; expected != "" {
		got := hex.EncodeToString(h.Sum(nil))
		if got != expected {
			_ = tmp.Close()
			cleanup()
			sendXferErr(stream, "sha256 mismatch")
			return
		}
	}

	if chmodErr := tmp.Chmod(mode); chmodErr != nil {
		_ = tmp.Close()
		cleanup()
		sendXferErr(stream, fsErrMsg(chmodErr))
		return
	}
	if syncErr := tmp.Sync(); syncErr != nil {
		_ = tmp.Close()
		cleanup()
		sendXferErr(stream, fsErrMsg(syncErr))
		return
	}
	if closeErr := tmp.Close(); closeErr != nil {
		cleanup()
		sendXferErr(stream, fsErrMsg(closeErr))
		return
	}
	// Re-acquire the stripe lock only for the check-then-rename window and
	// re-validate if_match so a concurrent writer that slipped in during the
	// (unlocked) receive cannot have its update silently clobbered.
	unlockRename := fsPathMu.lock(clean)
	if req.IfMatchSHA256 != "" {
		if matchErr := checkIfMatchSHA256(clean, req.IfMatchSHA256); matchErr != "" {
			unlockRename()
			cleanup()
			sendXferErr(stream, matchErr)
			return
		}
	}
	if renameErr := os.Rename(tmpName, clean); renameErr != nil {
		unlockRename()
		cleanup()
		sendXferErr(stream, fsErrMsg(renameErr))
		return
	}
	syncErr := fsyncDir(filepath.Dir(clean))
	unlockRename()
	if syncErr != nil {
		sendXferErr(stream, fsErrMsg(syncErr))
		return
	}

	finalHash := hex.EncodeToString(h.Sum(nil))
	_ = sendXferOK(stream, finalHash, req.Size)
}

// checkIfMatchSHA256 returns "" when the file at clean currently hashes to
// want, or a ready-to-send NZTE message otherwise. Caller must hold the path
// stripe lock so the hash and the subsequent rename observe the same state.
func checkIfMatchSHA256(clean, want string) string {
	cur, err := sha256OfFile(clean)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "if_match precondition failed: file does not exist"
		}
		return fsErrMsg(err)
	}
	if cur != want {
		return "if_match precondition failed: sha256 mismatch"
	}
	return ""
}

// enforceUploadOversend rejects any inbound payload whose length exceeds
// the declared remaining bytes. The pre-fix behaviour silently truncated
// and accepted, hiding protocol violations and potential corruption.
// Returning a fatal error here lets fsTransferUpload close + cleanup the
// temp file and surface NZTE to dashboard.
func enforceUploadOversend(payload []byte, remaining int64) ([]byte, error) {
	if int64(len(payload)) > remaining {
		return nil, errors.New("upload oversend: payload exceeds declared remaining size")
	}
	return payload, nil
}

// receiveUploadBody drains exactly size bytes from recv into w (hashing into
// h) and returns once the declared body is complete. It skips empty keep-alive
// frames and rejects any frame whose length would cross the size boundary
// (per-frame oversend). It returns the moment remaining hits 0 and MUST NOT
// call recv again: the honest dashboard sends no terminator after the body and
// is already waiting to read the agent's OK, so a post-body Recv would deadlock
// both sides (see mcp_transfer.go: io.CopyN then readXferFixedHeader). Trailing
// frames a misbehaving sender appends past size are unreachable here; they die
// with the per-transfer IOStream and cannot corrupt the size-bounded file.
func receiveUploadBody(recv func() ([]byte, error), w io.Writer, h hash.Hash, size int64) (int64, error) {
	var written int64
	remaining := size
	for remaining > 0 {
		payload, err := recv()
		if err != nil {
			return written, err
		}
		if len(payload) == 0 {
			continue
		}
		payload, err = enforceUploadOversend(payload, remaining)
		if err != nil {
			return written, err
		}
		n, err := w.Write(payload)
		written += int64(n)
		if err != nil {
			return written, err
		}
		h.Write(payload)
		remaining -= int64(len(payload))
	}
	return written, nil
}

// fsTransferDownload 把 req.Path 的内容推给 dashboard。req.Size 在下行场景
// 由 agent 决定（实际文件大小），dashboard 通过 NZTD 帧得知。
func fsTransferDownload(stream pb.NezhaService_IOStreamClient, req *model.FsTransferRequest) {
	clean, err := resolveFsPath(req.Path)
	if err != nil {
		sendXferErr(stream, "invalid path: "+err.Error())
		return
	}
	li, err := os.Lstat(clean)
	if err != nil {
		sendXferErr(stream, fsErrMsg(err))
		return
	}
	if !li.Mode().IsRegular() {
		sendXferErr(stream, "path is not a regular file")
		return
	}
	f, err := openRegularNoFollow(clean)
	if err != nil {
		sendXferErr(stream, fsErrMsg(err))
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		sendXferErr(stream, fsErrMsg(err))
		return
	}
	if !fi.Mode().IsRegular() {
		sendXferErr(stream, "path is not a regular file")
		return
	}
	size := fi.Size()
	if size > model.MCPFsTransferMaxSize {
		sendXferErr(stream, "file exceeds MCP transfer cap (100MiB)")
		return
	}

	// 下行 header 里不预先附 sha256：要算就得先全文件扫一遍，浪费 100MB
	// 量级的 IO。dashboard 端在收完所有 chunk 后从 NZTO 帧取最终 sha。
	if err := sendXferFixedHeader(stream, model.MCPFsXferMagicDownloadHdr, uint64(size), make([]byte, 32)); err != nil {
		printf("FsTransfer 下载准备帧发送失败: %v", err)
		return
	}

	sender := &grpcXferSender{stream: stream, hash: sha256.New()}
	if err := streamFileChunks(sender, f, size); err != nil {
		printf("FsTransfer 下载失败: %v", err)
		return
	}

	_ = sendXferOK(stream, hex.EncodeToString(sender.hash.Sum(nil)), size)
}

type xferSender interface {
	sendXferData(p []byte) error
	sendXferErrFrame(msg string)
}

type grpcXferSender struct {
	stream pb.NezhaService_IOStreamClient
	hash   hash.Hash
}

func (g *grpcXferSender) sendXferData(p []byte) error {
	if g.hash == nil {
		g.hash = sha256.New()
	}
	g.hash.Write(p)
	var buf bytes.Buffer
	buf.Write(model.MCPFsXferMagicChunk)
	if err := binary.Write(&buf, binary.BigEndian, uint64(len(p))); err != nil {
		return err
	}
	buf.Write(p)
	return g.stream.Send(&pb.IOStreamData{Data: buf.Bytes()})
}

func (g *grpcXferSender) sendXferErrFrame(msg string) {
	sendXferErr(g.stream, msg)
}

func streamFileChunks(sender xferSender, src io.Reader, declaredSize int64) error {
	buf := make([]byte, mcpFsTransferChunk)
	remaining := declaredSize
	for remaining > 0 {
		toRead := int64(len(buf))
		if toRead > remaining {
			toRead = remaining
		}
		n, readErr := io.ReadFull(src, buf[:toRead])
		if n > 0 {
			if sendErr := sender.sendXferData(append([]byte(nil), buf[:n]...)); sendErr != nil {
				return sendErr
			}
			remaining -= int64(n)
		}
		if readErr != nil {
			if remaining > 0 && (errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF)) {
				sender.sendXferErrFrame("source truncated mid-transfer")
				return readErr
			}
			if !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
				sender.sendXferErrFrame(fsErrMsg(readErr))
				return readErr
			}
		}
	}
	return nil
}

// sendXferFixedHeader 写入 4 字节 magic + 8 字节 size，以及可选 32 字节 sha
// 字段（hash==nil 表示 magic 不携带 sha）。所有协议字段统一用大端，方便
// dashboard / 调试工具直接 hexdump。
func sendXferFixedHeader(stream pb.NezhaService_IOStreamClient, magic []byte, size uint64, hash []byte) error {
	var buf bytes.Buffer
	buf.Write(magic)
	if err := binary.Write(&buf, binary.BigEndian, size); err != nil {
		return err
	}
	if hash != nil {
		if len(hash) != 32 {
			padded := make([]byte, 32)
			copy(padded, hash)
			hash = padded
		}
		buf.Write(hash)
	}
	return stream.Send(&pb.IOStreamData{Data: buf.Bytes()})
}

func sendXferOK(stream pb.NezhaService_IOStreamClient, sha string, size int64) error {
	hashBytes, _ := hex.DecodeString(sha)
	if len(hashBytes) != 32 {
		hashBytes = make([]byte, 32)
	}
	var buf bytes.Buffer
	buf.Write(model.MCPFsXferMagicOK)
	if err := binary.Write(&buf, binary.BigEndian, uint64(size)); err != nil {
		return err
	}
	buf.Write(hashBytes)
	return stream.Send(&pb.IOStreamData{Data: buf.Bytes()})
}

func sendXferErr(stream pb.NezhaService_IOStreamClient, msg string) {
	var buf bytes.Buffer
	buf.Write(model.MCPFsXferMagicErr)
	buf.WriteString(msg)
	_ = stream.Send(&pb.IOStreamData{Data: buf.Bytes()})
}

func sha256OfFile(path string) (string, error) {
	f, err := openRegularNoFollow(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var h hash.Hash = sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
