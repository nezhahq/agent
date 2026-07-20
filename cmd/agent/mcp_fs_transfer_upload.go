package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/nezhahq/agent/model"
)

func fsTransferUpload(stream fsTransferStream, req *model.FsTransferRequest) {
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
		if got := hex.EncodeToString(h.Sum(nil)); got != expected {
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
	_ = sendXferOK(stream, hex.EncodeToString(h.Sum(nil)), req.Size)
}

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

func enforceUploadOversend(payload []byte, remaining int64) ([]byte, error) {
	if int64(len(payload)) > remaining {
		return nil, errors.New("upload oversend: payload exceeds declared remaining size")
	}
	return payload, nil
}

func receiveUploadBody(recv func() ([]byte, error), writer io.Writer, digest hash.Hash, size int64) (int64, error) {
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
		n, err := writer.Write(payload)
		written += int64(n)
		if err != nil {
			return written, err
		}
		digest.Write(payload)
		remaining -= int64(len(payload))
	}
	return written, nil
}

func sha256OfFile(path string) (string, error) {
	file, err := openRegularNoFollow(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
