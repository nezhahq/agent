package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func fsTransferDownload(stream fsTransferStream, req *model.FsTransferRequest) {
	clean, err := resolveFsPath(req.Path)
	if err != nil {
		sendXferErr(stream, "invalid path: "+err.Error())
		return
	}
	info, err := os.Lstat(clean)
	if err != nil {
		sendXferErr(stream, fsErrMsg(err))
		return
	}
	if !info.Mode().IsRegular() {
		sendXferErr(stream, "path is not a regular file")
		return
	}
	file, err := openRegularNoFollow(clean)
	if err != nil {
		sendXferErr(stream, fsErrMsg(err))
		return
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		sendXferErr(stream, fsErrMsg(err))
		return
	}
	if !fileInfo.Mode().IsRegular() {
		sendXferErr(stream, "path is not a regular file")
		return
	}
	size := fileInfo.Size()
	if size > model.MCPFsTransferMaxSize {
		sendXferErr(stream, "file exceeds MCP transfer cap (100MiB)")
		return
	}
	if err := sendXferFixedHeader(stream, model.MCPFsXferMagicDownloadHdr, uint64(size), make([]byte, 32)); err != nil {
		printf("FsTransfer 下载准备帧发送失败: %v", err)
		return
	}
	sender := &grpcXferSender{stream: stream, hash: sha256.New()}
	if err := streamFileChunks(sender, file, size); err != nil {
		printf("FsTransfer 下载失败: %v", err)
		return
	}
	_ = sendXferOK(stream, hex.EncodeToString(sender.hash.Sum(nil)), size)
}

type xferSender interface {
	sendXferData([]byte) error
	sendXferErrFrame(string)
}

type grpcXferSender struct {
	stream ioStreamSender
	hash   hash.Hash
}

func (g *grpcXferSender) sendXferData(payload []byte) error {
	if g.hash == nil {
		g.hash = sha256.New()
	}
	g.hash.Write(payload)
	var buffer bytes.Buffer
	buffer.Write(model.MCPFsXferMagicChunk)
	if err := binary.Write(&buffer, binary.BigEndian, uint64(len(payload))); err != nil {
		return err
	}
	buffer.Write(payload)
	return g.stream.Send(&pb.IOStreamData{Data: buffer.Bytes()})
}

func (g *grpcXferSender) sendXferErrFrame(message string) {
	sendXferErr(g.stream, message)
}

func streamFileChunks(sender xferSender, source io.Reader, declaredSize int64) error {
	buffer := make([]byte, mcpFsTransferChunk)
	remaining := declaredSize
	for remaining > 0 {
		toRead := min(int64(len(buffer)), remaining)
		read, readErr := io.ReadFull(source, buffer[:toRead])
		if read > 0 {
			if sendErr := sender.sendXferData(append([]byte(nil), buffer[:read]...)); sendErr != nil {
				return sendErr
			}
			remaining -= int64(read)
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

func sendXferFixedHeader(stream ioStreamSender, magic []byte, size uint64, hashBytes []byte) error {
	var buffer bytes.Buffer
	buffer.Write(magic)
	if err := binary.Write(&buffer, binary.BigEndian, size); err != nil {
		return err
	}
	if hashBytes != nil {
		if len(hashBytes) != sha256.Size {
			padded := make([]byte, sha256.Size)
			copy(padded, hashBytes)
			hashBytes = padded
		}
		buffer.Write(hashBytes)
	}
	return stream.Send(&pb.IOStreamData{Data: buffer.Bytes()})
}

func sendXferOK(stream ioStreamSender, sha string, size int64) error {
	hashBytes, _ := hex.DecodeString(sha)
	if len(hashBytes) != sha256.Size {
		hashBytes = make([]byte, sha256.Size)
	}
	var buffer bytes.Buffer
	buffer.Write(model.MCPFsXferMagicOK)
	if err := binary.Write(&buffer, binary.BigEndian, uint64(size)); err != nil {
		return err
	}
	buffer.Write(hashBytes)
	return stream.Send(&pb.IOStreamData{Data: buffer.Bytes()})
}

func sendXferErr(stream ioStreamSender, message string) {
	var buffer bytes.Buffer
	buffer.Write(model.MCPFsXferMagicErr)
	buffer.WriteString(message)
	_ = stream.Send(&pb.IOStreamData{Data: buffer.Bytes()})
}
