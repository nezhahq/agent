package fm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"

	pb "github.com/nezhahq/agent/proto"
)

var currentUserHomeDir = func() (string, error) {
	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return usr.HomeDir, nil
}

func (t *Task) listDir(dir string) error {
	var entries []fs.DirEntry
	var err error
	entries, err = os.ReadDir(dir)
	if err != nil {
		// 回退到主目录只能尝试一次：服务账号的主目录常常不存在或不可读
		// （例如 /nonexistent），循环重试会让这个协程永久空转占满一个 CPU。
		homeDir, userErr := currentUserHomeDir()
		if userErr != nil {
			return t.sender.Send(&pb.IOStreamData{Data: CreateErr(userErr)})
		}
		dir = homeDir + string(filepath.Separator)
		entries, err = os.ReadDir(dir)
		if err != nil {
			return t.sender.Send(&pb.IOStreamData{Data: CreateErr(err)})
		}
	}
	if t.framed.Load() {
		for _, page := range createListingPages(dir, entries) {
			if err := t.sender.Send(&pb.IOStreamData{Data: page}); err != nil {
				return err
			}
		}
		return nil
	}
	return t.sender.Send(&pb.IOStreamData{Data: createLegacyListing(dir, entries)})
}

func createLegacyListing(dir string, entries []fs.DirEntry) []byte {
	var buffer bytes.Buffer
	data := Create(&buffer, dir)
	for _, entry := range entries {
		// 旧协议的文件名长度只有 1 字节：超过 255 字节的名字写进去长度会回绕，
		// 之后的所有条目跟着错位。这样的条目在旧协议里无法表示，只能跳过。
		if len(entry.Name()) > 255 {
			continue
		}
		data = AppendFileName(data, entry.Name(), entry.IsDir())
	}
	return data
}

func (t *Task) download(path string) error {
	file, err := t.openFile(path)
	if err != nil {
		t.printf("Error opening file: %s", err)
		return t.sender.Send(&pb.IOStreamData{Data: CreateErr(err)})
	}
	if !t.registerFile(file) {
		_ = file.Close()
		return context.Cause(t.context)
	}
	defer func() {
		t.unregisterFile(file)
		_ = file.Close()
	}()

	fileInfo, err := file.Stat()
	if err != nil {
		t.printf("Error getting file info: %s", err)
		return t.sender.Send(&pb.IOStreamData{Data: CreateErr(err)})
	}
	fileSize := fileInfo.Size()
	framed := t.framed.Load()
	// 旧协议没有结束帧，对端靠“收够声明的字节数”判断下载完成，0 字节的文件
	// 没有任何分片可等，所以只能拒绝。带帧头的协议有结束帧，可以下载空文件。
	if fileSize < 0 || (fileSize == 0 && !framed) {
		return t.sender.Send(&pb.IOStreamData{Data: CreateErr(errors.New("requested file is empty"))})
	}

	var header bytes.Buffer
	headerData := CreateFile(&header, uint64(fileSize))
	if err := t.sender.Send(&pb.IOStreamData{Data: headerData}); err != nil {
		t.printf("Error sending file header: %s", err)
		_ = t.sender.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return err
	}

	// 头里声明的是 stat 时的大小，之后只能发这么多字节，一个不多一个不少：
	// 对端没有结束帧可看，只能数到声明的大小为止。文件在传输中被追加时多发的
	// 字节会被对端当成后续的协议帧；被截短时对端会一直等下去，所以要明确报错。
	declaredContent := io.LimitReader(file, fileSize)
	sentBytes := int64(0)
	for {
		if err := t.context.Err(); err != nil {
			return context.Cause(t.context)
		}
		buffer := bufPool.Get().(*bp)
		// 带帧头的协议里每片以标识开头，整帧不超过缓冲区大小。
		chunk := buffer.buf
		chunkPrefixBytes := 0
		if framed {
			chunkPrefixBytes = copy(chunk, downloadChunkIdentifier)
		}
		// 必须读满整片再发：分片不带帧头，面板前端只能靠“除最后一片外都是整 1MiB”
		// 来区分文件内容和错误帧。单次 Read 的长度由文件系统决定，FUSE 和部分
		// 网络文件系统会短读，短的分片若恰好以错误标识开头就会被当成错误中止下载。
		read, readErr := io.ReadFull(declaredContent, chunk[chunkPrefixBytes:])
		if readErr == io.ErrUnexpectedEOF {
			// 文件的最后一片：不足一整片，照常发出，下一轮读到 EOF 结束。
			readErr = nil
		}
		if readErr != nil {
			bufPool.Put(buffer)
			if readErr == io.EOF {
				if sentBytes < fileSize {
					shortened := fmt.Errorf("file changed during download: sent %d of %d bytes", sentBytes, fileSize)
					t.printf("Error reading file: %s", shortened)
					return t.sender.Send(&pb.IOStreamData{Data: CreateErr(shortened)})
				}
				if framed {
					return t.sender.Send(&pb.IOStreamData{Data: createDownloadEnd(uint64(sentBytes))})
				}
				return nil
			}
			t.printf("Error reading file: %s", readErr)
			return t.sender.Send(&pb.IOStreamData{Data: CreateErr(readErr)})
		}
		if err := t.sender.Send(&pb.IOStreamData{Data: chunk[:chunkPrefixBytes+read]}); err != nil {
			bufPool.Put(buffer)
			t.printf("Error sending file chunk: %s", err)
			_ = t.sender.Send(&pb.IOStreamData{Data: CreateErr(err)})
			return err
		}
		sentBytes += int64(read)
		bufPool.Put(buffer)
	}
}

func (t *Task) upload(path string, fileSize uint64) error {
	file, err := os.Create(path)
	if err != nil {
		t.printf("Error creating file: %s", err)
		return t.rejectUploadAfterDrainingBody(err, fileSize)
	}
	defer file.Close()

	totalReceived := uint64(0)
	t.printf("receiving file: %s, size: %d", file.Name(), fileSize)
	for totalReceived < fileSize {
		frame, recvErr := t.uploadReceiver.Recv()
		if recvErr != nil {
			t.printf("Error receiving data: %s", recvErr)
			if sendErr := t.sender.Send(&pb.IOStreamData{Data: CreateErr(recvErr)}); sendErr != nil {
				return sendErr
			}
			return recvErr
		}
		bytesWritten, writeErr := file.Write(frame.Data)
		if writeErr != nil {
			t.printf("Error writing to file: %s", writeErr)
			arrived := totalReceived + uint64(len(frame.Data))
			if arrived >= fileSize {
				return t.rejectUploadAfterDrainingBody(writeErr, 0)
			}
			return t.rejectUploadAfterDrainingBody(writeErr, fileSize-arrived)
		}
		totalReceived += uint64(bytesWritten)
	}
	t.printf("received file %s.", file.Name())
	return t.sender.Send(&pb.IOStreamData{Data: completeIdentifier})
}

// rejectUploadAfterDrainingBody 先把上传声明的剩余内容读完丢弃，再回报错误。
// 上传的内容帧没有帧头，对端在收到错误之前会一直发：这里直接返回的话，剩下的
// 内容帧会被命令循环当成命令解析，以 0x02 开头的一片会在它“声明”的路径上
// 创建或清空文件。必须先读完再报错，报错在前对端就会停止发送，读不满。
func (t *Task) rejectUploadAfterDrainingBody(cause error, remaining uint64) error {
	for remaining > 0 {
		frame, recvErr := t.uploadReceiver.Recv()
		if recvErr != nil {
			t.printf("Error receiving data: %s", recvErr)
			return recvErr
		}
		arrived := uint64(len(frame.Data))
		if arrived >= remaining {
			break
		}
		remaining -= arrived
	}
	return t.sender.Send(&pb.IOStreamData{Data: CreateErr(cause)})
}
