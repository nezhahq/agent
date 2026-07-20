package fm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"

	pb "github.com/nezhahq/agent/proto"
)

func (t *Task) listDir(dir string) error {
	var entries []fs.DirEntry
	var err error
	for {
		entries, err = os.ReadDir(dir)
		if err != nil {
			usr, userErr := user.Current()
			if userErr != nil {
				return t.sender.Send(&pb.IOStreamData{Data: CreateErr(userErr)})
			}
			dir = usr.HomeDir + string(filepath.Separator)
			continue
		}
		break
	}
	var buffer bytes.Buffer
	data := Create(&buffer, dir)
	for _, entry := range entries {
		data = AppendFileName(data, entry.Name(), entry.IsDir())
	}
	return t.sender.Send(&pb.IOStreamData{Data: data})
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
	if fileSize <= 0 {
		return t.sender.Send(&pb.IOStreamData{Data: CreateErr(errors.New("requested file is empty"))})
	}

	var header bytes.Buffer
	headerData := CreateFile(&header, uint64(fileSize))
	if err := t.sender.Send(&pb.IOStreamData{Data: headerData}); err != nil {
		t.printf("Error sending file header: %s", err)
		_ = t.sender.Send(&pb.IOStreamData{Data: CreateErr(err)})
		return err
	}

	for {
		if err := t.context.Err(); err != nil {
			return context.Cause(t.context)
		}
		buffer := bufPool.Get().(*bp)
		read, readErr := file.Read(buffer.buf)
		if readErr != nil {
			bufPool.Put(buffer)
			if readErr == io.EOF {
				return nil
			}
			t.printf("Error reading file: %s", readErr)
			return t.sender.Send(&pb.IOStreamData{Data: CreateErr(readErr)})
		}
		if err := t.sender.Send(&pb.IOStreamData{Data: buffer.buf[:read]}); err != nil {
			bufPool.Put(buffer)
			t.printf("Error sending file chunk: %s", err)
			_ = t.sender.Send(&pb.IOStreamData{Data: CreateErr(err)})
			return err
		}
		bufPool.Put(buffer)
	}
}

func (t *Task) upload(path string, fileSize uint64) error {
	file, err := os.Create(path)
	if err != nil {
		t.printf("Error creating file: %s", err)
		return t.sender.Send(&pb.IOStreamData{Data: CreateErr(err)})
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
			return t.sender.Send(&pb.IOStreamData{Data: CreateErr(writeErr)})
		}
		totalReceived += uint64(bytesWritten)
	}
	t.printf("received file %s.", file.Name())
	return t.sender.Send(&pb.IOStreamData{Data: completeIdentifier})
}
