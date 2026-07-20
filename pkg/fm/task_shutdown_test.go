package fm

import (
	"context"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

type blockedDownloadFile struct {
	closed    chan struct{}
	closeOnce sync.Once
	info      os.FileInfo
}

func (f *blockedDownloadFile) Read([]byte) (int, error) {
	<-f.closed
	return 0, os.ErrClosed
}

func (f *blockedDownloadFile) Stat() (os.FileInfo, error) { return f.info, nil }
func (f *blockedDownloadFile) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

type fixedDownloadFileInfo struct{}

func (fixedDownloadFileInfo) Name() string       { return "blocked.bin" }
func (fixedDownloadFileInfo) Size() int64        { return 1 }
func (fixedDownloadFileInfo) Mode() os.FileMode  { return 0 }
func (fixedDownloadFileInfo) ModTime() time.Time { return time.Time{} }
func (fixedDownloadFileInfo) IsDir() bool        { return false }
func (fixedDownloadFileInfo) Sys() any           { return nil }

func TestTask_ShutdownClosesBlockedDownloadFileAndJoinsProducer(t *testing.T) {
	// Given
	file := &blockedDownloadFile{closed: make(chan struct{}), info: fixedDownloadFileInfo{}}
	sender := &serialTaskSender{downloadSent: make(chan struct{})}
	task := NewFMClient(Dependencies{
		Context:        context.Background(),
		Sender:         sender,
		UploadReceiver: &legacyUploadReceiver{},
		Printf:         func(string, ...interface{}) {},
	})
	openEntered := make(chan struct{})
	task.openFile = func(string) (downloadFile, error) {
		close(openEntered)
		return file, nil
	}
	if err := task.DoTask(&pb.IOStreamData{Data: []byte{byte(commandDownload), 'p'}}); err != nil {
		t.Fatalf("start blocked download: %v", err)
	}
	select {
	case <-openEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("download did not open the blocking file")
	}
	shutdownDone := make(chan struct{})

	// When
	go func() {
		task.Shutdown(context.Canceled)
		close(shutdownDone)
	}()

	// Then
	select {
	case <-shutdownDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown did not close the blocked download file and join its producer")
	}
}

var _ downloadFile = (*blockedDownloadFile)(nil)
var _ io.Reader = (*blockedDownloadFile)(nil)
