package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type fmUploadCancellationServer struct {
	pb.UnimplementedNezhaServiceServer
	uploadCommand []byte
	attach        chan []byte
	canceled      chan error
}

func (s *fmUploadCancellationServer) IOStream(stream pb.NezhaService_IOStreamServer) error {
	attach, err := stream.Recv()
	if err != nil {
		return err
	}
	s.attach <- append([]byte(nil), attach.GetData()...)
	if err := stream.Send(&pb.IOStreamData{Data: s.uploadCommand}); err != nil {
		return err
	}
	<-stream.Context().Done()
	s.canceled <- stream.Context().Err()
	return stream.Context().Err()
}

func TestFMUploadRecvCancellation_RealBufconnRecvExitsOnParentCancel(t *testing.T) {
	// Given
	directory := t.TempDir()
	target := filepath.Join(directory, "blocked-upload.bin")
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatalf("create fs watcher: %v", err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
	if err := watcher.Add(directory); err != nil {
		t.Fatalf("watch upload directory: %v", err)
	}
	command := make([]byte, 9, 9+len(target))
	command[0] = 2
	binary.BigEndian.PutUint64(command[1:9], 1)
	command = append(command, target...)
	service := &fmUploadCancellationServer{
		uploadCommand: command,
		attach:        make(chan []byte, 1),
		canceled:      make(chan error, 1),
	}
	listener := bufconn.Listen(bufconnFixtureSize)
	server := grpc.NewServer()
	pb.RegisterNezhaServiceServer(server, service)
	serveResult := make(chan error, 1)
	go func() { serveResult <- server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	dialContext, cancelDial := context.WithTimeout(context.Background(), streamFixtureDeadline)
	defer cancelDial()
	connection, err := grpc.DialContext(
		dialContext,
		"passthrough:///fm-upload-cancel",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	client := pb.NewNezhaServiceClient(connection)
	parent, cancelParent := context.WithCancel(context.Background())
	handler := newFMHandler()
	handler.openStream = func(ctx context.Context) (pb.NezhaService_IOStreamClient, error) {
		return client.IOStream(ctx)
	}
	handlerDone := make(chan struct{})
	go func() {
		handler.run(parent, taskFeatureGates{}, &pb.Task{Data: `{"StreamID":"upload-cancel"}`})
		close(handlerDone)
	}()
	attach := awaitStreamOperationResult(t, service.attach)
	if string(attach[4:]) != "upload-cancel" {
		t.Fatalf("FM attach stream ID = %q, want upload-cancel", attach[4:])
	}
	waitForUploadCreateEvent(t, watcher, target)
	if info, err := os.Stat(target); err != nil || info.Size() != 0 {
		t.Fatalf("upload target before cancel: info=%v err=%v, want existing empty file", info, err)
	}

	// When
	cancelParent()
	awaitStreamSignal(t, handlerDone, "real bufconn upload Recv cancellation")
	serverErr := awaitStreamOperationResult(t, service.canceled)

	// Then
	if !errors.Is(serverErr, context.Canceled) {
		t.Fatalf("server upload stream cancellation = %v, want context.Canceled", serverErr)
	}
	if !errors.Is(context.Cause(parent), context.Canceled) {
		t.Fatalf("parent cancellation cause = %v, want context.Canceled", context.Cause(parent))
	}
	server.Stop()
	if err := awaitStreamOperationResult(t, serveResult); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		t.Fatalf("serve bufconn: %v", err)
	}
}

func waitForUploadCreateEvent(t *testing.T, watcher *fsnotify.Watcher, target string) {
	t.Helper()
	for {
		select {
		case event := <-watcher.Events:
			if event.Name == target && event.Op&(fsnotify.Create|fsnotify.Write) != 0 {
				return
			}
		case err := <-watcher.Errors:
			t.Fatalf("watch upload target: %v", err)
		case <-time.After(streamFixtureDeadline):
			t.Fatal("upload target was not created before blocked body Recv")
		}
	}
}
