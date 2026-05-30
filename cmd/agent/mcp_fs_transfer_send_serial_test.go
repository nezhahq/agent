package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"
	"google.golang.org/grpc/metadata"
)

type concurrencyTrackingStream struct {
	pb.NezhaService_IOStreamClient

	mu          sync.Mutex
	inFlight    int32
	maxInFlight int32
}

func (s *concurrencyTrackingStream) Send(d *pb.IOStreamData) error {
	current := atomic.AddInt32(&s.inFlight, 1)
	defer atomic.AddInt32(&s.inFlight, -1)
	s.mu.Lock()
	if current > s.maxInFlight {
		s.maxInFlight = current
	}
	s.mu.Unlock()
	time.Sleep(2 * time.Millisecond)
	return nil
}

func (s *concurrencyTrackingStream) CloseSend() error                  { return nil }
func (s *concurrencyTrackingStream) Recv() (*pb.IOStreamData, error)    { return nil, nil }
func (s *concurrencyTrackingStream) Header() (metadata.MD, error)       { return metadata.MD{}, nil }
func (s *concurrencyTrackingStream) Trailer() metadata.MD               { return metadata.MD{} }

// gRPC Go ClientStream does not allow concurrent SendMsg invocations
// (https://pkg.go.dev/google.golang.org/grpc#ClientStream).
// handleFsTransferTask spawns ioStreamKeepAlive on the same client stream
// that fsTransferUpload / fsTransferDownload use to send NZTU / NZTD / NZTC /
// NZTO / NZTE frames; a slow >30s transfer therefore lets the keepalive
// goroutine race the protocol goroutine on stream.Send. The fix path must
// route every Send through a per-stream serial sender so concurrent callers
// queue rather than race.
func TestSerialIOStreamSender_GuaranteesAtMostOneSendInFlight(t *testing.T) {
	raw := &concurrencyTrackingStream{}
	sender := newSerialIOStreamSender(raw)

	var wg sync.WaitGroup
	const goroutines = 8
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				if err := sender.Send(&pb.IOStreamData{Data: []byte("frame")}); err != nil {
					t.Errorf("Send returned unexpected error: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	raw.mu.Lock()
	defer raw.mu.Unlock()
	if raw.maxInFlight != 1 {
		t.Fatalf("serialIOStreamSender must serialize Send; observed max-in-flight=%d, want 1", raw.maxInFlight)
	}
}

// keepalive 与协议帧共用同一个底层 stream 时，必须经由同一个串行化器，
// 不允许独立持有底层 stream 直接 Send，否则又会出现并发写入。
func TestSerialIOStreamSender_KeepaliveSharesSerializerWithProtocolFrames(t *testing.T) {
	raw := &concurrencyTrackingStream{}
	sender := newSerialIOStreamSender(raw)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		serializedKeepAlive(ctx, sender, 1*time.Millisecond)
	}()

	deadline := time.After(80 * time.Millisecond)
	for {
		select {
		case <-deadline:
			cancel()
			<-done
			raw.mu.Lock()
			max := raw.maxInFlight
			raw.mu.Unlock()
			if max != 1 {
				t.Fatalf("keepalive must share the serializer; max-in-flight=%d", max)
			}
			return
		default:
			if err := sender.Send(&pb.IOStreamData{Data: []byte("data")}); err != nil {
				t.Fatalf("Send returned unexpected error: %v", err)
			}
		}
	}
}
