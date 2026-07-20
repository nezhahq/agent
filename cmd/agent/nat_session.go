package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

const (
	natKeepaliveInterval     = 30 * time.Second
	natShutdownTimeout       = 2 * time.Second
	natHalfCloseDrainTimeout = 30 * time.Second
)

type natDialer func(context.Context, string, string) (net.Conn, error)

type natHandler struct {
	openStream            func(context.Context) (pb.NezhaService_IOStreamClient, error)
	dial                  natDialer
	startKeepalive        func(*ioStreamWriteOwner, time.Duration) error
	startHalfCloseDrain   func(time.Duration) (<-chan time.Time, func())
	keepaliveInterval     time.Duration
	halfCloseDrainTimeout time.Duration
	shutdownTimeout       time.Duration
}

var natHandlerForTask = newNATHandler

type natSession struct {
	parent           context.Context
	stream           pb.NezhaService_IOStreamClient
	owner            *ioStreamWriteOwner
	conn             net.Conn
	cancelReader     context.CancelCauseFunc
	readerContext    context.Context
	shutdownTimeout  time.Duration
	readerDone       chan error
	readerResultDone chan natReaderResult
	receiverDone     chan error
}

func newNATHandler() natHandler {
	dialer := &net.Dialer{}
	return natHandler{
		openStream: func(ctx context.Context) (pb.NezhaService_IOStreamClient, error) {
			return client.IOStream(ctx)
		},
		dial:                  dialer.DialContext,
		startKeepalive:        (*ioStreamWriteOwner).StartKeepalive,
		startHalfCloseDrain:   startNATHalfCloseDrain,
		keepaliveInterval:     natKeepaliveInterval,
		halfCloseDrainTimeout: natHalfCloseDrainTimeout,
		shutdownTimeout:       natShutdownTimeout,
	}
}

func handleNATTaskWithConfig(parent context.Context, gates taskFeatureGates, task *pb.Task) {
	natHandlerForTask().run(parent, gates, task)
}

func (h natHandler) run(parent context.Context, gates taskFeatureGates, task *pb.Task) {
	if gates.disableNat {
		println("This server has disabled NAT traversal")
		return
	}
	if h.startHalfCloseDrain == nil {
		h.startHalfCloseDrain = startNATHalfCloseDrain
	}
	if h.halfCloseDrainTimeout <= 0 {
		h.halfCloseDrainTimeout = natHalfCloseDrainTimeout
	}
	var nat model.TaskNAT
	if err := json.Unmarshal([]byte(task.GetData()), &nat); err != nil {
		printf("NAT 任务解析错误: %v", err)
		return
	}

	streamContext, cancelStream := context.WithCancelCause(parent)
	stream, err := h.openStream(streamContext)
	if err != nil {
		cancelStream(err)
		printf("NAT IOStream失败: %v", err)
		return
	}
	owner := newIOStreamWriteOwner(stream, cancelStream)
	if err := owner.Send(&pb.IOStreamData{Data: natAttachFrame(nat.StreamID)}); err != nil {
		shutdownResult := h.shutdownOwner(parent, owner, err)
		println("NAT exit", nat.StreamID, nil, shutdownResult.Err)
		printf("NAT 发送StreamID失败: %v", err)
		return
	}

	conn, err := h.dial(streamContext, "tcp", nat.Host)
	if err != nil {
		shutdownResult := h.shutdownOwner(parent, owner, err)
		println("NAT exit", nat.StreamID, nil, shutdownResult.Err)
		printf("NAT Dial %s 失败：%s", nat.Host, err)
		return
	}
	readerContext, cancelReader := context.WithCancelCause(parent)
	session := natSession{
		parent:           parent,
		stream:           stream,
		owner:            owner,
		conn:             conn,
		cancelReader:     cancelReader,
		readerContext:    readerContext,
		shutdownTimeout:  h.shutdownTimeout,
		readerResultDone: make(chan natReaderResult, 1),
		receiverDone:     make(chan error, 1),
	}
	if err := h.startKeepalive(owner, h.keepaliveInterval); err != nil {
		connErr, shutdownResult := session.shutdownBeforeStart(err)
		println("NAT exit", nat.StreamID, connErr, shutdownResult.Err)
		printf("NAT KeepAlive启动失败: %v", err)
		return
	}
	println("NAT init", nat.StreamID)
	go func() { session.readerResultDone <- session.produceTCPOutput() }()
	go func() { session.receiverDone <- session.receiveRemoteOutput() }()

	var cause error
	readerJoined := false
	receiverJoined := false
	select {
	case readerResult := <-session.readerResultDone:
		readerJoined = true
		if readerResult.kind == natReaderLocalReadEnded {
			cause, receiverJoined = h.waitAfterLocalReadEnded(parent, &session)
		} else {
			cause = readerResult.err
		}
	case cause = <-session.receiverDone:
		receiverJoined = true
	case <-parent.Done():
		cause = context.Cause(parent)
	}
	connErr, shutdownResult := session.shutdown(cause, readerJoined, receiverJoined)
	println("NAT exit", nat.StreamID, connErr, shutdownResult.Err)
}

func (h natHandler) waitAfterLocalReadEnded(parent context.Context, session *natSession) (error, bool) {
	drain, stopDrain := h.startHalfCloseDrain(h.halfCloseDrainTimeout)
	defer stopDrain()
	select {
	case cause := <-session.receiverDone:
		return cause, true
	case <-parent.Done():
		return context.Cause(parent), false
	case <-drain:
		return errNATHalfCloseDrainTimeout, false
	}
}

func natAttachFrame(streamID string) []byte {
	return append([]byte{0xff, 0x05, 0xff, 0x05}, []byte(streamID)...)
}

func (h natHandler) shutdownOwner(
	parent context.Context,
	owner *ioStreamWriteOwner,
	cause error,
) ioStreamWriteShutdownResult {
	graceContext, cancelGrace := context.WithTimeout(context.WithoutCancel(parent), h.shutdownTimeout)
	defer cancelGrace()
	return owner.Shutdown(graceContext, cause)
}

func (s *natSession) receiveRemoteOutput() error {
	for {
		remoteData, err := s.stream.Recv()
		if err != nil {
			return err
		}
		payload := remoteData.GetData()
		for written := 0; written < len(payload); {
			count, writeErr := s.conn.Write(payload[written:])
			written += count
			if writeErr != nil {
				return writeErr
			}
			if count == 0 {
				return io.ErrNoProgress
			}
		}
	}
}

func (s *natSession) shutdownBeforeStart(
	cause error,
) (error, ioStreamWriteShutdownResult) {
	s.cancelReader(cause)
	connErr := s.conn.Close()
	graceContext, cancelGrace := context.WithTimeout(context.WithoutCancel(s.parent), s.shutdownTimeout)
	defer cancelGrace()
	return connErr, s.owner.Shutdown(graceContext, cause)
}

func (s *natSession) shutdown(
	cause error,
	readerJoined bool,
	receiverJoined bool,
) (error, ioStreamWriteShutdownResult) {
	s.cancelReader(cause)
	connErr := s.conn.Close()
	graceContext, cancelGrace := context.WithTimeout(context.WithoutCancel(s.parent), s.shutdownTimeout)
	defer cancelGrace()
	result := s.owner.Shutdown(graceContext, cause)
	// A successful local-read half-close consumes shutdownOnce without canceling
	// the receive side. Final termination must still unblock the sole Recv.
	s.owner.cancel(cause)
	if !readerJoined {
		<-s.readerResultDone
	}
	if !receiverJoined {
		<-s.receiverDone
	}
	return connErr, result
}
