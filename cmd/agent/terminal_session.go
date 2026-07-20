package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/pty"
	pb "github.com/nezhahq/agent/proto"
)

const (
	terminalKeepaliveInterval = 30 * time.Second
	terminalShutdownTimeout   = 2 * time.Second
)

type terminalWindowSize struct {
	Cols uint32
	Rows uint32
}

type terminalHandler struct {
	openStream        func(context.Context) (pb.NezhaService_IOStreamClient, error)
	startPTY          func() (pty.IPty, error)
	startKeepalive    func(*ioStreamWriteOwner, time.Duration) error
	keepaliveInterval time.Duration
	shutdownTimeout   time.Duration
}

var terminalHandlerForTask = newTerminalHandler

type terminalSession struct {
	parent          context.Context
	stream          pb.NezhaService_IOStreamClient
	owner           *ioStreamWriteOwner
	tty             pty.IPty
	cancelProducer  context.CancelCauseFunc
	producerContext context.Context
	shutdownTimeout time.Duration
	producerDone    chan error
	receiverDone    chan error
}

func newTerminalHandler() terminalHandler {
	return terminalHandler{
		openStream: func(ctx context.Context) (pb.NezhaService_IOStreamClient, error) {
			return client.IOStream(ctx)
		},
		startPTY:          pty.Start,
		startKeepalive:    (*ioStreamWriteOwner).StartKeepalive,
		keepaliveInterval: terminalKeepaliveInterval,
		shutdownTimeout:   terminalShutdownTimeout,
	}
}

func handleTerminalTaskWithConfig(parent context.Context, gates taskFeatureGates, task *pb.Task) {
	terminalHandlerForTask().run(parent, gates, task)
}

func (h terminalHandler) run(parent context.Context, gates taskFeatureGates, task *pb.Task) {
	if gates.disableCommandExecute {
		println("此 Agent 已禁止命令执行")
		return
	}
	var terminal model.TerminalTask
	if err := json.Unmarshal([]byte(task.GetData()), &terminal); err != nil {
		printf("Terminal 任务解析错误: %v", err)
		return
	}

	streamContext, cancelStream := context.WithCancelCause(parent)
	stream, err := h.openStream(streamContext)
	if err != nil {
		cancelStream(err)
		printf("Terminal IOStream失败: %v", err)
		return
	}
	owner := newIOStreamWriteOwner(stream, cancelStream)
	if err := owner.Send(&pb.IOStreamData{Data: terminalAttachFrame(terminal.StreamID)}); err != nil {
		h.shutdownOwner(parent, owner, err)
		printf("Terminal 发送StreamID失败: %v", err)
		return
	}

	tty, err := h.startPTY()
	if err != nil {
		h.shutdownOwner(parent, owner, err)
		printf("Terminal pty.Start失败 %v", err)
		return
	}
	producerContext, cancelProducer := context.WithCancelCause(parent)
	session := terminalSession{
		parent:          parent,
		stream:          stream,
		owner:           owner,
		tty:             tty,
		cancelProducer:  cancelProducer,
		producerContext: producerContext,
		shutdownTimeout: h.shutdownTimeout,
		producerDone:    make(chan error, 1),
		receiverDone:    make(chan error, 1),
	}
	if err := h.startKeepalive(owner, h.keepaliveInterval); err != nil {
		ptyErr := tty.Close()
		shutdownResult := h.shutdownOwner(parent, owner, err)
		println("terminal exit", terminal.StreamID, ptyErr, shutdownResult.Err)
		printf("Terminal KeepAlive启动失败: %v", err)
		return
	}
	println("terminal init", terminal.StreamID)
	go func() { session.producerDone <- session.producePTYOutput() }()
	go func() { session.receiverDone <- session.receiveInput() }()

	var cause error
	producerJoined := false
	receiverJoined := false
	select {
	case cause = <-session.producerDone:
		producerJoined = true
	case cause = <-session.receiverDone:
		receiverJoined = true
	case <-parent.Done():
		cause = context.Cause(parent)
	}
	ptyErr, shutdownResult := session.shutdown(cause, producerJoined, receiverJoined)
	println("terminal exit", terminal.StreamID, ptyErr, shutdownResult.Err)
}

func terminalAttachFrame(streamID string) []byte {
	return append([]byte{0xff, 0x05, 0xff, 0x05}, []byte(streamID)...)
}

func (h terminalHandler) shutdownOwner(
	parent context.Context,
	owner *ioStreamWriteOwner,
	cause error,
) ioStreamWriteShutdownResult {
	graceContext, cancelGrace := context.WithTimeout(context.WithoutCancel(parent), h.shutdownTimeout)
	defer cancelGrace()
	return owner.Shutdown(graceContext, cause)
}

func (s *terminalSession) producePTYOutput() error {
	buffer := make([]byte, 10240)
	for {
		read, err := s.tty.Read(buffer)
		if err != nil {
			if s.producerContext.Err() != nil {
				return context.Cause(s.producerContext)
			}
			if sendErr := s.owner.Send(&pb.IOStreamData{Data: []byte(err.Error())}); sendErr != nil {
				return sendErr
			}
			return err
		}
		if read == 0 {
			continue
		}
		if err := s.owner.Send(&pb.IOStreamData{Data: buffer[:read]}); err != nil {
			return err
		}
	}
}

func (s *terminalSession) receiveInput() error {
	for {
		remoteData, err := s.stream.Recv()
		if err != nil {
			return err
		}
		if len(remoteData.GetData()) == 0 {
			continue
		}
		switch remoteData.GetData()[0] {
		case 0:
			_, _ = s.tty.Write(remoteData.GetData()[1:])
		case 1:
			var resize terminalWindowSize
			if err := json.Unmarshal(remoteData.GetData()[1:], &resize); err == nil {
				_ = s.tty.Setsize(resize.Cols, resize.Rows)
			}
		}
	}
}

func (s *terminalSession) shutdown(
	cause error,
	producerJoined bool,
	receiverJoined bool,
) (error, ioStreamWriteShutdownResult) {
	s.cancelProducer(cause)
	graceContext, cancelGrace := context.WithTimeout(context.WithoutCancel(s.parent), s.shutdownTimeout)
	defer cancelGrace()
	activeDone, sendErr := s.owner.beginClosing()
	keepaliveDone := s.owner.StopKeepalive()
	forced, forcedCause := s.owner.waitForQuiescence(graceContext, keepaliveDone, activeDone)
	if forced {
		s.owner.cancel(forcedCause)
		s.owner.joinQuiescence(keepaliveDone, activeDone)
	}
	ptyErr := s.tty.Close()
	// IPty.Close owns process cleanup and must release an in-flight Read. Joining
	// here keeps the producer from retaining the stream after CloseSend.
	if !producerJoined {
		<-s.producerDone
	}
	closeErr := s.owner.closeSendOnce()
	if !forced {
		s.owner.cancel(firstError(sendErr, closeErr, cause))
	}
	s.owner.stateMu.Lock()
	s.owner.state = ioStreamWriteClosed
	s.owner.stateMu.Unlock()
	result := ioStreamWriteShutdownResult{
		Err:    firstError(sendErr, closeErr),
		Cause:  forcedCause,
		Forced: forced,
	}
	if !receiverJoined {
		<-s.receiverDone
	}
	return ptyErr, result
}
