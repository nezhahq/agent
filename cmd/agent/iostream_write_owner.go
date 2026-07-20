package main

import (
	"context"
	"errors"
	"sync"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

var (
	errIOStreamWriteClosed           = errors.New("IOStream write side is closed")
	errIOStreamKeepaliveAlreadyStart = errors.New("IOStream keepalive already started")
)

type ioStreamWriteState uint8

const (
	ioStreamWriteAccepting ioStreamWriteState = iota
	ioStreamWriteClosing
	ioStreamWriteClosed
)

type ioStreamWriteShutdownResult struct {
	Err    error
	Cause  error
	Forced bool
}

type ioStreamWriteOwner struct {
	stream       pb.NezhaService_IOStreamClient
	cancelStream func(error)

	sendMu sync.Mutex

	stateMu        sync.Mutex
	state          ioStreamWriteState
	activeDone     chan struct{}
	terminalErr    error
	keepaliveStart bool
	keepaliveStop  chan struct{}
	keepaliveDone  chan struct{}

	stopKeepaliveOnce sync.Once
	cancelOnce        sync.Once
	closeOnce         sync.Once
	shutdownOnce      sync.Once
	shutdownResult    ioStreamWriteShutdownResult
}

func newIOStreamWriteOwner(stream pb.NezhaService_IOStreamClient, cancelStream func(error)) *ioStreamWriteOwner {
	return &ioStreamWriteOwner{
		stream:        stream,
		cancelStream:  cancelStream,
		state:         ioStreamWriteAccepting,
		keepaliveStop: make(chan struct{}),
		keepaliveDone: make(chan struct{}),
	}
}

func (o *ioStreamWriteOwner) Send(message *pb.IOStreamData) error {
	if err := o.rejectedSendError(); err != nil {
		return err
	}
	o.sendMu.Lock()

	o.stateMu.Lock()
	if o.state != ioStreamWriteAccepting {
		err := errors.Join(errIOStreamWriteClosed, o.terminalErr)
		o.stateMu.Unlock()
		o.sendMu.Unlock()
		return err
	}
	activeDone := make(chan struct{})
	o.activeDone = activeDone
	o.stateMu.Unlock()

	err := o.stream.Send(message)

	o.stateMu.Lock()
	o.activeDone = nil
	if err != nil {
		o.state = ioStreamWriteClosing
		o.recordTerminalErrorLocked(err)
	}
	o.stateMu.Unlock()
	o.sendMu.Unlock()
	if err != nil {
		o.cancel(err)
	}
	close(activeDone)
	return err
}

func (o *ioStreamWriteOwner) StartKeepalive(interval time.Duration) error {
	o.stateMu.Lock()
	if o.state != ioStreamWriteAccepting {
		err := errors.Join(errIOStreamWriteClosed, o.terminalErr)
		o.stateMu.Unlock()
		return err
	}
	if o.keepaliveStart {
		o.stateMu.Unlock()
		return errIOStreamKeepaliveAlreadyStart
	}
	o.keepaliveStart = true
	o.stateMu.Unlock()

	go o.runKeepalive(interval)
	return nil
}

func (o *ioStreamWriteOwner) runKeepalive(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(o.keepaliveDone)
	for {
		select {
		case <-o.keepaliveStop:
			return
		default:
		}
		select {
		case <-o.keepaliveStop:
			return
		case <-ticker.C:
			if err := o.Send(&pb.IOStreamData{Data: []byte{}}); err != nil {
				return
			}
		}
	}
}

func (o *ioStreamWriteOwner) StopKeepalive() <-chan struct{} {
	o.stateMu.Lock()
	started := o.keepaliveStart
	o.stopKeepaliveOnce.Do(func() { close(o.keepaliveStop) })
	if !started {
		close(o.keepaliveDone)
		o.keepaliveStart = true
	}
	done := o.keepaliveDone
	o.stateMu.Unlock()
	return done
}

func (o *ioStreamWriteOwner) Shutdown(graceContext context.Context, cause error) ioStreamWriteShutdownResult {
	return o.finishWriteSide(graceContext, cause, true)
}

func (o *ioStreamWriteOwner) beginClosing() (<-chan struct{}, error) {
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	if o.state == ioStreamWriteAccepting {
		o.state = ioStreamWriteClosing
	}
	return o.activeDone, o.terminalErr
}

func (o *ioStreamWriteOwner) waitForQuiescence(
	graceContext context.Context,
	keepaliveDone <-chan struct{},
	activeDone <-chan struct{},
) (bool, error) {
	if err := o.stream.Context().Err(); err != nil {
		return true, context.Cause(o.stream.Context())
	}
	if forced, cause := waitForIOStreamSignal(graceContext, o.stream.Context(), keepaliveDone); forced {
		return true, cause
	}
	if activeDone == nil {
		return false, nil
	}
	return waitForIOStreamSignal(graceContext, o.stream.Context(), activeDone)
}

func waitForIOStreamSignal(graceContext, streamContext context.Context, done <-chan struct{}) (bool, error) {
	select {
	case <-done:
		return false, nil
	default:
	}
	select {
	case <-done:
		return false, nil
	case <-graceContext.Done():
		select {
		case <-done:
			return false, nil
		default:
			return true, context.Cause(graceContext)
		}
	case <-streamContext.Done():
		return true, context.Cause(streamContext)
	}
}

func (o *ioStreamWriteOwner) joinQuiescence(keepaliveDone <-chan struct{}, activeDone <-chan struct{}) {
	<-keepaliveDone
	if activeDone != nil {
		<-activeDone
	}
}

func (o *ioStreamWriteOwner) closeSendOnce() error {
	o.sendMu.Lock()
	var closeErr error
	o.closeOnce.Do(func() {
		closeErr = o.stream.CloseSend()
		o.stateMu.Lock()
		o.recordTerminalErrorLocked(closeErr)
		o.stateMu.Unlock()
	})
	o.sendMu.Unlock()
	if closeErr != nil {
		o.cancel(o.terminalError())
	}
	return o.terminalError()
}

func (o *ioStreamWriteOwner) rejectedSendError() error {
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	if o.state == ioStreamWriteAccepting {
		return nil
	}
	return errors.Join(errIOStreamWriteClosed, o.terminalErr)
}

func (o *ioStreamWriteOwner) terminalError() error {
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	return o.terminalErr
}

func (o *ioStreamWriteOwner) recordTerminalErrorLocked(err error) {
	if o.terminalErr == nil && err != nil {
		o.terminalErr = err
	}
}

func (o *ioStreamWriteOwner) cancel(cause error) {
	o.cancelOnce.Do(func() { o.cancelStream(cause) })
}
