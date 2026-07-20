package main

import (
	"errors"
	"sync"

	pb "github.com/nezhahq/agent/proto"
)

var errReportStateWriteClosed = errors.New("ReportState write side is closed")

type reportStateWriteOwner struct {
	stream pb.NezhaService_ReportSystemStateClient

	sendMu sync.Mutex

	stateMu     sync.Mutex
	accepting   bool
	activeDone  chan struct{}
	terminalErr error
	closeOnce   sync.Once
}

func newReportStateWriteOwner(stream pb.NezhaService_ReportSystemStateClient) *reportStateWriteOwner {
	return &reportStateWriteOwner{stream: stream, accepting: true}
}

func (o *reportStateWriteOwner) Send(state *pb.State) error {
	if err := o.rejectedSendError(); err != nil {
		return err
	}
	o.sendMu.Lock()

	o.stateMu.Lock()
	if !o.accepting {
		err := errors.Join(errReportStateWriteClosed, o.terminalErr)
		o.stateMu.Unlock()
		o.sendMu.Unlock()
		return err
	}
	activeDone := make(chan struct{})
	o.activeDone = activeDone
	o.stateMu.Unlock()

	err := o.stream.Send(state)

	o.stateMu.Lock()
	o.activeDone = nil
	if err != nil {
		o.accepting = false
		o.recordTerminalErrorLocked(err)
	}
	close(activeDone)
	o.stateMu.Unlock()
	o.sendMu.Unlock()
	return err
}

func (o *reportStateWriteOwner) rejectedSendError() error {
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	if o.accepting {
		return nil
	}
	return errors.Join(errReportStateWriteClosed, o.terminalErr)
}

func (o *reportStateWriteOwner) beginClosing() (<-chan struct{}, error) {
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	o.accepting = false
	return o.activeDone, o.terminalErr
}

func (o *reportStateWriteOwner) closeSendOnce() error {
	o.sendMu.Lock()
	defer o.sendMu.Unlock()
	o.closeOnce.Do(func() {
		err := o.stream.CloseSend()
		o.stateMu.Lock()
		o.recordTerminalErrorLocked(err)
		o.stateMu.Unlock()
	})
	return o.terminalError()
}

func (o *reportStateWriteOwner) terminalError() error {
	o.stateMu.Lock()
	defer o.stateMu.Unlock()
	return o.terminalErr
}

func (o *reportStateWriteOwner) recordTerminalErrorLocked(err error) {
	if o.terminalErr == nil && err != nil {
		o.terminalErr = err
	}
}
