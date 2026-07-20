package main

import (
	"context"
	"errors"
	"time"

	pb "github.com/nezhahq/agent/proto"
)

var errNATHalfCloseDrainTimeout = errors.New("NAT half-close drain timeout")

type natReaderResultKind uint8

const (
	natReaderLocalReadEnded natReaderResultKind = iota
	natReaderStreamSendFailed
	natReaderCanceled
)

type natReaderResult struct {
	kind natReaderResultKind
	err  error
}

func startNATHalfCloseDrain(timeout time.Duration) (<-chan time.Time, func()) {
	timer := time.NewTimer(timeout)
	return timer.C, func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

func (s *natSession) produceTCPOutput() natReaderResult {
	buffer := make([]byte, 10240)
	for {
		read, readErr := s.conn.Read(buffer)
		if readErr != nil {
			return s.finishLocalRead(buffer[:read], readErr)
		}
		if read == 0 {
			continue
		}
		if err := s.owner.Send(&pb.IOStreamData{Data: buffer[:read]}); err != nil {
			return natReaderResult{kind: natReaderStreamSendFailed, err: err}
		}
	}
}

func (s *natSession) finishLocalRead(tail []byte, readErr error) natReaderResult {
	if s.readerContext.Err() != nil {
		return natReaderResult{kind: natReaderCanceled, err: context.Cause(s.readerContext)}
	}
	graceContext, cancelGrace := context.WithTimeout(context.WithoutCancel(s.parent), s.shutdownTimeout)
	defer cancelGrace()
	keepaliveDone := s.owner.StopKeepalive()
	select {
	case <-keepaliveDone:
	case <-graceContext.Done():
		s.owner.cancel(context.Cause(graceContext))
		<-keepaliveDone
		return natReaderResult{kind: natReaderStreamSendFailed, err: context.Cause(graceContext)}
	case <-s.stream.Context().Done():
		return natReaderResult{kind: natReaderCanceled, err: context.Cause(s.stream.Context())}
	}
	if len(tail) > 0 {
		if err := s.owner.Send(&pb.IOStreamData{Data: tail}); err != nil {
			return natReaderResult{kind: natReaderStreamSendFailed, err: err}
		}
	}
	if err := s.owner.Send(&pb.IOStreamData{Data: []byte(readErr.Error())}); err != nil {
		return natReaderResult{kind: natReaderStreamSendFailed, err: err}
	}
	shutdownResult := s.owner.CloseSendAfterQuiescence(graceContext)
	if shutdownResult.Err != nil || shutdownResult.Forced {
		return natReaderResult{
			kind: natReaderStreamSendFailed,
			err:  firstError(shutdownResult.Err, shutdownResult.Cause),
		}
	}
	return natReaderResult{kind: natReaderLocalReadEnded, err: readErr}
}
