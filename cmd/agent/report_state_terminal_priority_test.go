package main

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
)

func TestReportStateTerminal_TerminalWinsWhenGraceAlsoReady(t *testing.T) {
	// Given
	var cancelCalls atomic.Int32
	session := &reportStateSession{
		cancelStream: func(error) { cancelCalls.Add(1) },
		terminalDone: make(chan struct{}),
	}
	session.finishTerminal(io.EOF)
	grace, cancelGrace := context.WithCancelCause(context.Background())
	graceCause := errors.New("grace expired")
	cancelGrace(graceCause)

	// When
	terminalErr, forced := session.waitForTerminal(grace)

	// Then
	if !errors.Is(terminalErr, io.EOF) || forced {
		t.Fatalf("terminal result = (%v, forced=%t), want io.EOF and false", terminalErr, forced)
	}
	if got := cancelCalls.Load(); got != 0 {
		t.Fatalf("ReportState child cancel calls = %d, want 0", got)
	}
}
