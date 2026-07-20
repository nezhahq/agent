package main

import (
	"context"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/pty"
	pb "github.com/nezhahq/agent/proto"
)

func TestTerminalShutdown_ConnectionSessionWaitsForActualHandlerBeforeReconnect(t *testing.T) {
	// Given
	restoreRuntimeConfigSnapshot(t)
	publishRuntimeConfig(model.AgentConfig{})
	originalFactory := terminalHandlerForTask
	t.Cleanup(func() { terminalHandlerForTask = originalFactory })
	releaseRead := make(chan struct{})
	tty := newTerminalTestPTY()
	tty.readRelease = releaseRead
	stream := &terminalTestStream{}
	stream.recvHook = func() (*pb.IOStreamData, error) {
		<-stream.ctx.Done()
		return nil, context.Cause(stream.ctx)
	}
	terminalHandlerForTask = func() terminalHandler {
		return terminalHandler{
			openStream: func(ctx context.Context) (pb.NezhaService_IOStreamClient, error) {
				stream.ctx = ctx
				return stream, nil
			},
			startPTY:          func() (pty.IPty, error) { return tty, nil },
			startKeepalive:    (*ioStreamWriteOwner).StartKeepalive,
			keepaliveInterval: time.Hour,
			shutdownTimeout:   100 * time.Millisecond,
		}
	}
	session := newConnectionSession(context.Background())
	execution := agentTaskExecution{
		parent:  session.streamContext,
		session: session,
		send:    func(*pb.TaskResult) error { return nil },
		cancel:  func() {},
	}
	execution.dispatch(&pb.Task{Type: model.TaskTypeTerminalGRPC, Data: `{"StreamID":"session-integration"}`})
	awaitStreamSignal(t, tty.readEntered, "actual Terminal PTY producer")
	reconnected := make(chan struct{})
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	go reconnectAfterSessionExit(session, sessionShutdown{
		graceContext: shutdownContext,
		cause:        context.Canceled,
	}, func() { close(reconnected) })
	awaitStreamSignal(t, tty.closed, "actual Terminal PTY close")

	// When
	select {
	case <-reconnected:
		t.Fatal("reconnect occurred before the actual Terminal producer joined")
	default:
	}
	close(releaseRead)
	awaitStreamSignal(t, reconnected, "reconnect after actual Terminal cleanup")

	// Then
	awaitStreamSignal(t, tty.readDone, "actual Terminal producer completion")
	_, maxInFlight, closeCount, recvCount := stream.observation()
	if maxInFlight != 1 || closeCount != 1 || recvCount != 1 || tty.closes() != 1 {
		t.Fatalf("actual Terminal cleanup: max=%d close=%d recv=%d pty_close=%d", maxInFlight, closeCount, recvCount, tty.closes())
	}
	if active := session.longLivedStreamTasks.activeCount(); active != 0 {
		t.Fatalf("long-lived registry active at reconnect = %d, want 0", active)
	}
}
