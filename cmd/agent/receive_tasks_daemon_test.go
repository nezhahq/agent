package main

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

type sendCompletionRequestTaskStream struct {
	pb.NezhaService_RequestTaskClient
	sendCompleted chan struct{}
}

func (s *sendCompletionRequestTaskStream) Send(result *pb.TaskResult) error {
	err := s.NezhaService_RequestTaskClient.Send(result)
	s.sendCompleted <- struct{}{}
	return err
}

func TestReceiveTasksDaemon_DoesNotCancelHealthyIdleStream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Given
		session := newConnectionSession(context.Background())
		stream := newRequestTaskStreamFixture(session.requestTaskContext, streamCallAllowance{recv: 2, send: 1})
		requestSession := session.bindRequestTask(stream)
		daemonExited := make(chan struct{})
		go func() {
			receiveTasksDaemon(requestSession, session)
			close(daemonExited)
		}()
		<-stream.recvEntered
		task := &pb.Task{Id: 72, Type: model.TaskTypeKeepalive}
		oldIdleBoundaryElapsed := make(chan struct{})
		go func() {
			time.Sleep(31 * time.Second)
			close(oldIdleBoundaryElapsed)
			stream.releaseRecv(task, nil)
		}()

		// When
		<-oldIdleBoundaryElapsed
		synctest.Wait()

		// Then
		select {
		case <-daemonExited:
			t.Fatal("healthy idle RequestTask daemon exited at the old caller-only timeout boundary")
		default:
		}
		select {
		case <-session.streamContext.Done():
			t.Fatalf("healthy idle RequestTask context canceled: %v", context.Cause(session.streamContext))
		default:
		}
		<-stream.writeEntered
		stream.releaseWrite(streamWriteSend, nil)
		<-stream.recvEntered
		sent := stream.sentMessages()
		if len(sent) != 1 || sent[0].GetId() != task.GetId() {
			t.Fatalf("task results = %+v, want one result for task %d", sent, task.GetId())
		}

		session.cancelStream(context.Canceled)
		synctest.Wait()
		<-daemonExited
	})
}

func TestReceiveTasksDaemon_PreservesTaskDeliveryAndResult(t *testing.T) {
	// Given
	session := newConnectionSession(context.Background())
	baseStream := newRequestTaskStreamFixture(session.requestTaskContext, streamCallAllowance{recv: 2, send: 1})
	stream := &sendCompletionRequestTaskStream{
		NezhaService_RequestTaskClient: baseStream,
		sendCompleted:                  make(chan struct{}, 1),
	}
	requestSession := session.bindRequestTask(stream)
	daemonExited := make(chan struct{})
	go func() {
		receiveTasksDaemon(requestSession, session)
		close(daemonExited)
	}()
	baseStream.waitRecvEntered(t)
	task := &pb.Task{Id: 71, Type: model.TaskTypeKeepalive}

	// When
	baseStream.releaseRecv(task, nil)
	baseStream.waitWriteEntered(t, streamWriteSend)
	baseStream.releaseWrite(streamWriteSend, nil)
	awaitStreamSignal(t, stream.sendCompleted, "RequestTask result Send completion")
	baseStream.waitRecvEntered(t)

	// Then
	sent := baseStream.sentMessages()
	if len(sent) != 1 {
		t.Fatalf("task result count = %d, want 1", len(sent))
	}
	if sent[0].GetId() != task.GetId() || sent[0].GetType() != task.GetType() {
		t.Fatalf("task result = %+v, want id=%d type=%d", sent[0], task.GetId(), task.GetType())
	}

	session.cancelStream(context.Canceled)
	awaitStreamSignal(t, daemonExited, "receiveTasksDaemon exit")
}
