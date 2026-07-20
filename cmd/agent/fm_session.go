package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/fm"
	pb "github.com/nezhahq/agent/proto"
)

const (
	fmKeepaliveInterval = 30 * time.Second
	fmShutdownTimeout   = 2 * time.Second
)

type fmHandler struct {
	openStream        func(context.Context) (pb.NezhaService_IOStreamClient, error)
	newTask           func(fm.Dependencies) *fm.Task
	startKeepalive    func(*ioStreamWriteOwner, time.Duration) error
	keepaliveInterval time.Duration
	shutdownTimeout   time.Duration
}

var fmHandlerForTask = newFMHandler

func newFMHandler() fmHandler {
	return fmHandler{
		openStream: func(ctx context.Context) (pb.NezhaService_IOStreamClient, error) {
			return client.IOStream(ctx)
		},
		newTask:           fm.NewFMClient,
		startKeepalive:    (*ioStreamWriteOwner).StartKeepalive,
		keepaliveInterval: fmKeepaliveInterval,
		shutdownTimeout:   fmShutdownTimeout,
	}
}

func handleFMTaskWithConfig(parent context.Context, gates taskFeatureGates, task *pb.Task) {
	fmHandlerForTask().run(parent, gates, task)
}

func (h fmHandler) run(parent context.Context, gates taskFeatureGates, task *pb.Task) {
	if gates.disableCommandExecute {
		println("此 Agent 已禁止命令执行")
		return
	}
	var fileManagerTask model.TaskFM
	if err := json.Unmarshal([]byte(task.GetData()), &fileManagerTask); err != nil {
		printf("FM 任务解析错误: %v", err)
		return
	}

	streamContext, cancelStream := context.WithCancelCause(parent)
	stream, err := h.openStream(streamContext)
	if err != nil {
		cancelStream(err)
		printf("FM IOStream失败: %v", err)
		return
	}
	owner := newIOStreamWriteOwner(stream, cancelStream)
	if err := owner.Send(&pb.IOStreamData{Data: fmAttachFrame(fileManagerTask.StreamID)}); err != nil {
		h.shutdown(owner, nil, err)
		printf("FM 发送StreamID失败: %v", err)
		return
	}

	fileManagerContext, finishSession := prepareFMSessionContext(streamContext, fileManagerTask.StreamID)
	fileManager := h.newTask(fm.Dependencies{
		Context:        fileManagerContext,
		Sender:         owner,
		UploadReceiver: stream,
		Printf:         printf,
	})
	if err := h.startKeepalive(owner, h.keepaliveInterval); err != nil {
		h.shutdown(owner, fileManager, err)
		printf("FM KeepAlive启动失败: %v", err)
		return
	}
	println("FM init", fileManagerTask.StreamID)

	var cause error
	for {
		remoteData, recvErr := stream.Recv()
		if recvErr != nil {
			cause = recvErr
			break
		}
		if len(remoteData.GetData()) == 0 {
			continue
		}
		if taskErr := fileManager.DoTask(remoteData); taskErr != nil {
			cause = taskErr
			break
		}
	}
	result := h.shutdown(owner, fileManager, cause)
	finishSession()
	println("FM exit", fileManagerTask.StreamID, cause, result.Err)
}

func fmAttachFrame(streamID string) []byte {
	return append([]byte{0xff, 0x05, 0xff, 0x05}, []byte(streamID)...)
}

func (h fmHandler) shutdown(owner *ioStreamWriteOwner, fileManager *fm.Task, cause error) ioStreamWriteShutdownResult {
	owner.cancel(cause)
	if fileManager != nil {
		fileManager.Shutdown(cause)
	}
	graceContext, cancelGrace := context.WithTimeout(context.WithoutCancel(owner.stream.Context()), h.shutdownTimeout)
	defer cancelGrace()
	return owner.Shutdown(graceContext, cause)
}
