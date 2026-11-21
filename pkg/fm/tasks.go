package fm

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"sync/atomic"

	pb "github.com/nezhahq/agent/proto"
)

type Sender interface {
	Send(*pb.IOStreamData) error
}

type UploadReceiver interface {
	Recv() (*pb.IOStreamData, error)
}

type Dependencies struct {
	Context        context.Context
	Sender         Sender
	UploadReceiver UploadReceiver
	Printf         func(string, ...interface{})
}

type Task struct {
	context         context.Context
	cancel          context.CancelCauseFunc
	sender          Sender
	uploadReceiver  UploadReceiver
	printf          func(string, ...interface{})
	openFile        func(string) (downloadFile, error)
	parseCommand    commandParser
	dispatchCommand commandDispatcher

	// framed 为 true 表示本会话已协商成带帧头的协议（版本 2）。
	framed atomic.Bool

	producerMu sync.Mutex
	accepting  bool
	producers  sync.WaitGroup
	active     atomic.Int64
	files      map[downloadFile]struct{}
}

type downloadFile interface {
	Read([]byte) (int, error)
	Stat() (os.FileInfo, error)
	Close() error
}

type commandOperation byte

const (
	commandList commandOperation = iota
	commandDownload
	commandUpload
	// commandHello 协商带帧头的协议，见 framed_protocol.go。
	commandHello
)

type parsedCommand struct {
	operation commandOperation
	path      string
	fileSize  uint64
	// helloVersion 是对端在问候里声明的最高协议版本。
	helloVersion byte
}

type commandParser func([]byte) (parsedCommand, error)
type commandDispatcher func(parsedCommand) error

var errInvalidCommandData = errors.New("data is invalid")

func NewFMClient(dependencies Dependencies) *Task {
	taskContext, cancelTask := context.WithCancelCause(dependencies.Context)
	task := &Task{
		context:        taskContext,
		cancel:         cancelTask,
		sender:         dependencies.Sender,
		uploadReceiver: dependencies.UploadReceiver,
		printf:         dependencies.Printf,
		openFile:       openDownloadFile,
		parseCommand:   defaultCommandParser,
		accepting:      true,
		files:          make(map[downloadFile]struct{}),
	}
	task.dispatchCommand = task.dispatchParsedCommand
	return task
}

func (t *Task) DoTask(data *pb.IOStreamData) error {
	command, err := t.parseCommand(data.GetData())
	if err != nil {
		return t.sendInvalidData()
	}

	return t.dispatchCommand(command)
}

func (t *Task) dispatchParsedCommand(command parsedCommand) error {
	switch command.operation {
	case commandList:
		return t.listDir(command.path)
	case commandDownload:
		if !t.startDownload(command.path) {
			return context.Cause(t.context)
		}
		return nil
	case commandUpload:
		return t.upload(command.path, command.fileSize)
	case commandHello:
		return t.acknowledgeHello(command.helloVersion)
	}
	return nil
}

func defaultCommandParser(frame []byte) (parsedCommand, error) {
	if len(frame) == 0 {
		return parsedCommand{}, errInvalidCommandData
	}
	command := parsedCommand{operation: commandOperation(frame[0])}
	switch command.operation {
	case commandList, commandDownload:
		command.path = string(frame[1:])
	case commandUpload:
		if len(frame) < 9 {
			return parsedCommand{}, errInvalidCommandData
		}
		command.fileSize = binary.BigEndian.Uint64(frame[1:9])
		command.path = string(frame[9:])
	case commandHello:
		if len(frame) < 2 {
			return parsedCommand{}, errInvalidCommandData
		}
		command.helloVersion = frame[1]
	}
	return command, nil
}

// acknowledgeHello 应答问候并切换到双方都支持的最高版本。
// 声明的版本低于 2 的对端得到版本 1 的应答，会话继续按旧协议工作。
func (t *Task) acknowledgeHello(peerVersion byte) error {
	version := byte(1)
	if peerVersion >= framedProtocolVersion {
		version = framedProtocolVersion
		t.framed.Store(true)
	}
	return t.sender.Send(&pb.IOStreamData{Data: createHelloAcknowledgement(version)})
}

func (t *Task) sendInvalidData() error {
	t.printf(errInvalidCommandData.Error())
	return t.sender.Send(&pb.IOStreamData{Data: CreateErr(errInvalidCommandData)})
}

func (t *Task) startDownload(path string) bool {
	t.producerMu.Lock()
	if !t.accepting {
		t.producerMu.Unlock()
		return false
	}
	t.producers.Add(1)
	active := t.active.Add(1)
	t.producerMu.Unlock()
	observeProducerCount(t.context, active)
	go func() {
		defer func() {
			active := t.active.Add(-1)
			observeProducerCount(t.context, active)
			t.producers.Done()
		}()
		_ = t.download(path)
	}()
	return true
}

func (t *Task) Shutdown(cause error) {
	t.producerMu.Lock()
	t.accepting = false
	t.cancel(cause)
	for file := range t.files {
		_ = file.Close()
	}
	t.producerMu.Unlock()
	t.producers.Wait()
}

func (t *Task) registerFile(file downloadFile) bool {
	t.producerMu.Lock()
	defer t.producerMu.Unlock()
	if !t.accepting {
		return false
	}
	t.files[file] = struct{}{}
	return true
}

func (t *Task) unregisterFile(file downloadFile) {
	t.producerMu.Lock()
	delete(t.files, file)
	t.producerMu.Unlock()
}

type bp struct {
	buf []byte
}

var bufPool = sync.Pool{
	New: func() any {
		return &bp{
			buf: make([]byte, 1024*1024),
		}
	},
}
