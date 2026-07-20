package main

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

// gRPC Go ClientStream 不允许两个 goroutine 并发调用 SendMsg
// (https://pkg.go.dev/google.golang.org/grpc#ClientStream). MCP fs.transfer
// 在同一条 IOStream 上既要让 keepalive 周期发空帧，又要 upload/download 主
// 流程发协议帧，因此所有 Send 都必须经由 serialIOStreamSender 串行化。
type ioStreamSender interface {
	Send(*pb.IOStreamData) error
}

type fsTransferStream interface {
	ioStreamSender
	Recv() (*pb.IOStreamData, error)
}

type serialIOStreamSender struct {
	owner *ioStreamWriteOwner
}

func newSerialIOStreamSender(stream pb.NezhaService_IOStreamClient) *serialIOStreamSender {
	return &serialIOStreamSender{owner: newIOStreamWriteOwner(stream, func(error) {})}
}

func (s *serialIOStreamSender) Send(data *pb.IOStreamData) error {
	return s.owner.Send(data)
}

// serializedKeepAlive 是 fs.transfer 期间替代 ioStreamKeepAlive 的版本：
// 复用 serialIOStreamSender，保证心跳帧与协议帧共享同一串行化器，永远不会
// 与 NZTU / NZTD / NZTC / NZTO / NZTE 帧并发写入。
func serializedKeepAlive(ctx context.Context, sender *serialIOStreamSender, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		// Check cancellation before selecting a ready tick. Without this priority,
		// a completed Send can race a queued tick and emit one frame after stop.
		select {
		case <-ctx.Done():
			return
		default:
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sender.Send(&pb.IOStreamData{Data: []byte{}}); err != nil {
				printf("IOStream serializedKeepAlive failed: %v", err)
				return
			}
		}
	}
}

// MCP fs.upload / fs.download 走 IOStream 双向流而非 RequestTask 的一次性
// RPC，专为 ~100MB 量级大文件设计：避免 gRPC 默认 4MB 单消息上限，并且
// 不再一次性把整文件 base64 后塞进 JSON。
//
// 协议帧规格定义见 model.MCPFsXferMagic* 与 model.MCPFsTransferOp*。
//
// 上传时序（dashboard→agent）：
//
//	  agent ─▶ NZTU(magic+size)            // 通告"准备好接 size 字节"
//	  dashboard ─▶ chunk... (size bytes)   // 多帧任意大小的数据
//	  agent ─▶ NZTO(magic+sha256+size)     // 成功，附 sha256 校验
//	  agent ─▶ NZTE(magic+msg)             // 失败
//
// 下载时序（agent→dashboard）：
//
//	  agent ─▶ NZTD(magic+size+sha256)     // 通告"接下来会发 size 字节"
//	  agent ─▶ chunk... (size bytes)
//	  agent ─▶ NZTO(magic+sha256+size)     // 全部发完，附 sha256 终值
//	  agent ─▶ NZTE(magic+msg)             // 失败
//
// agent 任何分支失败都先发 NZTE 再关流，dashboard 据此把错误返回给调用方。

const (
	mcpFsTransferChunk      = 1 * 1024 * 1024 // 1MiB；与 fm.bufPool 同序，方便复用调试经验
	mcpFsTransferIOTimeout  = 5 * time.Minute // agent 单边阻塞最大时长（防止挂死）
	mcpFsTransferTempPrefix = ".mcp-xfer-"
)

// decideFsTransferEarlyError 把 fs.transfer 的 pre-IOStream 决策做成纯函数，
// 以便单测在不构造 gRPC 通道的前提下钉死契约。返回值含义：
//
//   - req:        成功解析的请求；JSON 解析失败时为 nil
//   - errMsg:     非空表示这是一个早退失败分支，应通过 NZTE 通知 dashboard
//   - hasStream:  errMsg 非空时还能不能 attach；只有同时拿到 stream_id 才有
//     可能走完 IOStream hello。stream_id 缺失 / JSON 完全解析失败时
//     hasStream=false，此时只能记录日志、放弃 attach（dashboard 侧会
//     在 30s WaitForAgent 超时兜底）。
//
// 没有任何错误时 errMsg=="" 且 hasStream=true，调用方按正常路径继续。
func decideFsTransferEarlyError(commandExecutionDisabled bool, task *pb.Task) (*model.FsTransferRequest, string, bool) {
	var req model.FsTransferRequest
	if err := json.Unmarshal([]byte(task.GetData()), &req); err != nil {
		return nil, "FsTransfer 任务解析失败: " + err.Error(), false
	}
	if req.StreamID == "" {
		return &req, "FsTransfer 缺少必要参数: stream_id 为空", false
	}
	// stream_id 已知 → 失败分支仍可走完 IOStream hello + NZTE。
	if commandExecutionDisabled {
		return &req, "FsTransfer 被 agent DisableCommandExecute 拒绝", true
	}
	if req.Path == "" {
		return &req, "FsTransfer 缺少必要参数: path 为空", true
	}
	switch req.Op {
	case model.MCPFsTransferOpUpload, model.MCPFsTransferOpDownload:
	default:
		return &req, "unknown op: " + req.Op, true
	}
	return &req, "", true
}

func handleFsTransferTaskWithConfig(parent context.Context, gates taskFeatureGates, task *pb.Task) {
	req, earlyErr, hasStream := decideFsTransferEarlyError(gates.disableCommandExecute, task)
	if earlyErr != "" && !hasStream {
		printf("%s", earlyErr)
		return
	}

	ctx, cancel := context.WithTimeout(parent, mcpFsTransferIOTimeout)
	// 不 defer cancel() — cancel 发 RST_STREAM 终止 stream，
	// 可能抢在 CloseSend 之前到达，dashboard 丢数据。

	stream, err := client.IOStream(ctx)
	if err != nil {
		cancel()
		printf("FsTransfer IOStream 拨号失败: %v", err)
		return
	}

	owner := newIOStreamWriteOwner(stream, func(error) { cancel() })
	if err := owner.Send(&pb.IOStreamData{Data: append(
		[]byte{0xff, 0x05, 0xff, 0x05}, []byte(req.StreamID)...,
	)}); err != nil {
		owner.Shutdown(ctx, err)
		printf("FsTransfer 发送 streamId 失败: %v", err)
		return
	}

	if err := owner.StartKeepalive(30 * time.Second); err != nil {
		owner.Shutdown(ctx, err)
		printf("FsTransfer 启动 keepalive 失败: %v", err)
		return
	}

	runFsTransferOnStream(streamWithSerialSender{stream: stream, sender: owner}, earlyErr, req)

	// 传输完成：先停 keepalive，再 CloseSend，等 dashboard 关流后 cancel。
	// 顺序保证 CloseSend 在 cancel 之前送达，drain 保证在 cancel 前收到对端确认。
	closeResult := owner.CloseSendAfterQuiescence(ctx)
	if closeResult.Forced || closeResult.Err != nil {
		// Forced/error cleanup has already canceled through the owner, joined every
		// writer and attempted CloseSend once. It deliberately skips peer drain:
		// this non-graceful branch cannot promise final delivery or trailers.
		if closeResult.Err != nil {
			printf("FsTransfer CloseSend 失败: %v", closeResult.Err)
		}
		return
	}
	drainToEOF(stream)
	cancel()
}

// drainToEOF 丢弃空帧直到对端关闭。dashboard 读完所有数据后会通过
// CloseStream 关流，agent 端 Recv() 收到 io.EOF。
func drainToEOF(stream pb.NezhaService_IOStreamClient) {
	for {
		if _, err := stream.Recv(); err != nil {
			return
		}
	}
}

// streamWithSerialSender 让 runFsTransferOnStream 仍然按
// pb.NezhaService_IOStreamClient 的接口工作，但把 Send 全部走串行化器；
// CloseSend / Recv 等非写入侧方法仍直通底层 stream。
type streamWithSerialSender struct {
	stream pb.NezhaService_IOStreamClient
	sender ioStreamSender
}

func (s streamWithSerialSender) Send(d *pb.IOStreamData) error {
	return s.sender.Send(d)
}

func (s streamWithSerialSender) Recv() (*pb.IOStreamData, error) {
	return s.stream.Recv()
}

// runFsTransferOnStream 跑 attach 后的协议核心。早退分支只发一帧 NZTE
// 然后返回；正常分支按 op 派给 upload/download。抽出来是为了让单测能在
// 不构造 gRPC 通道的前提下钉死“早退即 NZTE”的契约，dashboard 端的
// readXferFixedHeader 会立即看到错误，而不是等到 30s WaitForAgent 超时。
func runFsTransferOnStream(stream fsTransferStream, earlyErr string, req *model.FsTransferRequest) {
	if earlyErr != "" {
		sendXferErr(stream, earlyErr)
		return
	}
	switch req.Op {
	case model.MCPFsTransferOpUpload:
		fsTransferUpload(stream, req)
	case model.MCPFsTransferOpDownload:
		fsTransferDownload(stream, req)
	default:
		sendXferErr(stream, "unknown op: "+req.Op)
	}
}
