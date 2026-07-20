package main

import (
	"context"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func receiveTasksDaemon(tasks *requestTaskSession, session *connectionSession) {
	execution := agentTaskExecution{
		parent:  tasks.Context(),
		session: session,
		send:    tasks.Send,
		cancel:  func() { session.signalExit(context.Canceled) },
	}
	for {
		task, err := tasks.Recv()
		if err != nil {
			printf("receiveTasks exit: %v", err)
			session.signalExit(err)
			return
		}
		execution.dispatch(task)
	}
}

func dispatchAgentTask(task *pb.Task, send func(*pb.TaskResult) error, cancel context.CancelFunc) {
	agentTaskExecution{
		parent: context.Background(),
		send:   send,
		cancel: cancel,
	}.dispatch(task)
}

type agentTaskRunner func(context.Context, *model.AgentConfig, *pb.Task) *pb.TaskResult

type agentTaskExecution struct {
	parent     context.Context
	session    *connectionSession
	send       func(*pb.TaskResult) error
	cancel     context.CancelFunc
	runTask    agentTaskRunner
	onTaskExit func()
}

func (e agentTaskExecution) dispatch(task *pb.Task) {
	switch task.GetType() {
	case model.TaskTypeApplyConfig, model.TaskTypeServerTransferApply:
		// Apply handlers capture their sole snapshot after acquiring reloadMu.
		// Loading here would either duplicate the snapshot or use a stale baseline
		// after waiting behind applyPendingReload.
		e.runAgentTask(e.parent, nil, task)
		return
	case model.TaskTypeTerminalGRPC, model.TaskTypeNAT, model.TaskTypeFM, model.TaskTypeFsTransfer:
		config := loadRuntimeConfig()
		if e.session != nil {
			e.session.startLongLivedStreamTask(func(taskContext context.Context) {
				e.runAgentTask(taskContext, config, task)
			})
			return
		}
		go e.runAgentTask(e.parent, config, task)
		return
	}
	config := loadRuntimeConfig()
	go e.runAgentTask(e.parent, config, task)
}

func (e agentTaskExecution) runAgentTask(
	taskContext context.Context,
	config *model.AgentConfig,
	task *pb.Task,
) {
	if e.onTaskExit != nil {
		defer e.onTaskExit()
	}
	defer func() {
		if err := recover(); err != nil {
			println("task panic", task, err)
		}
	}()
	runTask := e.runTask
	if runTask == nil {
		runTask = doTaskWithSnapshot
	}
	result := runTask(taskContext, config, task)
	if result == nil {
		return
	}
	if err := e.send(result); err != nil {
		printf("send task result exit: %v", err)
		e.cancel()
	}
}

func doTask(task *pb.Task) *pb.TaskResult {
	return doTaskWithSnapshot(context.Background(), loadRuntimeConfig(), task)
}

func doTaskWithContext(parent context.Context, task *pb.Task) *pb.TaskResult {
	return doTaskWithSnapshot(parent, loadRuntimeConfig(), task)
}

func doTaskWithSnapshot(
	parent context.Context,
	config *model.AgentConfig,
	task *pb.Task,
) *pb.TaskResult {
	result := &pb.TaskResult{Id: task.GetId(), Type: task.GetType()}
	if task.GetType() == model.TaskTypeApplyConfig {
		handleApplyConfigTask(task, result)
		return result
	}
	if task.GetType() == model.TaskTypeServerTransferApply {
		handleServerTransferApplyTask(task, result)
		return result
	}
	gates := taskFeatureGatesFrom(config)
	switch task.GetType() {
	case model.TaskTypeHTTPGet:
		handleHttpGetTaskWithConfig(gates, task, result)
	case model.TaskTypeICMPPing:
		handleIcmpPingTaskWithConfig(gates, task, result)
	case model.TaskTypeTCPPing:
		handleTcpPingTaskWithConfig(gates, task, result)
	case model.TaskTypeCommand:
		handleCommandTaskWithConfig(gates, task, result)
	case model.TaskTypeUpgrade:
		handleUpgradeTaskWithConfig(updateConfigTupleFrom(config), gates)
	case model.TaskTypeTerminalGRPC:
		handleTerminalTaskWithConfig(parent, gates, task)
		return nil
	case model.TaskTypeNAT:
		handleNATTaskWithConfig(parent, gates, task)
		return nil
	case model.TaskTypeFM:
		handleFMTaskWithConfig(parent, gates, task)
		return nil
	case model.TaskTypeReportConfig:
		handleReportConfigTaskWithConfig(config, result)
	case model.TaskTypeExec:
		handleExecTaskWithConfig(gates, task, result)
	case model.TaskTypeFsList:
		handleFsListTaskWithConfig(gates, task, result)
	case model.TaskTypeFsRead:
		handleFsReadTaskWithConfig(gates, task, result)
	case model.TaskTypeFsWrite:
		handleFsWriteTaskWithConfig(gates, task, result)
	case model.TaskTypeFsDelete:
		handleFsDeleteTaskWithConfig(gates, task, result)
	case model.TaskTypeFsTransfer:
		handleFsTransferTaskWithConfig(parent, gates, task)
		return nil
	case model.TaskTypeKeepalive:
	default:
		printf("不支持的任务: %v", task)
		return nil
	}
	return result
}
