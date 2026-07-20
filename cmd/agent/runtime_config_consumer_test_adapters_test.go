package main

import (
	"context"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

func setTestRuntimeConfig(config model.AgentConfig) *model.AgentConfig {
	agentConfig = config
	return publishRuntimeConfig(config)
}

func loadLegacyHandlerTestConfig() *model.AgentConfig {
	return publishRuntimeConfig(agentConfig)
}

func handleUpgradeTask(task *pb.Task, result *pb.TaskResult) {
	config := loadLegacyHandlerTestConfig()
	handleUpgradeTaskWithConfig(updateConfigTupleFrom(config), taskFeatureGatesFrom(config))
}

func handleTcpPingTask(task *pb.Task, result *pb.TaskResult) {
	handleTcpPingTaskWithConfig(taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task, result)
}

func handleIcmpPingTask(task *pb.Task, result *pb.TaskResult) {
	handleIcmpPingTaskWithConfig(taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task, result)
}

func handleHttpGetTask(task *pb.Task, result *pb.TaskResult) {
	handleHttpGetTaskWithConfig(taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task, result)
}

func handleCommandTask(task *pb.Task, result *pb.TaskResult) {
	handleCommandTaskWithConfig(taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task, result)
}

func handleReportConfigTask(result *pb.TaskResult) {
	handleReportConfigTaskWithConfig(loadLegacyHandlerTestConfig(), result)
}

func handleTerminalTask(task *pb.Task) {
	handleTerminalTaskWithConfig(context.Background(), taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task)
}

func handleNATTask(task *pb.Task) {
	handleNATTaskWithConfig(context.Background(), taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task)
}

func handleFMTask(task *pb.Task) {
	handleFMTaskWithConfig(context.Background(), taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task)
}

func handleExecTask(task *pb.Task, result *pb.TaskResult) {
	handleExecTaskWithConfig(taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task, result)
}

func handleFsListTask(task *pb.Task, result *pb.TaskResult) {
	handleFsListTaskWithConfig(taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task, result)
}

func handleFsReadTask(task *pb.Task, result *pb.TaskResult) {
	handleFsReadTaskWithConfig(taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task, result)
}

func handleFsWriteTask(task *pb.Task, result *pb.TaskResult) {
	handleFsWriteTaskWithConfig(taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task, result)
}

func handleFsDeleteTask(task *pb.Task, result *pb.TaskResult) {
	handleFsDeleteTaskWithConfig(taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task, result)
}

func handleFsTransferTask(task *pb.Task) {
	handleFsTransferTaskWithConfig(context.Background(), taskFeatureGatesFrom(loadLegacyHandlerTestConfig()), task)
}
