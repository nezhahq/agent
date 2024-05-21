package main

import (
	"os"

	"github.com/spf13/cobra"
)

var serviceCmd = &cobra.Command{
	Use:    "service <install/uninstall/start/stop/restart>",
	Short:  "服务与自启动设置",
	Args:   cobra.ExactArgs(1),
	Run:    serviceActions,
	PreRun: servicePreRun,
}

func init() {
	agentCmd.AddCommand(serviceCmd)
}

func servicePreRun(cmd *cobra.Command, args []string) {
	if args[0] == "install" {
		if agentCliParam.ClientSecret == "" {
			cmd.Help()
			os.Exit(1)
		}
	}

	if agentCliParam.ReportDelay < 1 || agentCliParam.ReportDelay > 4 {
		println("report-delay 的区间为 1-4")
		os.Exit(1)
	}
}

func serviceActions(cmd *cobra.Command, args []string) {
	action := args[0]
	runService(action)
}
