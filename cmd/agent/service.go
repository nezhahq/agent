package main

import (
	"fmt"
	"os"

	"github.com/nezhahq/service"
	"github.com/spf13/cobra"
)

type AgentCliFlags struct {
	IsSpecified bool
	Flag        string
	Value       string
}

type program struct {
	exit    chan struct{}
	service service.Service
}

var serviceCmd = &cobra.Command{
	Use:    "service <install/uninstall/start/stop/restart>",
	Short:  "服务与自启动设置",
	Args:   cobra.ExactArgs(1),
	Run:    serviceActions,
	PreRun: servicePreRun,
}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	close(p.exit)
	if service.Interactive() {
		os.Exit(0)
	}
	return nil
}

func (p *program) run() {
	defer func() {
		if service.Interactive() {
			p.Stop(p.service)
		} else {
			p.service.Stop()
		}
	}()

	run()

	return
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
	var agentCliFlags []string

	flags := []AgentCliFlags{
		{agentCliParam.Server != "localhost:5555", "-s", agentCliParam.Server},
		{agentCliParam.ClientSecret != "", "-p", agentCliParam.ClientSecret},
		{agentCliParam.TLS, "--tls", ""},
		{agentCliParam.Debug, "-d", ""},
		{agentCliParam.ReportDelay != 1, "--report-delay", fmt.Sprint(agentCliParam.ReportDelay)},
		{agentCliParam.SkipConnectionCount, "--skip-conn", ""},
		{agentCliParam.SkipProcsCount, "--skip-procs", ""},
		{agentCliParam.DisableCommandExecute, "--disable-command-execute", ""},
		{agentCliParam.DisableAutoUpdate, "--disable-auto-update", ""},
		{agentCliParam.DisableForceUpdate, "--disable-force-update", ""},
		{agentCliParam.UseIPv6CountryCode, "--use-ipv6-countrycode", ""},
		{agentConfig.GPU, "--gpu", ""},
		{agentCliParam.IPReportPeriod != 30*60, "-u", fmt.Sprint(agentCliParam.IPReportPeriod)},
	}

	for _, f := range flags {
		if f.IsSpecified {
			if f.Value == "" {
				agentCliFlags = append(agentCliFlags, f.Flag)
			} else {
				agentCliFlags = append(agentCliFlags, f.Flag, f.Value)
			}
		}
	}

	action := args[0]
	runService(action, agentCliFlags)
}
