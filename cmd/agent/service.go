package main

import (
	"os"
	"log"

	"github.com/spf13/cobra"
	"github.com/nezhahq/service"
)

type program struct {
	exit    chan struct{}
	service service.Service
}

var serviceCmd = &cobra.Command{
	Use:    "service <install/uninstall/start/stop/restart>",
	Short:  "服务与自启动设置",
	Args:   cobra.ExactArgs(1),
	Run:    runService,
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

func (p *program) Start(s service.Service) error {
	go p.run()
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

func (p *program) Stop(s service.Service) error {
	close(p.exit)
	if service.Interactive() {
		os.Exit(0)
	}
	return nil
}

func runService(cmd *cobra.Command, args []string) {
	var tlsoption string

	mode := args[0]
	dir, err := os.Getwd()
    if err != nil {
        println("获取当前工作目录时出错: ", err)
        return
    }

	if agentCliParam.TLS {
		tlsoption = "--tls"
	}

	svcConfig := &service.Config{
		Name:             "nezha-agent",
		DisplayName:      "Nezha Agent",
		Description:      "哪吒探针监控端",
		Arguments:   []string{
			"-s", agentCliParam.Server,
			"-p", agentCliParam.ClientSecret,
			tlsoption,
		},
		WorkingDirectory: dir,
	}

	prg := &program{
		exit: make(chan struct{}),
	}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal("创建服务时出错: ", err)
	}

	if mode == "install" {
		initName := s.Platform()
		log.Println("Init system is:", initName)
	}

	err = service.Control(s, mode)
	if err != nil {
		log.Fatal(err)
	}
}
