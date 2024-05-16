package main

import (
	"os"
	"log"

	"github.com/spf13/cobra"
	"github.com/kardianos/service"
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

	switch mode {
	case "install":
		initName := s.Platform()
		log.Println("Init 系统为:", initName)
		if err = s.Install(); err != nil {
			log.Fatal("安装服务时出错: ", err)
		} else {
			log.Println("服务安装成功！")
		}
		// 安装后重启
		if err = s.Restart(); err != nil {
			log.Fatal("重启服务时出错: ", err)
		}
	case "uninstall":
		s.Stop()
		if err = s.Uninstall(); err != nil {
			log.Fatal("卸载服务时出错: ", err)
		} else {
			log.Println("服务卸载成功！")
		}
	case "start":
		if err = s.Start(); err != nil {
			log.Fatal("启动服务时出错: ", err)
		}
	case "stop":
		if err = s.Stop(); err != nil {
			log.Fatal("停止服务时出错: ", err)
		}
	case "restart":
		if err = s.Restart(); err != nil {
			log.Fatal("重启服务时出错: ", err)
		}
	default:
		cmd.Help()
		os.Exit(1)
	}
}
