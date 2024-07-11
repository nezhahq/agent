package main

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/shirou/gopsutil/v4/disk"
	psnet "github.com/shirou/gopsutil/v4/net"
	"github.com/spf13/cobra"
)

var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "修改要监控的网卡/分区名单，修改自定义 DNS",
	Run:   editAgentConfig,
	Args:  cobra.NoArgs,
}

func init() {
	agentCmd.AddCommand(editCmd)
}

// 修改Agent要监控的网卡与硬盘分区
func editAgentConfig(cmd *cobra.Command, args []string) {
	nc, err := psnet.IOCounters(true)
	if err != nil {
		panic(err)
	}
	var nicAllowlistOptions []string
	for _, v := range nc {
		nicAllowlistOptions = append(nicAllowlistOptions, v.Name)
	}

	var diskAllowlistOptions []string
	diskList, err := disk.Partitions(false)
	if err != nil {
		panic(err)
	}
	for _, p := range diskList {
		diskAllowlistOptions = append(diskAllowlistOptions, fmt.Sprintf("%s\t%s\t%s", p.Mountpoint, p.Fstype, p.Device))
	}

	var qs = []*survey.Question{
		{
			Name: "nic",
			Prompt: &survey.MultiSelect{
				Message: "选择要监控的网卡",
				Options: nicAllowlistOptions,
			},
		},
		{
			Name: "disk",
			Prompt: &survey.MultiSelect{
				Message: "选择要监控的硬盘分区",
				Options: diskAllowlistOptions,
			},
		},
		{
			Name: "dns",
			Prompt: &survey.Input{
				Message: "自定义 DNS，可输入空格跳过，如 1.1.1.1:53,1.0.0.1:53",
				Default: strings.Join(agentConfig.DNS, ","),
			},
		},
		{
			Name: "gpu",
			Prompt: &survey.Confirm{
				Message: "是否启用 GPU 监控？",
				Default: false,
			},
		},
		{
			Name: "temperature",
			Prompt: &survey.Confirm{
				Message: "是否启用温度监控？",
				Default: false,
			},
		},
		{
			Name: "slient",
			Prompt: &survey.Confirm{
				Message: "是否禁用日志输出？",
				Default: false,
			},
		},
	}

	answers := struct {
		Nic         []string
		Disk        []string
		DNS         string
		GPU         bool
		Temperature bool
		Silent      bool
	}{}

	err = survey.Ask(qs, &answers, survey.WithValidator(survey.Required))
	if err != nil {
		fmt.Println("选择错误", err.Error())
		return
	}

	agentConfig.HardDrivePartitionAllowlist = []string{}
	for _, v := range answers.Disk {
		agentConfig.HardDrivePartitionAllowlist = append(agentConfig.HardDrivePartitionAllowlist, strings.Split(v, "\t")[0])
	}

	agentConfig.NICAllowlist = make(map[string]bool)
	for _, v := range answers.Nic {
		agentConfig.NICAllowlist[v] = true
	}

	dnsServers := strings.TrimSpace(answers.DNS)

	if dnsServers != "" {
		agentConfig.DNS = strings.Split(dnsServers, ",")
		for _, s := range agentConfig.DNS {
			host, _, err := net.SplitHostPort(s)
			if err == nil {
				if net.ParseIP(host) == nil {
					err = errors.New("格式错误")
				}
			}
			if err != nil {
				panic(fmt.Sprintf("自定义 DNS 格式错误：%s %v", s, err))
			}
		}
	} else {
		agentConfig.DNS = []string{}
	}

	agentConfig.GPU = answers.GPU
	agentConfig.Temperature = answers.Temperature
	agentConfig.Silent = answers.Silent

	if err = agentConfig.Save(); err != nil {
		panic(err)
	}

	fmt.Println("修改自定义配置成功，重启 Agent 后生效")
}
