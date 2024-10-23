package commands

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/shirou/gopsutil/v4/disk"
	psnet "github.com/shirou/gopsutil/v4/net"

	"github.com/nezhahq/agent/model"
)

// 修改Agent要监控的网卡与硬盘分区
func EditAgentConfig(configPath string, agentConfig *model.AgentConfig) {
	agentConfig.Read(configPath)

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

	uuid, err := uuid.GenerateUUID()
	if err != nil {
		panic(err)
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
			Name: "uuid",
			Prompt: &survey.Input{
				Message: "输入 Agent UUID",
				Default: agentConfig.UUID,
				Suggest: func(_ string) []string {
					return []string{uuid}
				},
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
			Name: "debug",
			Prompt: &survey.Confirm{
				Message: "是否开启调试模式？",
				Default: false,
			},
		},
	}

	answers := struct {
		Nic         []string `mapstructure:"nic_allowlist" json:"nic_allowlist"`
		Disk        []string `mapstructure:"hard_drive_partition_allowlist" json:"hard_drive_partition_allowlist"`
		DNS         string   `mapstructure:"dns" json:"dns"`
		GPU         bool     `mapstructure:"gpu" json:"gpu"`
		Temperature bool     `mapstructure:"temperature" json:"temperature"`
		Debug       bool     `mapstructure:"debug" json:"debug"`
		UUID        string   `mapstructure:"uuid" json:"uuid"`
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
	agentConfig.Debug = answers.Debug
	agentConfig.UUID = answers.UUID

	if err = agentConfig.Save(); err != nil {
		panic(err)
	}

	fmt.Println("修改自定义配置成功，重启 Agent 后生效")
}
