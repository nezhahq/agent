package model

import (
	"os"

	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"
)

type AgentConfig struct {
	Debug bool `json:"debug,omitempty"`

	Server       string `json:"server,omitempty"`        // 服务器地址
	ClientSecret string `json:"client_secret,omitempty"` // 客户端密钥
	UUID         string `json:"uuid,omitempty"`

	HardDrivePartitionAllowlist []string        `json:"hard_drive_partition_allowlist,omitempty"`
	NICAllowlist                map[string]bool `json:"nic_allowlist,omitempty"`
	DNS                         []string        `json:"dns,omitempty"`
	GPU                         bool            `json:"gpu,omitempty"`                     // 是否检查GPU
	Temperature                 bool            `json:"temperature,omitempty"`             // 是否检查温度
	SkipConnectionCount         bool            `json:"skip_connection_count,omitempty"`   // 跳过连接数检查
	SkipProcsCount              bool            `json:"skip_procs_count,omitempty"`        // 跳过进程数量检查
	DisableAutoUpdate           bool            `json:"disable_auto_update,omitempty"`     // 关闭自动更新
	DisableForceUpdate          bool            `json:"disable_force_update,omitempty"`    // 关闭强制更新
	DisableCommandExecute       bool            `json:"disable_command_execute,omitempty"` // 关闭命令执行
	ReportDelay                 int             `json:"report_delay,omitempty"`            // 报告间隔
	TLS                         bool            `json:"tls,omitempty"`                     // 是否使用TLS加密传输至服务端
	InsecureTLS                 bool            `json:"insecure_tls,omitempty"`            // 是否禁用证书检查
	UseIPv6CountryCode          bool            `json:"use_i_pv_6_country_code,omitempty"` // 默认优先展示IPv6旗帜
	UseGiteeToUpgrade           bool            `json:"use_gitee_to_upgrade,omitempty"`    // 强制从Gitee获取更新
	IPReportPeriod              uint32          `json:"ip_report_period,omitempty"`        // IP上报周期

	v *viper.Viper
}

// Read 从给定的文件目录加载配置文件
func (c *AgentConfig) Read(path string) error {
	c.v = viper.New()
	c.v.SetConfigFile(path)
	err := c.v.ReadInConfig()
	if err != nil {
		return err
	}
	err = c.v.Unmarshal(c)
	if err != nil {
		return err
	}
	return nil
}

func (c *AgentConfig) Save() error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(c.v.ConfigFileUsed(), data, os.ModePerm)
}
