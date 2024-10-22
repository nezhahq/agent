package model

import (
	"os"

	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"
)

type AgentConfig struct {
	Debug bool `mapstructure:"debug"`

	Server       string `mapstructure:"server"`        // 服务器地址
	ClientSecret string `mapstructure:"client_secret"` // 客户端密钥
	UUID         string `mapstructure:"uuid"`

	HardDrivePartitionAllowlist []string        `mapstructure:"hard_drive_partition_allowlist"`
	NICAllowlist                map[string]bool `mapstructure:"nic_allowlist"`
	DNS                         []string        `mapstructure:"dns"`
	GPU                         bool            `mapstructure:"gpu"`                     // 是否检查GPU
	Temperature                 bool            `mapstructure:"temperature"`             // 是否检查温度
	SkipConnectionCount         bool            `mapstructure:"skip_connection_count"`   // 跳过连接数检查
	SkipProcsCount              bool            `mapstructure:"skip_procs_count"`        // 跳过进程数量检查
	DisableAutoUpdate           bool            `mapstructure:"disable_auto_update"`     // 关闭自动更新
	DisableForceUpdate          bool            `mapstructure:"disable_force_update"`    // 关闭强制更新
	DisableCommandExecute       bool            `mapstructure:"disable_command_execute"` // 关闭命令执行
	ReportDelay                 int             `mapstructure:"report_delay"`            // 报告间隔
	TLS                         bool            `mapstructure:"tls"`                     // 是否使用TLS加密传输至服务端
	InsecureTLS                 bool            `mapstructure:"insecure_tls"`            // 是否禁用证书检查
	UseIPv6CountryCode          bool            `mapstructure:"use_i_pv_6_country_code"` // 默认优先展示IPv6旗帜
	UseGiteeToUpgrade           bool            `mapstructure:"use_gitee_to_upgrade"`    // 强制从Gitee获取更新
	IPReportPeriod              uint32          `mapstructure:"ip_report_period"`        // IP上报周期

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
