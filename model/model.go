package model

import (
	"os"

	"github.com/spf13/viper"
	"sigs.k8s.io/yaml"
)

type AgentConfig struct {
	HardDrivePartitionAllowlist []string
	NICAllowlist                map[string]bool
	DNS                         []string
	GPU                         bool
	v                           *viper.Viper
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
