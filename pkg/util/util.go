package util

import (
	"fmt"
	"os"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/nezhahq/service"
)

var (
	Json                  = jsoniter.ConfigCompatibleWithStandardLibrary
	Logger service.Logger = service.ConsoleLogger
)

func IsWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}

func Println(enabled bool, v ...interface{}) {
	if enabled {
		Logger.Infof("NEZHA@%s>> %v", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprint(v...))
	}
}
