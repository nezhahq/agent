package util

import (
	"fmt"
	"os"
	"runtime"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/nezhahq/service"
)

var (
	Json   = jsoniter.ConfigCompatibleWithStandardLibrary
	Logger service.Logger
)

func IsWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}

func Println(enabled bool, v ...interface{}) {
	if enabled {
		if runtime.GOOS != "darwin" {
			Logger.Infof("NEZHA@%s>> %v", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprint(v...))
		} else {
			fmt.Printf("NEZHA@%s>> ", time.Now().Format("2006-01-02 15:04:05"))
			fmt.Println(v...)
		}
	}
}
