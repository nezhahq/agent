package util

import (
	"os"

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
