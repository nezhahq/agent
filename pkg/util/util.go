package util

import (
	"os"

	jsoniter "github.com/json-iterator/go"
)

var Json = jsoniter.ConfigCompatibleWithStandardLibrary

func IsWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}
