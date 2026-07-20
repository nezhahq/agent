//go:build !unix || aix

package fm

import (
	"fmt"
	"os"
)

func openDownloadFile(path string) (downloadFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("classify download file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, &UnsupportedDownloadFileError{Path: path, Mode: info.Mode()}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open download file: %w", err)
	}
	return file, nil
}
