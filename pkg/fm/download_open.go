package fm

import (
	"fmt"
	"os"
)

type UnsupportedDownloadFileError struct {
	Path string
	Mode os.FileMode
}

func (e *UnsupportedDownloadFileError) Error() string {
	return fmt.Sprintf("download file type is unsupported on this platform: %s (%s)", e.Path, e.Mode.Type())
}
