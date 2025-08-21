package fsnotifyx

import (
	"path/filepath"

	"github.com/fsnotify/fsnotify"
)

func ExitOnDeleteFile(logFunc func(format string, v ...interface{}), filePath string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	err = watcher.Add(filepath.Dir(filePath))
	if err != nil {
		return err
	}

	exitChan := make(chan struct{})
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Name == filePath && event.Has(fsnotify.Remove) {
					logFunc("fsnotifyx: file %s removed, exiting...", filePath)
					select {
					case <-exitChan:
					default:
						close(exitChan)
					}
					return
				}
			case err := <-watcher.Errors:
				logFunc("fsnotifyx: %v", err)
			}
		}
	}()

	<-exitChan
	return nil
}
