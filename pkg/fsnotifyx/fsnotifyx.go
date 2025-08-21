package fsnotifyx

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

const defaultTimeout = time.Minute * 5

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					cancel()
					return
				}
				if event.Name == filePath && event.Has(fsnotify.Remove) {
					logFunc("fsnotifyx: file %s removed, exiting...", filePath)
					cancel()
					return
				}
			case werr := <-watcher.Errors:
				logFunc("fsnotifyx: %v", werr)
			}
		}
	}()

	timeout := time.NewTimer(defaultTimeout)
	for {
		select {
		case <-timeout.C:
			return errors.New("fsnotifyx: timeout")
		case <-ctx.Done():
			return nil
		}
	}
}
