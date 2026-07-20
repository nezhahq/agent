package hostfs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

func defaultHashOperations() hashOperations {
	return hashOperations{
		stat:     (*os.File).Stat,
		copy:     func(destination io.Writer, source *os.File) (int64, error) { return io.Copy(destination, source) },
		sameFile: os.SameFile,
	}
}

// HashRegular hashes one no-follow regular handle and rejects observable concurrent changes.
// Same-size writes that preserve identity and modification time are not observable and may be accepted.
func (anchor *Anchor) HashRegular() (digest string, resultErr error) {
	file, err := anchor.OpenRegular()
	if err != nil {
		return "", err
	}
	defer func() {
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, &PathError{Op: "close hashed final", Path: anchor.targetPath, Err: err})
		}
	}()
	initial, err := anchor.hashOperations.stat(file)
	if err != nil {
		return "", &PathError{Op: "stat final before hash", Path: anchor.targetPath, Err: err}
	}
	hash := sha256.New()
	bytesRead, err := anchor.hashOperations.copy(hash, file)
	if err != nil {
		return "", &PathError{Op: "hash final", Path: anchor.targetPath, Err: err}
	}
	final, err := anchor.hashOperations.stat(file)
	if err != nil {
		return "", &PathError{Op: "stat final after hash", Path: anchor.targetPath, Err: err}
	}
	reasons := observableHashChangeReasons(initial, final, bytesRead, anchor.hashOperations.sameFile)
	if len(reasons) != 0 {
		return "", &FileChangedDuringHashError{
			Path:           anchor.targetPath,
			InitialSize:    initial.Size(),
			FinalSize:      final.Size(),
			BytesRead:      bytesRead,
			InitialModTime: initial.ModTime(),
			FinalModTime:   final.ModTime(),
			Reasons:        reasons,
		}
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// SHA256 preserves the existing digest API while using HashRegular change detection.
func (anchor *Anchor) SHA256() (string, error) {
	return anchor.HashRegular()
}

func observableHashChangeReasons(
	initial os.FileInfo,
	final os.FileInfo,
	bytesRead int64,
	sameFile func(os.FileInfo, os.FileInfo) bool,
) []FileChangeReason {
	reasons := make([]FileChangeReason, 0, 4)
	if initial.Size() != final.Size() {
		reasons = append(reasons, FileChangeSize)
	}
	if bytesRead != initial.Size() {
		reasons = append(reasons, FileChangeBytesRead)
	}
	if !initial.ModTime().Equal(final.ModTime()) {
		reasons = append(reasons, FileChangeModificationTime)
	}
	if !sameFile(initial, final) {
		reasons = append(reasons, FileChangeIdentity)
	}
	return reasons
}

// SyncDirectory flushes the retained parent directory handle where supported.
func (anchor *Anchor) SyncDirectory() error {
	if err := anchor.atomicOperations.syncDirectory(anchor.nativeDirectory); err != nil {
		return &PathError{Op: "sync parent directory", Path: anchor.targetPath, Err: err}
	}
	return nil
}
