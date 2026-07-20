package hostfs

import (
	"errors"
	"fmt"
	"os"
	"time"
)

var (
	ErrPathRequired                 = errors.New("hostfs: path required")
	ErrAbsolutePathRequired         = errors.New("hostfs: absolute path required")
	ErrFilesystemRoot               = errors.New("hostfs: requested target is a filesystem root")
	ErrFinalNameRequired            = errors.New("hostfs: final path name required")
	ErrAlternateDataStream          = errors.New("hostfs: alternate data stream paths are not supported")
	ErrAncestorNotDirectory         = errors.New("hostfs: existing ancestor is not a directory")
	ErrHandleMismatch               = errors.New("hostfs: root and native directory handles do not match")
	ErrUnsupportedPlatform          = errors.New("hostfs: native directory handles are unsupported on this platform")
	ErrFinalTargetChanged           = errors.New("hostfs: final target changed during classification")
	ErrImmediateParentMissing       = errors.New("hostfs: immediate parent does not exist")
	ErrUnsupportedFileMode          = errors.New("hostfs: unsupported file mode")
	ErrAtomicTempCollisionExhausted = errors.New("hostfs: atomic temporary name collisions exhausted")
	ErrDirectorySyncUnsupported     = errors.New("hostfs: directory sync is unsupported on this platform")
	ErrCommittedDurabilityUnknown   = errors.New("hostfs: replacement committed but durability is unknown")
	ErrIfMatchSHA256Missing         = errors.New("if_match precondition failed: file does not exist")
	ErrIfMatchSHA256Mismatch        = errors.New("if_match precondition failed: sha256 mismatch")
	ErrAtomicTempNotSealed          = errors.New("hostfs: atomic temporary file is not sealed")
	ErrAtomicTempSealed             = errors.New("hostfs: atomic temporary file is already sealed")
	ErrAtomicTempCleanupRefused     = errors.New("hostfs: atomic temporary cleanup refused")
	ErrFileChangedDuringHash        = errors.New("hostfs: file changed during hash")
)

// FileChangeReason identifies observable metadata that changed while hashing.
type FileChangeReason string

const (
	FileChangeSize             FileChangeReason = "size"
	FileChangeBytesRead        FileChangeReason = "bytes-read"
	FileChangeModificationTime FileChangeReason = "modification-time"
	FileChangeIdentity         FileChangeReason = "identity"
)

// FileChangedDuringHashError reports an observable change on one opened file handle.
type FileChangedDuringHashError struct {
	Path           string
	InitialSize    int64
	FinalSize      int64
	BytesRead      int64
	InitialModTime time.Time
	FinalModTime   time.Time
	Reasons        []FileChangeReason
}

func (err *FileChangedDuringHashError) Error() string {
	return fmt.Sprintf("hostfs hash %q: %v (%v)", err.Path, ErrFileChangedDuringHash, err.Reasons)
}

func (err *FileChangedDuringHashError) Is(target error) bool {
	return target == ErrFileChangedDuringHash
}

// PathError identifies the host path and anchoring operation that failed.
type PathError struct {
	Op   string
	Path string
	Err  error
}

func (err *PathError) Error() string {
	return fmt.Sprintf("hostfs %s %q: %v", err.Op, err.Path, err.Err)
}

func (err *PathError) Unwrap() error {
	return err.Err
}

// FinalTargetTypeError reports that an anchored final target has the wrong type.
type FinalTargetTypeError struct {
	Path     string
	Expected FinalTargetType
	Actual   FinalTargetType
}

func (err *FinalTargetTypeError) Error() string {
	return fmt.Sprintf("hostfs final target %q has type %s, want %s", err.Path, err.Actual, err.Expected)
}

// AtomicTempCollisionExhaustedError reports bounded exclusive-create collisions.
type AtomicTempCollisionExhaustedError struct {
	Path     string
	Attempts int
}

func (err *AtomicTempCollisionExhaustedError) Error() string {
	return fmt.Sprintf("hostfs atomic temporary creation for %q exhausted %d collisions", err.Path, err.Attempts)
}

func (err *AtomicTempCollisionExhaustedError) Unwrap() error {
	return os.ErrExist
}

func (err *AtomicTempCollisionExhaustedError) Is(target error) bool {
	return target == ErrAtomicTempCollisionExhausted
}

// DirectorySyncUnsupportedError identifies a platform without defined directory-sync semantics.
type DirectorySyncUnsupportedError struct {
	Platform string
}

func (err *DirectorySyncUnsupportedError) Error() string {
	return fmt.Sprintf("hostfs directory sync is unsupported on %s", err.Platform)
}

func (err *DirectorySyncUnsupportedError) Is(target error) bool {
	return target == ErrDirectorySyncUnsupported
}

// CommittedDurabilityUnknown reports a committed replacement whose parent sync failed.
type CommittedDurabilityUnknown struct {
	Path string
	Err  error
}

func (err *CommittedDurabilityUnknown) Error() string {
	return fmt.Sprintf("hostfs atomic replace %q committed but durability is unknown: %v", err.Path, err.Err)
}

func (err *CommittedDurabilityUnknown) Unwrap() error {
	return err.Err
}

func (err *CommittedDurabilityUnknown) Is(target error) bool {
	return target == ErrCommittedDurabilityUnknown
}
