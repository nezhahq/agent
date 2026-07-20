package hostfs

import (
	"errors"
	"io"
	"os"
	"sync"
)

// PendingAtomicReplace owns a same-parent temporary entry until commit or cleanup.
type PendingAtomicReplace struct {
	anchor    *Anchor
	file      *os.File
	name      string
	mode      os.FileMode
	sealed    bool
	committed bool
	closeOnce sync.Once
	closeErr  error
}

// BeginAtomicReplace creates a private temporary entry without acquiring a path lock.
func (anchor *Anchor) BeginAtomicReplace(mode os.FileMode) (*PendingAtomicReplace, error) {
	if len(anchor.missingParents) != 0 {
		return nil, &PathError{Op: "begin atomic replace", Path: anchor.targetPath, Err: ErrImmediateParentMissing}
	}
	if mode.Perm() != mode {
		return nil, &PathError{Op: "begin atomic replace", Path: anchor.targetPath, Err: ErrUnsupportedFileMode}
	}
	file, name, err := anchor.createAtomicTemp()
	if err != nil {
		return nil, err
	}
	return &PendingAtomicReplace{anchor: anchor, file: file, name: name, mode: mode}, nil
}

// Write appends bytes to the private temporary entry before it is sealed.
func (pending *PendingAtomicReplace) Write(data []byte) (int, error) {
	if pending.sealed {
		return 0, ErrAtomicTempSealed
	}
	return pending.file.Write(data)
}

// Seal applies mode, syncs data, and closes the temporary file before commit.
func (pending *PendingAtomicReplace) Seal() error {
	if pending.sealed {
		return ErrAtomicTempSealed
	}
	operations := pending.anchor.atomicOperations
	if err := operations.chmodFile(pending.file, pending.mode); err != nil {
		return &PathError{Op: "chmod atomic temp", Path: pending.anchor.targetPath, Err: err}
	}
	if err := operations.syncFile(pending.file); err != nil {
		return &PathError{Op: "sync atomic temp", Path: pending.anchor.targetPath, Err: err}
	}
	if err := operations.closeFile(pending.file); err != nil {
		return &PathError{Op: "close atomic temp", Path: pending.anchor.targetPath, Err: err}
	}
	pending.sealed = true
	return nil
}

// CommitIfMatch revalidates type and optional digest immediately before Root.Rename.
func (pending *PendingAtomicReplace) CommitIfMatch(expectedSHA256 string) (AtomicReplaceResult, error) {
	result := AtomicReplaceResult{}
	if !pending.sealed {
		return result, ErrAtomicTempNotSealed
	}
	targetType, err := pending.anchor.ClassifyFinal()
	if err != nil {
		return result, err
	}
	if targetType != FinalTargetAbsent && targetType != FinalTargetRegular {
		return result, pending.anchor.typeError(FinalTargetRegular, targetType)
	}
	if expectedSHA256 != "" {
		if targetType == FinalTargetAbsent {
			return result, ErrIfMatchSHA256Missing
		}
		currentSHA256, hashErr := pending.anchor.SHA256()
		if hashErr != nil {
			return result, hashErr
		}
		if currentSHA256 != expectedSHA256 {
			return result, ErrIfMatchSHA256Mismatch
		}
	}
	operations := pending.anchor.atomicOperations
	if operations.beforeRename != nil {
		operations.beforeRename()
	}
	if err := operations.rename(pending.anchor.root, pending.name, pending.anchor.finalName); err != nil {
		return result, &PathError{Op: "rename atomic temp", Path: pending.anchor.targetPath, Err: err}
	}
	pending.committed = true
	result = AtomicReplaceResult{Committed: true, Durability: DurabilityConfirmed}
	if err := operations.syncDirectory(pending.anchor.nativeDirectory); err != nil {
		result.Durability = DurabilityUnknown
		return result, &CommittedDurabilityUnknown{Path: pending.anchor.targetPath, Err: err}
	}
	return result, nil
}

// Close releases an uncommitted temporary handle and safely refuses mutable-name cleanup.
// It is safe to call repeatedly and returns the first cleanup result.
func (pending *PendingAtomicReplace) Close() error {
	if pending == nil {
		return nil
	}
	pending.closeOnce.Do(func() {
		if pending.committed {
			return
		}
		var closeErr error
		if !pending.sealed {
			closeErr = pending.anchor.atomicOperations.closeTemp(pending.file)
		}
		cleanupErr := pending.anchor.atomicOperations.cleanupTemp()
		pending.closeErr = errors.Join(closeErr, cleanupErr)
	})
	return pending.closeErr
}

var _ io.Writer = (*PendingAtomicReplace)(nil)
