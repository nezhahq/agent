package hostfs

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

const maxAtomicTempAttempts = 16

// DurabilityState describes whether an atomic replacement reached stable parent metadata.
type DurabilityState uint8

const (
	DurabilityNotCommitted DurabilityState = iota
	DurabilityConfirmed
	DurabilityUnknown
)

// AtomicReplaceResult identifies the commit boundary independently from durability reporting.
type AtomicReplaceResult struct {
	Committed  bool
	Durability DurabilityState
}

type atomicReplaceOperations struct {
	openFile        func(*os.Root, string, int, os.FileMode) (*os.File, error)
	writeFile       func(*os.File, []byte) error
	chmodFile       func(*os.File, os.FileMode) error
	syncFile        func(*os.File) error
	closeFile       func(*os.File) error
	revalidateFinal func(*Anchor) (FinalTargetType, error)
	beforeRename    func()
	rename          func(*os.Root, string, string) error
	closeTemp       func(*os.File) error
	cleanupTemp     func() error
	syncDirectory   func(*os.File) error
	temporaryName   func() (string, error)
}

func defaultAtomicReplaceOperations() atomicReplaceOperations {
	return atomicReplaceOperations{
		openFile:        (*os.Root).OpenFile,
		writeFile:       writeEntireFile,
		chmodFile:       (*os.File).Chmod,
		syncFile:        (*os.File).Sync,
		closeFile:       (*os.File).Close,
		revalidateFinal: (*Anchor).revalidateAtomicFinal,
		rename:          (*os.Root).Rename,
		closeTemp:       (*os.File).Close,
		cleanupTemp:     refuseAtomicTempCleanup,
		syncDirectory:   syncReplacementDirectory,
		temporaryName:   randomAtomicTempName,
	}
}

// AtomicReplace writes data to a private same-directory entry and commits with Root.Rename.
// Pre-commit failures retain the random entry because deleting it by name could remove a concurrent replacement.
func (anchor *Anchor) AtomicReplace(data []byte, mode os.FileMode) (result AtomicReplaceResult, resultErr error) {
	if len(anchor.missingParents) != 0 {
		return result, &PathError{Op: "atomic replace", Path: anchor.targetPath, Err: ErrImmediateParentMissing}
	}
	if mode.Perm() != mode {
		return result, &PathError{Op: "atomic replace", Path: anchor.targetPath, Err: ErrUnsupportedFileMode}
	}

	temporary, temporaryName, err := anchor.createAtomicTemp()
	if err != nil {
		return result, err
	}
	temporaryOpen := true
	temporaryOwned := true
	defer func() {
		if !temporaryOwned {
			return
		}
		cleanupErr := cleanupAtomicTemp(anchor.atomicOperations, temporary, temporaryOpen)
		if cleanupErr != nil {
			resultErr = errors.Join(resultErr, &PathError{
				Op:   "clean atomic temp",
				Path: anchor.targetPath,
				Err:  cleanupErr,
			})
		}
	}()

	if err := anchor.atomicOperations.writeFile(temporary, data); err != nil {
		return result, &PathError{Op: "write atomic temp", Path: anchor.targetPath, Err: err}
	}
	if err := anchor.atomicOperations.chmodFile(temporary, mode); err != nil {
		return result, &PathError{Op: "chmod atomic temp", Path: anchor.targetPath, Err: err}
	}
	if err := anchor.atomicOperations.syncFile(temporary); err != nil {
		return result, &PathError{Op: "sync atomic temp", Path: anchor.targetPath, Err: err}
	}
	if err := anchor.atomicOperations.closeFile(temporary); err != nil {
		return result, &PathError{Op: "close atomic temp", Path: anchor.targetPath, Err: err}
	}
	// Keep cleanup ownership until closeFile succeeds so a failed close can be retried.
	temporaryOpen = false

	targetType, err := anchor.atomicOperations.revalidateFinal(anchor)
	if err != nil {
		return result, err
	}
	if targetType != FinalTargetAbsent && targetType != FinalTargetRegular {
		return result, anchor.typeError(FinalTargetRegular, targetType)
	}
	if anchor.atomicOperations.beforeRename != nil {
		anchor.atomicOperations.beforeRename()
	}
	if err := anchor.atomicOperations.rename(anchor.root, temporaryName, anchor.finalName); err != nil {
		return result, &PathError{Op: "rename atomic temp", Path: anchor.targetPath, Err: err}
	}

	temporaryOwned = false
	result = AtomicReplaceResult{Committed: true, Durability: DurabilityConfirmed}
	if err := anchor.atomicOperations.syncDirectory(anchor.nativeDirectory); err != nil {
		result.Durability = DurabilityUnknown
		return result, &CommittedDurabilityUnknown{Path: anchor.targetPath, Err: err}
	}
	return result, nil
}

func (anchor *Anchor) createAtomicTemp() (*os.File, string, error) {
	for range maxAtomicTempAttempts {
		name, err := anchor.atomicOperations.temporaryName()
		if err != nil {
			return nil, "", &PathError{Op: "name atomic temp", Path: anchor.targetPath, Err: err}
		}
		file, err := anchor.atomicOperations.openFile(anchor.root, name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", &PathError{Op: "create atomic temp", Path: anchor.targetPath, Err: err}
		}
	}
	return nil, "", &AtomicTempCollisionExhaustedError{Path: anchor.targetPath, Attempts: maxAtomicTempAttempts}
}

func cleanupAtomicTemp(operations atomicReplaceOperations, file *os.File, open bool) error {
	var closeErr error
	if open {
		closeErr = operations.closeTemp(file)
	}
	// Name-based deletion is forbidden: a concurrent parent mutation can substitute another entry at name.
	return errors.Join(closeErr, operations.cleanupTemp())
}

func refuseAtomicTempCleanup() error {
	return ErrAtomicTempCleanupRefused
}

func writeEntireFile(file *os.File, data []byte) error {
	remaining := data
	for len(remaining) != 0 {
		written, err := file.Write(remaining)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		remaining = remaining[written:]
	}
	return nil
}

func randomAtomicTempName() (string, error) {
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return atomicTempPrefix() + hex.EncodeToString(random), nil
}

func atomicTempPrefix() string {
	return ".hostfs-atomic-"
}
