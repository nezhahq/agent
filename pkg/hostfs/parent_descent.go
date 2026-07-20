package hostfs

import (
	"errors"
	"os"
	"path/filepath"
)

func defaultDescentOperations() descentOperations {
	return descentOperations{
		mkdir:                (*os.Root).Mkdir,
		openRoot:             (*os.Root).OpenRoot,
		openNativeDirectory:  openNativeChildDirectory,
		sameFile:             os.SameFile,
		syncDirectory:        syncCreatedParentDirectory,
		closeRoot:            closeRoot,
		closeNativeDirectory: closeFile,
	}
}

// EnsureParent anchors the requested target's immediate parent.
func (anchor *Anchor) EnsureParent(create bool, mode os.FileMode) error {
	if len(anchor.missingParents) == 0 {
		return nil
	}
	if !create {
		return &PathError{Op: "ensure parent", Path: anchor.targetPath, Err: ErrImmediateParentMissing}
	}
	if mode.Perm() != mode {
		return &PathError{Op: "ensure parent", Path: anchor.targetPath, Err: ErrUnsupportedFileMode}
	}
	for len(anchor.missingParents) != 0 {
		component := anchor.missingParents[0]
		if err := anchor.descentOperations.mkdir(anchor.root, component, mode); err != nil && !errors.Is(err, os.ErrExist) {
			return &PathError{Op: "create parent", Path: anchor.targetPath, Err: err}
		}
		childRoot, childNative, err := anchor.openMatchingChildPair(component)
		if err != nil {
			return err
		}
		if err := anchor.descentOperations.syncDirectory(anchor.nativeDirectory); err != nil {
			cleanupErr := anchor.closeCandidatePair(childRoot, childNative)
			return &PathError{Op: "sync parent directory", Path: anchor.targetPath, Err: errors.Join(err, cleanupErr)}
		}
		previousRoot := anchor.root
		previousNative := anchor.nativeDirectory
		anchor.root = childRoot
		anchor.nativeDirectory = childNative
		anchor.rootOwned = true
		anchor.nativeOwned = true
		anchor.ancestorPath = filepath.Join(anchor.ancestorPath, component)
		anchor.missingParents = anchor.missingParents[1:]
		rootCloseErr := anchor.descentOperations.closeRoot(previousRoot)
		if rootCloseErr != nil {
			anchor.retiredRoots = append(anchor.retiredRoots, previousRoot)
		}
		nativeCloseErr := anchor.descentOperations.closeNativeDirectory(previousNative)
		if nativeCloseErr != nil {
			anchor.retiredDirectories = append(anchor.retiredDirectories, previousNative)
		}
		if err := errors.Join(rootCloseErr, nativeCloseErr); err != nil {
			return &PathError{Op: "close parent handles", Path: anchor.targetPath, Err: err}
		}
	}
	return nil
}

func (anchor *Anchor) openMatchingChildPair(component string) (*os.Root, *os.File, error) {
	for range maxPairAttempts {
		childNative, err := anchor.descentOperations.openNativeDirectory(anchor.nativeDirectory, component)
		if err != nil {
			return nil, nil, &PathError{Op: "open child native directory", Path: anchor.targetPath, Err: errors.Join(err, anchor.closeCandidatePair(nil, childNative))}
		}
		childRoot, err := anchor.descentOperations.openRoot(anchor.root, component)
		if err != nil {
			return nil, nil, &PathError{Op: "open child root", Path: anchor.targetPath, Err: errors.Join(err, anchor.closeCandidatePair(childRoot, childNative))}
		}
		rootInfo, rootStatErr := childRoot.Stat(".")
		nativeInfo, nativeStatErr := childNative.Stat()
		if rootStatErr == nil && nativeStatErr == nil && anchor.descentOperations.sameFile(rootInfo, nativeInfo) {
			return childRoot, childNative, nil
		}
		closeErr := anchor.closeCandidatePair(childRoot, childNative)
		if rootStatErr != nil || nativeStatErr != nil || closeErr != nil {
			return nil, nil, &PathError{Op: "verify child handles", Path: anchor.targetPath, Err: errors.Join(rootStatErr, nativeStatErr, closeErr)}
		}
	}
	return nil, nil, &PathError{Op: "verify child handles", Path: anchor.targetPath, Err: ErrHandleMismatch}
}

func (anchor *Anchor) closeCandidatePair(root *os.Root, nativeDirectory *os.File) error {
	rootErr := anchor.descentOperations.closeRoot(root)
	if rootErr != nil && root != nil {
		anchor.retiredRoots = append(anchor.retiredRoots, root)
	}
	nativeErr := anchor.descentOperations.closeNativeDirectory(nativeDirectory)
	if nativeErr != nil && nativeDirectory != nil {
		anchor.retiredDirectories = append(anchor.retiredDirectories, nativeDirectory)
	}
	return errors.Join(rootErr, nativeErr)
}
