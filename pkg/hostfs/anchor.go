package hostfs

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const maxPairAttempts = 4

type anchorOperations struct {
	openRoot            func(string) (*os.Root, error)
	openNativeDirectory func(string) (*os.File, error)
	sameFile            func(os.FileInfo, os.FileInfo) bool
}

type descentOperations struct {
	mkdir                func(*os.Root, string, os.FileMode) error
	openRoot             func(*os.Root, string) (*os.Root, error)
	openNativeDirectory  func(*os.File, string) (*os.File, error)
	sameFile             func(os.FileInfo, os.FileInfo) bool
	syncDirectory        func(*os.File) error
	closeRoot            func(*os.Root) error
	closeNativeDirectory func(*os.File) error
}

type hashOperations struct {
	stat     func(*os.File) (os.FileInfo, error)
	copy     func(io.Writer, *os.File) (int64, error)
	sameFile func(os.FileInfo, os.FileInfo) bool
}

// Anchor retains two handles to one resolved existing parent directory.
type Anchor struct {
	targetPath         string
	ancestorPath       string
	missingParents     []string
	finalName          string
	root               *os.Root
	nativeDirectory    *os.File
	rootOwned          bool
	nativeOwned        bool
	retiredRoots       []*os.Root
	retiredDirectories []*os.File
	descentOperations  descentOperations
	hashOperations     hashOperations
	finalOperations    finalTargetOperations
	atomicOperations   atomicReplaceOperations
}

// New resolves target's existing parent path and anchors that directory.
func New(target string) (*Anchor, error) {
	return newWithOperations(target, defaultAnchorOperations())
}

func newWithOperations(target string, operations anchorOperations) (*Anchor, error) {
	cleanTarget, err := cleanTargetPath(target)
	if err != nil {
		return nil, err
	}
	ancestorPath, missingParents, finalName, err := resolveParent(cleanTarget)
	if err != nil {
		return nil, err
	}
	root, nativeDirectory, err := openMatchingPair(ancestorPath, operations)
	if err != nil {
		return nil, err
	}
	return &Anchor{
		targetPath:        cleanTarget,
		ancestorPath:      ancestorPath,
		missingParents:    missingParents,
		finalName:         finalName,
		root:              root,
		nativeDirectory:   nativeDirectory,
		rootOwned:         true,
		nativeOwned:       true,
		descentOperations: defaultDescentOperations(),
		hashOperations:    defaultHashOperations(),
		finalOperations:   defaultFinalTargetOperations(),
		atomicOperations:  defaultAtomicReplaceOperations(),
	}, nil
}

func defaultAnchorOperations() anchorOperations {
	return anchorOperations{
		openRoot:            os.OpenRoot,
		openNativeDirectory: openNativeDirectory,
		sameFile:            os.SameFile,
	}
}

func cleanTargetPath(target string) (string, error) {
	if target == "" {
		return "", &PathError{Op: "parse", Path: target, Err: ErrPathRequired}
	}
	if hasWindowsADSSuffix(target) {
		return "", &PathError{Op: "parse", Path: target, Err: ErrAlternateDataStream}
	}
	cleanTarget := filepath.Clean(target)
	if !filepath.IsAbs(cleanTarget) {
		return "", &PathError{Op: "parse", Path: target, Err: ErrAbsolutePathRequired}
	}
	if filepath.Dir(cleanTarget) == cleanTarget {
		return "", &PathError{Op: "parse", Path: target, Err: ErrFilesystemRoot}
	}
	if os.IsPathSeparator(target[len(target)-1]) {
		return "", &PathError{Op: "parse", Path: target, Err: ErrFinalNameRequired}
	}
	finalName := filepath.Base(cleanTarget)
	if finalName == "" || finalName == "." || finalName == string(filepath.Separator) {
		return "", &PathError{Op: "parse", Path: target, Err: ErrFinalNameRequired}
	}
	return cleanTarget, nil
}

func resolveParent(cleanTarget string) (string, []string, string, error) {
	finalName := filepath.Base(cleanTarget)
	candidate := filepath.Dir(cleanTarget)
	missingParents := make([]string, 0)
	for {
		info, err := os.Stat(candidate)
		if err == nil {
			if !info.IsDir() {
				return "", nil, "", &PathError{Op: "resolve parent", Path: candidate, Err: ErrAncestorNotDirectory}
			}
			return candidate, missingParents, finalName, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", nil, "", &PathError{Op: "resolve parent", Path: candidate, Err: err}
		}
		parent := filepath.Dir(candidate)
		if parent == candidate {
			return "", nil, "", &PathError{Op: "resolve parent", Path: candidate, Err: err}
		}
		missingParents = append([]string{filepath.Base(candidate)}, missingParents...)
		candidate = parent
	}
}

func openMatchingPair(path string, operations anchorOperations) (*os.Root, *os.File, error) {
	for range maxPairAttempts {
		root, err := operations.openRoot(path)
		if err != nil {
			return nil, nil, &PathError{Op: "open root", Path: path, Err: errors.Join(err, closeRoot(root))}
		}
		nativeDirectory, err := operations.openNativeDirectory(path)
		if err != nil {
			return nil, nil, &PathError{Op: "open native directory", Path: path, Err: errors.Join(err, closeRoot(root), closeFile(nativeDirectory))}
		}
		rootInfo, rootStatErr := root.Stat(".")
		nativeInfo, nativeStatErr := nativeDirectory.Stat()
		if rootStatErr == nil && nativeStatErr == nil && operations.sameFile(rootInfo, nativeInfo) {
			return root, nativeDirectory, nil
		}
		closeErr := errors.Join(closeRoot(root), closeFile(nativeDirectory))
		if rootStatErr != nil || nativeStatErr != nil || closeErr != nil {
			return nil, nil, &PathError{Op: "verify handles", Path: path, Err: errors.Join(rootStatErr, nativeStatErr, closeErr)}
		}
	}
	return nil, nil, &PathError{Op: "verify handles", Path: path, Err: ErrHandleMismatch}
}

func closeRoot(root *os.Root) error {
	if root == nil {
		return nil
	}
	return root.Close()
}

func closeFile(file *os.File) error {
	if file == nil {
		return nil
	}
	return file.Close()
}

// TargetPath returns the cleaned absolute requested target.
func (anchor *Anchor) TargetPath() string { return anchor.targetPath }

// AncestorPath returns the longest existing parent path used to create the handles.
func (anchor *Anchor) AncestorPath() string { return anchor.ancestorPath }

// MissingParents returns parent components absent when the Anchor was created.
func (anchor *Anchor) MissingParents() []string { return slices.Clone(anchor.missingParents) }

// FinalName returns the requested target's final path component.
func (anchor *Anchor) FinalName() string { return anchor.finalName }

// Root returns the retained os.Root for root-relative operations.
func (anchor *Anchor) Root() *os.Root { return anchor.root }

// NativeDirectory returns the retained platform directory handle.
func (anchor *Anchor) NativeDirectory() *os.File { return anchor.nativeDirectory }

// Close releases both retained handles and is safe to call repeatedly.
func (anchor *Anchor) Close() error {
	if anchor == nil {
		return nil
	}
	var closeErrors []error
	if anchor.rootOwned {
		if err := anchor.descentOperations.closeRoot(anchor.root); err != nil {
			closeErrors = append(closeErrors, err)
		} else {
			anchor.rootOwned = false
		}
	}
	if anchor.nativeOwned {
		if err := anchor.descentOperations.closeNativeDirectory(anchor.nativeDirectory); err != nil {
			closeErrors = append(closeErrors, err)
		} else {
			anchor.nativeOwned = false
		}
	}
	anchor.retiredRoots, closeErrors = closeRetiredRoots(anchor.retiredRoots, anchor.descentOperations.closeRoot, closeErrors)
	anchor.retiredDirectories, closeErrors = closeRetiredDirectories(anchor.retiredDirectories, anchor.descentOperations.closeNativeDirectory, closeErrors)
	return errors.Join(closeErrors...)
}

func closeRetiredRoots(roots []*os.Root, closeHandle func(*os.Root) error, closeErrors []error) ([]*os.Root, []error) {
	retained := roots[:0]
	for _, root := range roots {
		if err := closeHandle(root); err != nil {
			retained = append(retained, root)
			closeErrors = append(closeErrors, err)
		}
	}
	return retained, closeErrors
}

func closeRetiredDirectories(directories []*os.File, closeHandle func(*os.File) error, closeErrors []error) ([]*os.File, []error) {
	retained := directories[:0]
	for _, directory := range directories {
		if err := closeHandle(directory); err != nil {
			retained = append(retained, directory)
			closeErrors = append(closeErrors, err)
		}
	}
	return retained, closeErrors
}

func hasWindowsADSSuffix(path string) bool {
	rest := path
	if extended, ok := strings.CutPrefix(rest, `\\?\`); ok {
		rest = extended
		if len(rest) >= 4 && strings.EqualFold(rest[:4], `UNC\`) {
			rest = rest[4:]
			return uncRemainderHasColon(rest)
		}
	}
	if strings.HasPrefix(rest, `\\`) {
		return uncRemainderHasColon(rest[2:])
	}
	if len(rest) >= 2 && rest[1] == ':' && isASCIIAlpha(rest[0]) {
		return strings.ContainsRune(rest[2:], ':')
	}
	return false
}

func uncRemainderHasColon(path string) bool {
	parts := strings.SplitN(strings.ReplaceAll(path, "/", `\`), `\`, 3)
	return len(parts) == 3 && parts[0] != "" && parts[1] != "" && strings.ContainsRune(parts[2], ':')
}

func isASCIIAlpha(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
