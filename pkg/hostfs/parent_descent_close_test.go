package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestAnchoredCreateDirs_RetainsOldRootWhenCloseFails(t *testing.T) {
	t.Parallel()
	testRetiredHandleOwnership(t, true, false)
}

func TestAnchoredCreateDirs_RetainsOldNativeWhenCloseFails(t *testing.T) {
	t.Parallel()
	testRetiredHandleOwnership(t, false, true)
}

func TestAnchoredCreateDirs_RetainsBothOldHandlesWhenCloseFails(t *testing.T) {
	t.Parallel()
	testRetiredHandleOwnership(t, true, true)
}

func TestAnchoredCreateDirs_CloseAggregatesAndRetriesPersistentlyFailedRetiredHandles(t *testing.T) {
	t.Parallel()

	// Given
	target := filepath.Join(t.TempDir(), "missing", "target.txt")
	anchor := newTestAnchor(t, target)
	oldRoot := anchor.Root()
	oldNative := anchor.NativeDirectory()
	operations := anchor.descentOperations
	closeRoot := operations.closeRoot
	closeNative := operations.closeNativeDirectory
	rootCalls := 0
	nativeCalls := 0
	oldRootAttempts := 0
	oldNativeAttempts := 0
	rootErr := errors.New("persistent retired root close failure")
	nativeErr := errors.New("persistent retired native close failure")
	operations.closeRoot = func(root *os.Root) error {
		rootCalls++
		if root == oldRoot {
			oldRootAttempts++
			if oldRootAttempts <= 2 {
				return rootErr
			}
		}
		return closeRoot(root)
	}
	operations.closeNativeDirectory = func(file *os.File) error {
		nativeCalls++
		if file == oldNative {
			oldNativeAttempts++
			if oldNativeAttempts <= 2 {
				return nativeErr
			}
		}
		return closeNative(file)
	}
	anchor.descentOperations = operations
	if err := anchor.EnsureParent(true, 0o755); !errors.Is(err, rootErr) || !errors.Is(err, nativeErr) {
		t.Fatalf("EnsureParent() error = %v, want both close failures", err)
	}

	// When
	firstCloseErr := anchor.Close()
	secondCloseErr := anchor.Close()

	// Then
	if !errors.Is(firstCloseErr, rootErr) || !errors.Is(firstCloseErr, nativeErr) {
		t.Fatalf("first Close() error = %v, want both retained errors", firstCloseErr)
	}
	if secondCloseErr != nil {
		t.Fatalf("second Close() error = %v, want successful retry", secondCloseErr)
	}
	if rootCalls != 4 || nativeCalls != 4 {
		t.Fatalf("close calls root/native = %d/%d, want 4/4", rootCalls, nativeCalls)
	}
}

func testRetiredHandleOwnership(t *testing.T, failRoot, failNative bool) {
	t.Helper()

	// Given
	target := filepath.Join(t.TempDir(), "missing", "target.txt")
	anchor := newTestAnchor(t, target)
	oldRoot := anchor.Root()
	oldNative := anchor.NativeDirectory()
	operations := anchor.descentOperations
	closeRoot := operations.closeRoot
	closeNative := operations.closeNativeDirectory
	rootCalls := 0
	nativeCalls := 0
	events := make([]string, 0, 6)
	rootCloseErr := errors.New("injected old root close failure")
	nativeCloseErr := errors.New("injected old native close failure")
	operations.closeRoot = func(root *os.Root) error {
		rootCalls++
		events = append(events, "root")
		if root == oldRoot && failRoot && rootCalls == 1 {
			return rootCloseErr
		}
		return closeRoot(root)
	}
	operations.closeNativeDirectory = func(file *os.File) error {
		nativeCalls++
		events = append(events, "native")
		if file == oldNative && failNative && nativeCalls == 1 {
			return nativeCloseErr
		}
		return closeNative(file)
	}
	anchor.descentOperations = operations

	// When
	descentErr := anchor.EnsureParent(true, 0o755)

	// Then
	if failRoot && !errors.Is(descentErr, rootCloseErr) || failNative && !errors.Is(descentErr, nativeCloseErr) {
		t.Fatalf("EnsureParent() error = %v, want injected close failures", descentErr)
	}
	if !failRoot && !failNative && descentErr != nil {
		t.Fatalf("EnsureParent(): %v", descentErr)
	}
	if _, err := anchor.Root().Stat("."); err != nil {
		t.Fatalf("installed child Root unusable: %v", err)
	}
	if _, err := anchor.NativeDirectory().Stat(); err != nil {
		t.Fatalf("installed child native directory unusable: %v", err)
	}
	if !slices.Equal(events, []string{"root", "native"}) {
		t.Fatalf("descent close order = %v, want [root native]", events)
	}

	// When
	firstCloseErr := anchor.Close()
	secondCloseErr := anchor.Close()

	// Then
	if firstCloseErr != nil || secondCloseErr != nil {
		t.Fatalf("Anchor.Close() errors = %v/%v, want retained handles reclaimed", firstCloseErr, secondCloseErr)
	}
	wantRootCalls := 2
	if failRoot {
		wantRootCalls++
	}
	wantNativeCalls := 2
	if failNative {
		wantNativeCalls++
	}
	if rootCalls != wantRootCalls || nativeCalls != wantNativeCalls {
		t.Fatalf("close calls root/native = %d/%d, want %d/%d", rootCalls, nativeCalls, wantRootCalls, wantNativeCalls)
	}
	wantEvents := []string{"root", "native", "root", "native"}
	if failRoot {
		wantEvents = append(wantEvents, "root")
	}
	if failNative {
		wantEvents = append(wantEvents, "native")
	}
	if !slices.Equal(events, wantEvents) {
		t.Fatalf("all close events = %v, want %v", events, wantEvents)
	}
}
