package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nezhahq/agent/pkg/hostfs"
)

func TestAnchoredLockWindow_DoesNotHoldStripeDuringReceive(t *testing.T) {
	// Given
	target := filepath.Join(t.TempDir(), "target.txt")
	anchor, pending := newAnchoredPendingReplace(t, target, "old-content")
	receiveEntered := make(chan struct{})
	receiveRelease := make(chan struct{})
	done := make(chan error, 1)
	var commitResult hostfs.AtomicReplaceResult
	var commitErr error

	// When
	go func() {
		done <- receiveThenCommitUnderPathLock(target, func() error {
			close(receiveEntered)
			<-receiveRelease
			if _, err := pending.Write([]byte("new-content")); err != nil {
				return err
			}
			return pending.Seal()
		}, func() error {
			commitResult, commitErr = pending.CommitIfMatch("")
			// Windows can report an unsupported parent sync after the rename committed.
			if commitErr != nil && !errors.Is(commitErr, hostfs.ErrCommittedDurabilityUnknown) {
				return commitErr
			}
			return nil
		})
	}()
	awaitTestSignal(t, receiveEntered, "receive entry")
	lockAcquired := make(chan struct{})
	go func() {
		unlock := fsPathMu.lock(target)
		unlock()
		close(lockAcquired)
	}()
	awaitTestSignal(t, lockAcquired, "stripe acquisition during receive")
	close(receiveRelease)

	// Then
	if err := awaitTestError(t, done, "anchored commit"); err != nil {
		t.Fatalf("receiveThenCommitUnderPathLock(): %v", err)
	}
	if !commitResult.Committed {
		t.Fatalf("commit result = %+v, want committed replacement", commitResult)
	}
	if errors.Is(commitErr, hostfs.ErrCommittedDurabilityUnknown) && commitResult.Durability != hostfs.DurabilityUnknown {
		t.Fatalf("commit result = %+v with durability error %v, want unknown durability", commitResult, commitErr)
	}
	content, err := anchor.Root().ReadFile(anchor.FinalName())
	if err != nil || string(content) != "new-content" {
		t.Fatalf("committed content = %q/%v, want new-content", content, err)
	}
}

func TestAnchoredLockWindow_TargetChangedDuringReceiveCausesMismatch(t *testing.T) {
	// Given
	target := filepath.Join(t.TempDir(), "target.txt")
	_, pending := newAnchoredPendingReplace(t, target, "old-content")
	wantBytes := sha256.Sum256([]byte("old-content"))
	want := hex.EncodeToString(wantBytes[:])
	receiveEntered := make(chan struct{})
	receiveRelease := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- receiveThenCommitUnderPathLock(target, func() error {
			close(receiveEntered)
			<-receiveRelease
			if _, err := pending.Write([]byte("new-content")); err != nil {
				return err
			}
			return pending.Seal()
		}, func() error {
			_, err := pending.CommitIfMatch(want)
			return err
		})
	}()
	awaitTestSignal(t, receiveEntered, "receive entry")
	if err := os.WriteFile(target, []byte("changed-during-receive"), 0o600); err != nil {
		t.Fatalf("change target during receive: %v", err)
	}

	// When
	close(receiveRelease)
	commitErr := awaitTestError(t, done, "anchored mismatch")

	// Then
	if !errors.Is(commitErr, hostfs.ErrIfMatchSHA256Mismatch) {
		t.Fatalf("commit error = %v, want if-match mismatch", commitErr)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "changed-during-receive" {
		t.Fatalf("target content = %q/%v, want competing content", content, err)
	}
}

func TestAnchoredLockWindow_SpecialTargetDuringReceiveAborts(t *testing.T) {
	// Given
	target := filepath.Join(t.TempDir(), "target")
	_, pending := newAnchoredPendingReplace(t, target, "old-content")
	receiveEntered := make(chan struct{})
	receiveRelease := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- receiveThenCommitUnderPathLock(target, func() error {
			close(receiveEntered)
			<-receiveRelease
			if _, err := pending.Write([]byte("new-content")); err != nil {
				return err
			}
			return pending.Seal()
		}, func() error {
			_, err := pending.CommitIfMatch("")
			return err
		})
	}()
	awaitTestSignal(t, receiveEntered, "receive entry")
	if err := os.Remove(target); err != nil {
		t.Fatalf("remove target: %v", err)
	}
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("replace target with directory: %v", err)
	}

	// When
	close(receiveRelease)
	commitErr := awaitTestError(t, done, "anchored special target")

	// Then
	var typeErr *hostfs.FinalTargetTypeError
	if !errors.As(commitErr, &typeErr) || typeErr.Actual != hostfs.FinalTargetDirectory {
		t.Fatalf("commit error = %v, want directory type rejection", commitErr)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("special target changed after rejection: %v/%v", info, err)
	}
}

func newAnchoredPendingReplace(t *testing.T, target, oldContent string) (*hostfs.Anchor, *hostfs.PendingAtomicReplace) {
	t.Helper()
	if err := os.WriteFile(target, []byte(oldContent), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	anchor, err := hostfs.New(target)
	if err != nil {
		t.Fatalf("hostfs.New(): %v", err)
	}
	t.Cleanup(func() { _ = anchor.Close() })
	pending, err := anchor.BeginAtomicReplace(0o600)
	if err != nil {
		t.Fatalf("BeginAtomicReplace(): %v", err)
	}
	t.Cleanup(func() { _ = pending.Close() })
	return anchor, pending
}

func awaitTestSignal(t *testing.T, signal <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
	}
}

func awaitTestError(t *testing.T, result <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		return nil
	}
}
