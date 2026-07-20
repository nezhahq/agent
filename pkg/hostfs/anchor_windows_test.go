//go:build windows

package hostfs

import (
	"errors"
	"testing"
)

func TestAnchor_RejectsWindowsAlternateDataStream(t *testing.T) {
	t.Parallel()

	anchor, err := New(`C:\hostfs\file.txt:stream`)

	if anchor != nil {
		t.Fatalf("anchor = %#v, want nil", anchor)
	}
	if !errors.Is(err, ErrAlternateDataStream) {
		t.Fatalf("error = %v, want ErrAlternateDataStream", err)
	}
}
