//go:build !agentcompat

package fm_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/nezhahq/agent/pkg/fm"
)

func TestProductionBuild_HasNoAgentcompatObserverAPIOrStrings(t *testing.T) {
	taskType := reflect.TypeOf((*fm.Task)(nil))
	for _, methodName := range []string{"ActiveProducerCount", "ClearProducerObserver", "SetProducerObserver"} {
		if _, exists := taskType.MethodByName(methodName); exists {
			t.Errorf("default fm.Task unexpectedly exposes %s", methodName)
		}
	}
	listObserverPackage := exec.CommandContext(t.Context(), "go", "list", "./internal/agentcompat")
	listObserverPackage.Dir = filepath.Join("..", "..")
	if output, err := listObserverPackage.CombinedOutput(); err == nil {
		t.Fatalf("default build unexpectedly exposes observer package: %s", output)
	}

	binaryPath := filepath.Join(t.TempDir(), "agent")
	command := exec.CommandContext(t.Context(), "go", "build", "-o", binaryPath, "../../cmd/agent")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build default Agent: %v\n%s", err, output)
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		{'A', 'G', 'E', 'N', 'T', 'C', 'O', 'M', 'P', 'A', 'T', '_', 'F', 'M', '_', 'O', 'B', 'S', 'E', 'R', 'V', 'E', 'R'},
		{'f', 'm', '-', 'o', 'b', 's', 'e', 'r', 'v', 'e', 'r', '.', 's', 'o', 'c', 'k'},
	} {
		if bytes.Contains(binary, forbidden) {
			t.Errorf("default Agent binary contains harness-only observer string %q", forbidden)
		}
	}
}
