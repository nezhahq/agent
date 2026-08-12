//go:build !windows

package pty

import (
	"slices"
	"testing"
)

func TestTerminalEnvironmentOverridesCapabilitiesWithoutDuplicates(t *testing.T) {
	environment := terminalEnvironment([]string{
		"PATH=/usr/bin",
		"TERM=dumb",
		"COLORTERM=old",
		"TERM_PROGRAM=old",
		"LANG=en_US.UTF-8",
	})

	for _, expected := range []string{
		"PATH=/usr/bin",
		"LANG=en_US.UTF-8",
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"TERM_PROGRAM=Nezha",
	} {
		if !slices.Contains(environment, expected) {
			t.Errorf("terminal environment missing %q: %v", expected, environment)
		}
	}
	for _, key := range []string{"TERM=", "COLORTERM=", "TERM_PROGRAM="} {
		count := 0
		for _, item := range environment {
			if len(item) >= len(key) && item[:len(key)] == key {
				count++
			}
		}
		if count != 1 {
			t.Errorf("terminal environment contains %d %s entries: %v", count, key, environment)
		}
	}
}
