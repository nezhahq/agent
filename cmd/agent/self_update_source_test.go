package main

import "testing"

func TestSelectUpdateSource(t *testing.T) {
	always := func() bool { return true }
	none := func() bool { return false }

	tests := []struct {
		name        string
		customRepo  string
		config      updateConfigTuple
		countryCode string
		preferGitee func() bool
		want        updateSource
	}{
		{
			name: "not injected: upstream GitHub",
			want: updateSource{kind: updateSourceGitHub, repo: "nezhahq/agent"},
		},
		{
			name:        "not injected: whitespace-only value is treated as unset",
			customRepo:  "  ",
			countryCode: "us",
			want:        updateSource{kind: updateSourceGitHub, repo: "nezhahq/agent"},
		},
		{
			name:   "not injected: Gitee configured",
			config: updateConfigTuple{useGiteeToUpgrade: true},
			want:   updateSource{kind: updateSourceGitee, repo: "naibahq/agent"},
		},
		{
			name:   "not injected: AtomGit configured",
			config: updateConfigTuple{useAtomGitToUpgrade: true},
			want:   updateSource{kind: updateSourceAtomGit, repo: "naiba/nezha-agent"},
		},
		{
			name:        "not injected: mainland China picks Gitee",
			countryCode: "cn",
			preferGitee: always,
			want:        updateSource{kind: updateSourceGitee, repo: "naibahq/agent"},
		},
		{
			name:        "not injected: mainland China picks AtomGit",
			countryCode: "cn",
			preferGitee: none,
			want:        updateSource{kind: updateSourceAtomGit, repo: "naiba/nezha-agent"},
		},
		{
			name:       "injected: custom GitHub repo",
			customRepo: "example/nezha-agent",
			want:       updateSource{kind: updateSourceGitHub, repo: "example/nezha-agent"},
		},
		{
			name:        "injected: mainland China skips mirrors",
			customRepo:  "example/nezha-agent",
			countryCode: "cn",
			want:        updateSource{kind: updateSourceGitHub, repo: "example/nezha-agent"},
		},
		{
			name:       "injected: Gitee/AtomGit config is ignored",
			customRepo: " example/nezha-agent ",
			config:     updateConfigTuple{useGiteeToUpgrade: true, useAtomGitToUpgrade: true},
			want:       updateSource{kind: updateSourceGitHub, repo: "example/nezha-agent"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preferGitee := tt.preferGitee
			if preferGitee == nil {
				preferGitee = func() bool {
					t.Fatal("preferGitee must not be called")
					return false
				}
			}
			if got := selectUpdateSource(tt.customRepo, tt.config, tt.countryCode, preferGitee); got != tt.want {
				t.Fatalf("selectUpdateSource() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// The release build injects main.updateRepo via ldflags; a plain build or test
// binary must keep the upstream behavior.
func TestUpdateRepoDefaultsToUnset(t *testing.T) {
	if updateRepo != "" {
		t.Fatalf("updateRepo = %q, want empty without ldflags injection", updateRepo)
	}
}

func TestEffectiveUpdateRepo(t *testing.T) {
	original := updateRepo
	t.Cleanup(func() { updateRepo = original })

	updateRepo = ""
	if got, want := effectiveUpdateRepo(), "nezhahq/agent (default; Gitee/AtomGit mirrors may be used)"; got != want {
		t.Fatalf("effectiveUpdateRepo() = %q, want %q", got, want)
	}
	updateRepo = " example/nezha-agent "
	if got, want := effectiveUpdateRepo(), "example/nezha-agent"; got != want {
		t.Fatalf("effectiveUpdateRepo() = %q, want %q", got, want)
	}
}
