package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

const injectTestRepo = "example/nezha-agent-inject-test"

// goreleaserUpdateRepoLDFlag returns the ldflags entry from .goreleaser.yml
// that injects the self-update repository, with its NZ_AGENT_UPDATE_REPO
// template replaced by repo.
func goreleaserUpdateRepoLDFlag(t *testing.T, repo string) string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "..", ".goreleaser.yml"))
	if err != nil {
		t.Fatalf("open .goreleaser.yml: %v", err)
	}
	defer f.Close()

	tmpl := regexp.MustCompile(`\{\{\s*envOrDefault\s+"NZ_AGENT_UPDATE_REPO"\s+""\s*\}\}`)
	var found []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "- ") || !strings.Contains(line, "NZ_AGENT_UPDATE_REPO") {
			continue
		}
		found = append(found, tmpl.ReplaceAllString(strings.TrimPrefix(line, "- "), repo))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read .goreleaser.yml: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one ldflags entry using NZ_AGENT_UPDATE_REPO in .goreleaser.yml, got %q", found)
	}
	if strings.Contains(found[0], "{{") {
		t.Fatalf("unexpected template in ldflags entry %q", found[0])
	}
	return found[0]
}

// buildAgentAndPrintUpdateRepo builds ./cmd/agent with ldflags and returns
// the output of its hidden update-repo command.
func buildAgentAndPrintUpdateRepo(t *testing.T, ldflags string) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	bin := filepath.Join(t.TempDir(), "nezha-agent")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command(goBin, "build", "-o", bin, "-ldflags", ldflags, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build -ldflags %q: %v\n%s", ldflags, err, out)
	}
	out, err := exec.Command(bin, "update-repo").Output()
	if err != nil {
		t.Fatalf("%s update-repo: %v", bin, err)
	}
	return strings.TrimSpace(string(out))
}

// TestReleaseBuildInjectsUpdateRepo builds the agent with the exact ldflags
// entry from .goreleaser.yml and checks that the injected repository is what
// the binary actually uses. It also proves the check catches a misspelled
// -X target: Go silently ignores -X for unknown symbols.
func TestReleaseBuildInjectsUpdateRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the agent binary")
	}

	ldflag := goreleaserUpdateRepoLDFlag(t, injectTestRepo)
	if got := buildAgentAndPrintUpdateRepo(t, ldflag); got != injectTestRepo {
		t.Fatalf("release ldflags %q: update-repo = %q, want %q", ldflag, got, injectTestRepo)
	}

	typo := strings.Replace(ldflag, "main.updateRepo=", "main.updateRepoTypo=", 1)
	if typo == ldflag {
		t.Fatalf("ldflags entry %q does not target main.updateRepo", ldflag)
	}
	if got := buildAgentAndPrintUpdateRepo(t, typo); got == injectTestRepo {
		t.Fatalf("misspelled -X target %q still reported %q; check would not catch it", typo, got)
	}
}
