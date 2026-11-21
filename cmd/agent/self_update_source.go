package main

import (
	"fmt"
	"io"
	"strings"
)

// updateRepo is the GitHub repository ("owner/repo") the agent updates itself
// from. It is injected at build time, e.g.
//
//	-X main.updateRepo=owner/nezha-agent
//
// (.goreleaser.yml fills it from NZ_AGENT_UPDATE_REPO). When it is empty the
// upstream behavior is kept: nezhahq/agent on GitHub, with Gitee/AtomGit
// mirrors for users in mainland China or when explicitly configured.
var updateRepo string

const (
	upstreamUpdateRepo = "nezhahq/agent"
	giteeUpdateRepo    = "naibahq/agent"
	atomGitUpdateRepo  = "naiba/nezha-agent"
)

type updateSourceKind int

const (
	updateSourceGitHub updateSourceKind = iota
	updateSourceGitee
	updateSourceAtomGit
)

type updateSource struct {
	kind updateSourceKind
	repo string
}

// selectUpdateSource decides where doSelfUpdate looks for new releases.
//
// A custom repository injected at build time only exists on GitHub, so it
// always wins and the Gitee/AtomGit mirrors (which carry upstream releases)
// are skipped. Without it the upstream selection order is preserved.
// preferGitee is only called for the random mirror pick in mainland China.
func selectUpdateSource(customRepo string, config updateConfigTuple, countryCode string, preferGitee func() bool) updateSource {
	if repo := strings.TrimSpace(customRepo); repo != "" {
		return updateSource{kind: updateSourceGitHub, repo: repo}
	}
	switch {
	case config.useGiteeToUpgrade:
		return updateSource{kind: updateSourceGitee, repo: giteeUpdateRepo}
	case config.useAtomGitToUpgrade:
		return updateSource{kind: updateSourceAtomGit, repo: atomGitUpdateRepo}
	case countryCode == "cn":
		if preferGitee() {
			return updateSource{kind: updateSourceGitee, repo: giteeUpdateRepo}
		}
		return updateSource{kind: updateSourceAtomGit, repo: atomGitUpdateRepo}
	default:
		return updateSource{kind: updateSourceGitHub, repo: upstreamUpdateRepo}
	}
}

// effectiveUpdateRepo describes the self-update source compiled into this
// binary. An injected repository is printed verbatim so release pipelines can
// compare it exactly against the value they meant to inject; a misspelled
// ldflags target leaves updateRepo empty and the comparison fails.
func effectiveUpdateRepo() string {
	if repo := strings.TrimSpace(updateRepo); repo != "" {
		return repo
	}
	return upstreamUpdateRepo + " (default; Gitee/AtomGit mirrors may be used)"
}

// printUpdateRepo backs the hidden, offline "update-repo" command.
func printUpdateRepo(w io.Writer) error {
	_, err := fmt.Fprintln(w, effectiveUpdateRepo())
	return err
}
