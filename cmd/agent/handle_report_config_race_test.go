package main

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/nezhahq/agent/proto"

	"github.com/nezhahq/agent/model"
)

// Race scenario: handleReportConfigTask reads `agentConfig.DisableCommandExecute`
// (line ~935) and later marshals `agentConfig` (line ~947) outside reloadMu,
// while applyPendingReload commits `agentConfig = cfg` — a multi-field struct
// assignment — under reloadMu. The same file documents this lock discipline
// at main.go:1003-1011 ("Hold reloadMu across the agentConfig read …") and
// at main.go:287-294 (bare reads "与 applyPendingReload 的 agentConfig = cfg
// 结构体赋值形成" a race). The reloadPending() check between the two reads
// briefly takes the lock but does not cover either of them, so a concurrent
// reload firing during a report dump can be observed mid-swap.
//
// This test runs handleReportConfigTask in a tight loop against a parallel
// `agentConfig = cfg` writer holding reloadMu. Without the fix, the Go race
// detector flags the unlocked reads at lines 935 and 947. With the fix, the
// reads happen under reloadMu and the test passes under -race.
func TestHandleReportConfigTaskDoesNotRaceWithReload(t *testing.T) {
	originalConfig := agentConfig
	t.Cleanup(func() {
		agentConfig = originalConfig
		clearReloadTimer()
	})

	// Two configs we will swap between. Both serialise cleanly so
	// json.Marshal inside handleReportConfigTask succeeds either way.
	a := model.AgentConfig{ClientSecret: "secret-a", UUID: "uuid-a"}
	b := model.AgentConfig{ClientSecret: "secret-b", UUID: "uuid-b"}
	agentConfig = a

	var stop atomic.Bool
	var wg sync.WaitGroup

	// Writer: mimics applyPendingReload's `agentConfig = cfg` under reloadMu.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; !stop.Load(); i++ {
			reloadMu.Lock()
			if i%2 == 0 {
				agentConfig = a
			} else {
				agentConfig = b
			}
			reloadMu.Unlock()
		}
	}()

	// Reader: the production handler. Without the fix this races on the
	// bare `agentConfig.DisableCommandExecute` read and the json.Marshal,
	// which `go test -race` reports as a DATA RACE.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			var r pb.TaskResult
			handleReportConfigTask(&r)
			// Sanity-check: whatever snapshot we marshalled must be one of
			// the two whole configs, never a torn mix of fields. The race
			// detector is the primary signal; this is a belt-and-braces
			// invariant for non-race runs.
			if r.Successful && r.Data != "" {
				var got model.AgentConfig
				if err := json.Unmarshal([]byte(r.Data), &got); err == nil {
					if !(got.ClientSecret == "secret-a" && got.UUID == "uuid-a") &&
						!(got.ClientSecret == "secret-b" && got.UUID == "uuid-b") {
						t.Errorf("torn agentConfig snapshot: %+v", got)
						return
					}
				}
			}
		}
	}()

	time.Sleep(50 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
}
