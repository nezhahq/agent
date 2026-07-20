package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nezhahq/agent/model"
	pb "github.com/nezhahq/agent/proto"
)

// handleApplyConfigTask must explicitly surface the DisableCommandExecute
// rejection so the dashboard can fail the transfer immediately instead of
// waiting 24h for the timeout sweep. The Successful flag stays false and
// result.Data carries a human-readable reason.
func TestHandleApplyConfigTaskRejectsWhenCommandExecuteDisabled(t *testing.T) {
	originalConfig := agentConfig
	defer func() {
		agentConfig = originalConfig
		clearReloadTimer()
	}()

	setTestRuntimeConfig(model.AgentConfig{DisableCommandExecute: true})

	task := &pb.Task{Id: 42, Data: `{"client_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}`}
	result := &pb.TaskResult{}

	handleApplyConfigTask(task, result)

	if result.Successful {
		t.Fatal("DisableCommandExecute must NOT report Successful=true")
	}
	if !strings.Contains(result.Data, "DisableCommandExecute") {
		t.Fatalf("result.Data must mention DisableCommandExecute for operator visibility, got %q", result.Data)
	}
	if reloadPending() {
		t.Fatal("DisableCommandExecute path must not leave a reload scheduled")
	}
}

// A second ApplyConfig arriving during the 10s reload window must supersede
// the first, not be rejected. This is the abort hook the dashboard relies on
// when an operator cancels a server transfer: the cancel pushes a counter
// task carrying the original secret, and without supersede the agent would
// commit the cancelled swap anyway and lock itself out.
func TestHandleApplyConfigTaskSupersedesPendingReload(t *testing.T) {
	originalConfig := agentConfig
	defer func() {
		agentConfig = originalConfig
		clearReloadTimer()
	}()

	setTestRuntimeConfig(model.AgentConfig{ClientSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TLS: true})

	first := &pb.Task{Id: 1, Data: `{"client_secret":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}`}
	firstResult := &pb.TaskResult{}
	handleServerTransferApplyTask(first, firstResult)
	if !firstResult.Successful {
		t.Fatalf("first ApplyConfig must succeed, got Data=%q", firstResult.Data)
	}
	if !reloadPending() {
		t.Fatal("first ApplyConfig must schedule a reload timer")
	}

	second := &pb.Task{Id: 2, Data: `{"client_secret":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"}`}
	secondResult := &pb.TaskResult{}
	handleServerTransferApplyTask(second, secondResult)
	if !secondResult.Successful {
		t.Fatalf("second ApplyConfig must supersede instead of being rejected, got Data=%q", secondResult.Data)
	}
	if !reloadPending() {
		t.Fatal("second ApplyConfig must leave a reload timer scheduled")
	}
}

// A plain TaskTypeApplyConfig push (admin /server/config reload) must not
// supersede an in-flight TaskTypeServerTransferApply reload: the plain push
// typically does not carry a rotated client_secret, so letting it win would
// drop the rotation and the dashboard would wait 24h for the transfer to
// timeout. Reject the plain push and keep the transfer timer untouched.
func TestHandleApplyConfigTaskPlainPushDoesNotSupersedeTransferReload(t *testing.T) {
	originalConfig := agentConfig
	defer func() {
		agentConfig = originalConfig
		clearReloadTimer()
	}()

	setTestRuntimeConfig(model.AgentConfig{ClientSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TLS: true})

	transfer := &pb.Task{Id: 42, Data: `{"client_secret":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}`}
	transferResult := &pb.TaskResult{}
	handleServerTransferApplyTask(transfer, transferResult)
	if !transferResult.Successful {
		t.Fatalf("transfer ApplyConfig must succeed, got Data=%q", transferResult.Data)
	}

	reloadMu.Lock()
	transferTimer := reloadTimer
	reloadMu.Unlock()
	if transferTimer == nil {
		t.Fatal("transfer ApplyConfig must install a reload timer")
	}

	plain := &pb.Task{Id: 0, Data: `{"debug":true}`}
	plainResult := &pb.TaskResult{}
	handleApplyConfigTask(plain, plainResult)
	if plainResult.Successful {
		t.Fatalf("plain ApplyConfig must NOT report success while a transfer reload is in flight, got Data=%q", plainResult.Data)
	}
	if plainResult.Data == "" {
		t.Fatal("plain ApplyConfig rejection must include a human-readable reason in Data")
	}

	reloadMu.Lock()
	stillTransfer := reloadTimer == transferTimer
	reloadMu.Unlock()
	if !stillTransfer {
		t.Fatal("plain ApplyConfig must not supersede the transfer reload timer")
	}
}

// Invalid JSON in the task payload must fail loudly with the parse error so
// the dashboard can surface it instead of letting the agent silently ignore
// the ApplyConfig push (which would leave the transfer stuck in Pending).
func TestHandleApplyConfigTaskFailsOnInvalidPayload(t *testing.T) {
	originalConfig := agentConfig
	defer func() {
		agentConfig = originalConfig
		clearReloadTimer()
	}()

	setTestRuntimeConfig(model.AgentConfig{})

	task := &pb.Task{Id: 1, Data: `not-json`}
	result := &pb.TaskResult{}

	handleApplyConfigTask(task, result)

	if result.Successful {
		t.Fatal("invalid JSON must report Successful=false")
	}
	if result.Data == "" {
		t.Fatal("invalid JSON must surface a parse error in result.Data")
	}
	if reloadPending() {
		t.Fatal("parse failure must not leave a reload timer scheduled")
	}
}

// 在 worker 因为断网走 retry() 期间没有接收方时，applyPendingReload 必须
// 非阻塞返回，否则 time.AfterFunc 起的 goroutine 会卡死在 reloadSigChan 上，
// 同时 reloadTimer 已被置 nil — 后续 ApplyConfig 不会走 supersede 路径，
// 网络抖动叠加会导致多个 goroutine 同时卡住、每次重连多带一次冗余抖动。
// 这是 review 评分 85 的真实 bug 现场。
func TestApplyPendingReloadDoesNotBlockWithoutReader(t *testing.T) {
	originalConfig := agentConfig
	defer func() {
		agentConfig = originalConfig
		clearReloadTimer()
		// 把可能被遗留信号清掉，避免影响后续测试
		select {
		case <-reloadSigChan:
		default:
		}
	}()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(configPath, []byte("server: \"example.com:5555\"\nclient_secret: \"original\"\nuuid: \"00000000-0000-0000-0000-000000000001\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	agentConfig = model.AgentConfig{}
	if err := agentConfig.Read(configPath); err != nil {
		t.Fatal(err)
	}
	publishRuntimeConfig(agentConfig)
	pendingConfig := agentConfig
	pendingConfig.ClientSecret = "rotated"

	active := time.AfterFunc(time.Hour, func() {})
	defer active.Stop()
	reloadMu.Lock()
	reloadTimer = active
	reloadMu.Unlock()

	done := make(chan struct{})
	go func() {
		applyPendingReload(active, pendingConfig)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("applyPendingReload blocked on reloadSigChan with no reader; supersede 保护被绕过")
	}
}

// 两条 ApplyConfig 任务背靠背到达时，dashboard 的取消流程依赖「最后到达的
// 那条赢」：取消 transfer 时面板会推一条反向 ApplyConfig 带原 secret，必须在
// 10s 重载窗口内 supersede 掉之前的 new-secret 任务。原实现 receiveTasksDaemon
// 对每个 task 都 `go func(t)` 并发处理，两个 goroutine 抢 reloadMu 的顺序与
// 到达流的顺序无关；如果反向 ApplyConfig 先抢到锁、原 ApplyConfig 后抢到锁，
// agent 会把已取消的凭据写盘并锁死自己。这是 review 评分 75 的真实问题。
//
// 修复方案：把 ApplyConfig 这一类 task 改成同步处理（其它 task 继续起
// goroutine），保证「receive 循环按到达顺序顺序处理 ApplyConfig」。本测试钉
// 死契约：dispatchAgentTask 对 TaskTypeApplyConfig 必须在返回前完成处理并
// 同步发送结果。
func TestDispatchAgentTaskRunsApplyConfigSynchronously(t *testing.T) {
	originalConfig := agentConfig
	defer func() {
		agentConfig = originalConfig
		clearReloadTimer()
	}()

	setTestRuntimeConfig(model.AgentConfig{ClientSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TLS: true})

	task := &pb.Task{Id: 1, Type: model.TaskTypeServerTransferApply, Data: `{"client_secret":"Abcdef0123456789ABCDEFGHIJklmnop"}`}
	sentResults := make(chan *pb.TaskResult, 1)
	send := func(r *pb.TaskResult) error {
		sentResults <- r
		return nil
	}

	dispatchAgentTask(task, send, func() {})

	// 同步契约一：dispatchAgentTask 返回前 reloadTimer 必须已挂上。
	// 否则两条 ApplyConfig 连续到达时，第二条可能先安装 timer、第一条
	// 的 goroutine 再 supersede 掉，把已取消的 credential 锁死写盘。
	if !reloadPending() {
		t.Fatal("dispatchAgentTask for ApplyConfig must install reloadTimer before returning")
	}

	// 同步契约二：result 必须在 dispatchAgentTask 返回前已发出。
	select {
	case <-sentResults:
	default:
		t.Fatal("dispatchAgentTask for ApplyConfig must send result synchronously")
	}
}

// 反向：非 ApplyConfig 任务（这里用 Keepalive，因为它走最短路径只置 result
// 字段、不依赖外部状态）必须保留异步派发，避免一个长任务（HTTP get、TCP
// ping、command）卡住整个接收循环、其它 task 全堆积。
func TestDispatchAgentTaskRunsNonApplyConfigAsync(t *testing.T) {
	releaseHandler := make(chan struct{})
	sentResults := make(chan *pb.TaskResult, 1)
	send := func(r *pb.TaskResult) error {
		// 阻塞 send 直到测试主动释放 — 用来模拟「task 处理慢」的场景。
		<-releaseHandler
		sentResults <- r
		return nil
	}

	task := &pb.Task{Id: 99, Type: model.TaskTypeKeepalive}

	done := make(chan struct{})
	go func() {
		dispatchAgentTask(task, send, func() {})
		close(done)
	}()

	// dispatchAgentTask 必须立刻返回（不等 send 完成）。
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("dispatchAgentTask for non-ApplyConfig must dispatch asynchronously")
	}

	close(releaseHandler)
	select {
	case <-sentResults:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("async dispatch must still eventually run the handler and send the result")
	}
}

// applyPendingReload's commit and handleApplyConfigTask's post-lock
// loadRuntimeConfig baseline must be serialized through reloadMu. Otherwise a
// follow-up ApplyConfig that waits behind a commit can retain a stale
// pre-rotation baseline and silently overwrite the rotated client_secret on
// its own timer fire.
func TestHandleApplyConfigTaskRaceFreeWithCommittingReload(t *testing.T) {
	originalConfig := agentConfig
	defer func() {
		agentConfig = originalConfig
		clearReloadTimer()
		select {
		case <-reloadSigChan:
		default:
		}
	}()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	if err := os.WriteFile(configPath, []byte("server: \"example.com:5555\"\nclient_secret: \"original\"\nuuid: \"00000000-0000-0000-0000-000000000001\"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	const rounds = 50
	for i := 0; i < rounds; i++ {
		agentConfig = model.AgentConfig{}
		if err := agentConfig.Read(configPath); err != nil {
			t.Fatal(err)
		}
		publishRuntimeConfig(agentConfig)

		active := time.AfterFunc(time.Hour, func() {})
		reloadMu.Lock()
		reloadTimer = active
		reloadMu.Unlock()

		rotated := agentConfig
		rotated.ClientSecret = "rotated"

		commitDone := make(chan struct{})
		go func() {
			applyPendingReload(active, rotated)
			close(commitDone)
		}()

		follow := &pb.Task{Id: uint64(i + 1), Data: `{"debug":true}`}
		followResult := &pb.TaskResult{}
		handleApplyConfigTask(follow, followResult)

		<-commitDone
		clearReloadTimer()
		select {
		case <-reloadSigChan:
		default:
		}
	}
}

// HIGH security regression: a malicious or buggy dashboard / MITM that
// downpushes an empty or malformed client_secret must NOT be applied. The
// agent would otherwise commit the bad credential 10s later, then reconnect
// under it; dashboard auth rejects, the agent is persistently offline, and
// recovery requires on-machine intervention.
//
// Validation pinned: client_secret has to be exactly 32 ASCII alphanumerics,
// matching what GenerateRandomString produces dashboard-side. Anything else
// is rejected with Successful=false and no reload timer scheduled.
func TestHandleApplyConfigTaskRejectsMalformedClientSecret(t *testing.T) {
	cases := []struct {
		name    string
		payload string
	}{
		{"empty", `{"client_secret":""}`},
		{"too_short", `{"client_secret":"abc"}`},
		{"too_long", `{"client_secret":"012345678901234567890123456789012345"}`},
		{"contains_newline", `{"client_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n1"}`},
		{"contains_space", `{"client_secret":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 1"}`},
		{"non_ascii", "{\"client_secret\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\u00e9\u00e92\"}"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			originalConfig := agentConfig
			defer func() {
				agentConfig = originalConfig
				clearReloadTimer()
			}()
			setTestRuntimeConfig(model.AgentConfig{ClientSecret: "current-known-good-32-char-secretX", TLS: true})

			task := &pb.Task{Id: 1, Data: tc.payload}
			result := &pb.TaskResult{}
			handleServerTransferApplyTask(task, result)

			if result.Successful {
				t.Fatalf("malformed client_secret (%s) must be rejected, got Successful=true Data=%q", tc.name, result.Data)
			}
			if result.Data == "" {
				t.Fatalf("rejection (%s) must carry a human-readable reason in result.Data", tc.name)
			}
			if reloadPending() {
				t.Fatalf("malformed client_secret (%s) must NOT schedule a reload timer", tc.name)
			}
		})
	}
}

// Positive control: a properly-shaped 32-character alphanumeric secret must
// still go through and schedule a reload. Guards against the validator being
// too strict.
func TestHandleApplyConfigTaskAcceptsWellFormedClientSecret(t *testing.T) {
	originalConfig := agentConfig
	defer func() {
		agentConfig = originalConfig
		clearReloadTimer()
	}()
	setTestRuntimeConfig(model.AgentConfig{ClientSecret: "current-known-good-32-char-secretX", TLS: true})

	task := &pb.Task{Id: 1, Data: `{"client_secret":"AbcdEfghIjklMnopQrstUvwxYz012345"}`}
	result := &pb.TaskResult{}
	handleServerTransferApplyTask(task, result)

	if !result.Successful {
		t.Fatalf("well-formed 32-char alphanumeric client_secret must be accepted, got Data=%q", result.Data)
	}
	if !reloadPending() {
		t.Fatal("well-formed client_secret must schedule a reload timer")
	}
}

// CRITICAL security: the rotated client_secret must never travel over an
// insecure transport. The gate checks tmpConfig (the connection the rotated
// secret will travel over on the NEXT reconnect), not agentConfig (the
// current connection) — otherwise a payload that simultaneously rotates
// the secret AND disables TLS (or enables InsecureTLS) leaks the new
// secret on the very next dial.
func TestHandleServerTransferApplyTaskRefusesRotationToInsecureTransport(t *testing.T) {
	cases := []struct {
		name    string
		current model.AgentConfig
		payload string
	}{
		{
			"already_plain",
			model.AgentConfig{ClientSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TLS: false, InsecureTLS: false},
			`{"client_secret":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}`,
		},
		{
			"already_insecure_tls",
			model.AgentConfig{ClientSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TLS: true, InsecureTLS: true},
			`{"client_secret":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}`,
		},
		{
			"downgrade_tls_in_payload",
			model.AgentConfig{ClientSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TLS: true, InsecureTLS: false},
			`{"client_secret":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","tls":false}`,
		},
		{
			"enable_insecure_tls_in_payload",
			model.AgentConfig{ClientSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TLS: true, InsecureTLS: false},
			`{"client_secret":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","insecure_tls":true}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			originalConfig := agentConfig
			defer func() {
				agentConfig = originalConfig
				clearReloadTimer()
			}()
			setTestRuntimeConfig(tc.current)

			task := &pb.Task{Id: 42, Data: tc.payload}
			result := &pb.TaskResult{}
			handleServerTransferApplyTask(task, result)

			if result.Successful {
				t.Fatalf("credential rotation to insecure transport must be rejected, got Successful=true")
			}
			if result.Data == "" {
				t.Fatal("rejection must include a human-readable reason")
			}
			if reloadPending() {
				t.Fatal("insecure rotation must NOT schedule a reload")
			}
		})
	}
}

// Non-rotation remote config push (no client_secret change) must still be
// honoured even when the transport is insecure. Disabling those would
// break large numbers of legitimate deployments.
func TestHandleApplyConfigTaskAllowsNonRotationConfigOnInsecureTransport(t *testing.T) {
	originalConfig := agentConfig
	defer func() {
		agentConfig = originalConfig
		clearReloadTimer()
	}()
	setTestRuntimeConfig(model.AgentConfig{ClientSecret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", TLS: false})

	task := &pb.Task{Id: 0, Data: `{"debug":true}`}
	result := &pb.TaskResult{}
	handleApplyConfigTask(task, result)

	if !result.Successful {
		t.Fatalf("non-rotation ApplyConfig over insecure transport must still be accepted, got Data=%q", result.Data)
	}
	if !reloadPending() {
		t.Fatal("non-rotation ApplyConfig must schedule a reload")
	}
}

// clearReloadTimer drops any pending swap so test cases stay independent.
// Tests rely on this in defers because handleApplyConfigTask schedules a real
// 10s timer that would otherwise outlive the test.
func clearReloadTimer() {
	reloadMu.Lock()
	defer reloadMu.Unlock()
	if reloadTimer != nil {
		reloadTimer.Stop()
		reloadTimer = nil
	}
	reloadIsTransfer = false
	// Give a possibly-already-fired callback a beat to observe the nil and
	// exit without mutating agentConfig.
	time.Sleep(5 * time.Millisecond)
}

// The whole point of ApplyConfig is to persist the new credential so the
// agent reconnects under it across crashes. That persistence runs through a
// chain of struct copies — handleApplyConfigTask's tmpConfig, the value
// captured by the timer closure, and the value parameter to
// applyPendingReload — any of which could lose AgentConfig.filePath (it's
// unexported but copied across the package boundary by value semantics).
// If filePath gets blanked, Save() either errors silently with "open : no
// such file or directory" or writes to "." instead of the operator-chosen
// path, and the dashboard's transfer flow is silently broken on the next
// agent restart. This test pins down end-to-end that the path survives.
func TestApplyPendingReloadWritesToConfigReadPath(t *testing.T) {
	originalConfig := agentConfig
	defer func() {
		agentConfig = originalConfig
		clearReloadTimer()
	}()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	// Seed an initial config on disk so Read populates filePath.
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	require(os.WriteFile(configPath, []byte("server: \"example.com:5555\"\nclient_secret: \"original\"\nuuid: \"00000000-0000-0000-0000-000000000001\"\n"), 0600))

	agentConfig = model.AgentConfig{}
	require(agentConfig.Read(configPath))
	publishRuntimeConfig(agentConfig)
	if agentConfig.ClientSecret != "original" {
		t.Fatalf("precondition: agentConfig.ClientSecret = %q, want %q", agentConfig.ClientSecret, "original")
	}

	// Build the same pendingConfig the timer closure would have captured.
	pendingConfig := agentConfig
	pendingConfig.ClientSecret = "rotated"

	// Pre-install a sentinel "active" timer so the identity check in
	// applyPendingReload accepts our synthetic call. Without this the helper
	// would short-circuit on the supersede guard.
	active := time.AfterFunc(time.Hour, func() {})
	defer active.Stop()
	reloadMu.Lock()
	reloadTimer = active
	reloadMu.Unlock()

	// applyPendingReload 末尾用 non-blocking 发送通知 worker 重连；本测试不
	// 拉接收方，验证场景就是「worker 不在线时 save+swap 仍然完成」。
	applyPendingReload(active, pendingConfig)

	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Save must have written to the Read path; got: %v", err)
	}
	if !strings.Contains(string(data), "rotated") {
		t.Fatalf("Saved config at %s must carry the new client_secret; got:\n%s", configPath, string(data))
	}
	// Cross-check no rogue file was created in the working directory under
	// the empty-path failure mode.
	if _, err := os.Stat("config.yml"); err == nil {
		t.Fatal("Save must NOT have fallen back to writing to the CWD (filePath was lost in the copy chain)")
	}
}
