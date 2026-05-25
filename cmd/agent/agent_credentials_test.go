package main

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/nezhahq/agent/model"
)

// AuthHandler 闭包原先直接读全局 agentConfig.ClientSecret/UUID；applyPendingReload
// 在 reloadMu 之外做 `agentConfig = cfg` 整体赋值。string 是 (指针, 长度) 两
// 个 word，整体 struct 赋值不是原子操作，torn read 可能让 GetRequestMetadata
// 返回包含旧指针 + 新长度的垃圾 metadata，gRPC dial 直接拒绝、严重时还会越
// 界访问。这是 review 评分 75 的真实问题。
//
// 修复：把 credential 抽到 atomic.Pointer 快照（publishCredentials /
// loadCredentials），AuthHandler 闭包改读快照，applyPendingReload 在 swap
// 时同步发布。这个测试在 -race 下钉死「auth 闭包 + applyPendingReload」并发
// 路径无 data race。
func TestAuthCredentialPublishConcurrentWithReadIsRaceFree(t *testing.T) {
	publishCredentials(model.AgentConfig{ClientSecret: "s0", UUID: "u0"})

	auth := &model.AuthHandler{
		Credentials: func() (string, string) {
			c := loadCredentials()
			return c.ClientSecret, c.ClientUUID
		},
	}

	const (
		writers = 2
		readers = 8
		rounds  = 1000
	)
	var wg sync.WaitGroup
	wg.Add(writers + readers)

	for i := 0; i < writers; i++ {
		writerID := i
		go func() {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				publishCredentials(model.AgentConfig{
					ClientSecret: fmt.Sprintf("s%d-%d", writerID, j),
					UUID:         fmt.Sprintf("u%d-%d", writerID, j),
				})
			}
		}()
	}
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				_, _ = auth.GetRequestMetadata(context.Background())
			}
		}()
	}
	wg.Wait()
}

// publishCredentials 必须让后续 loadCredentials 立刻看到新值，否则
// applyPendingReload 之后 gRPC 重连仍然带旧 secret 一直被 dashboard 拒。
func TestPublishCredentialsPropagatesToAuthHandler(t *testing.T) {
	publishCredentials(model.AgentConfig{ClientSecret: "old-secret", UUID: "agent-uuid"})

	auth := &model.AuthHandler{
		Credentials: func() (string, string) {
			c := loadCredentials()
			return c.ClientSecret, c.ClientUUID
		},
	}

	md, err := auth.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if md["client_secret"] != "old-secret" {
		t.Fatalf("expected old-secret, got %q", md["client_secret"])
	}

	publishCredentials(model.AgentConfig{ClientSecret: "new-secret", UUID: "agent-uuid"})

	md, err = auth.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if md["client_secret"] != "new-secret" {
		t.Fatalf("publishCredentials must be visible to subsequent reads, got %q", md["client_secret"])
	}
}
