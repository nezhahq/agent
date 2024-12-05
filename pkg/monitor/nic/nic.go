package nic

import (
	"context"
	"sync"

	"github.com/cloudflare/ahocorasick"
	"github.com/shirou/gopsutil/v4/net"
)

type NICKeyType string

const NICKey NICKeyType = "nic"

var (
	excludeNetInterfaces = []string{
		"lo", "tun", "docker", "veth", "br-", "vmbr", "vnet", "kube",
	}

	defaultMatcher = ahocorasick.NewStringMatcher(excludeNetInterfaces)
	customMatcher  *ahocorasick.Matcher
	matcherOnce    sync.Once
)

func GetState(ctx context.Context) ([]uint64, error) {
	var netInTransfer, netOutTransfer uint64
	nc, err := net.IOCountersWithContext(ctx, true)
	if err != nil {
		return nil, err
	}

	allowList, _ := ctx.Value(NICKey).(map[string]bool)
	matcherOnce.Do(func() {
		als := make([]string, 0)
		for nic, incl := range allowList {
			if incl {
				als = append(als, nic)
			}
		}
		customMatcher = ahocorasick.NewStringMatcher(als)
	})

	for _, v := range nc {
		if defaultMatcher.Contains([]byte(v.Name)) && !customMatcher.Contains([]byte(v.Name)) {
			continue
		}
		if len(allowList) > 0 && !customMatcher.Contains([]byte(v.Name)) {
			continue
		}
		netInTransfer += v.BytesRecv
		netOutTransfer += v.BytesSent
	}

	return []uint64{netInTransfer, netOutTransfer}, nil
}
