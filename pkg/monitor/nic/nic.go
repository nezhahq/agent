package nic

import (
	"context"

	"github.com/shirou/gopsutil/v4/net"
)

type NICKeyType string

const NICKey NICKeyType = "nic"

var excludeNetInterfaces = map[string]bool{
	"lo":     true,
	"tun":    true,
	"docker": true,
	"veth":   true,
	"br-":    true,
	"vmbr":   true,
	"vnet":   true,
	"kube":   true,
}

func GetState(ctx context.Context) ([]uint64, error) {
	var netInTransfer, netOutTransfer uint64
	nc, err := net.IOCountersWithContext(ctx, true)
	if err != nil {
		return nil, err
	}

	allowList := excludeNetInterfaces
	if m, ok := ctx.Value(NICKey).(map[string]bool); ok && len(m) > 0 {
		allowList = m
	}

	for _, v := range nc {
		if !allowList[v.Name] {
			continue
		}
		netInTransfer += v.BytesRecv
		netOutTransfer += v.BytesSent
	}

	return []uint64{netInTransfer, netOutTransfer}, nil
}
