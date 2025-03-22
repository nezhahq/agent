//go:build !linux

package conn

import (
	"context"
	"syscall"

	"github.com/shirou/gopsutil/v4/net"
)

func GetState(_ context.Context) ([]uint64, error) {
	var tcpConnCount, udpConnCount uint64

	conns, _ := net.Connections("all")
	for _, conn := range conns {
		switch conn.Type {
		case syscall.SOCK_STREAM:
			tcpConnCount++
		case syscall.SOCK_DGRAM:
			udpConnCount++
		}
	}

	return []uint64{tcpConnCount, udpConnCount}, nil
}
