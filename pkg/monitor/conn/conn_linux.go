//go:build linux

package conn

import (
	"context"
	"syscall"

	"github.com/dean2021/goss"
	"github.com/shirou/gopsutil/v4/net"
)

func GetState(_ context.Context) ([]uint64, error) {
	var tcpConnCount, udpConnCount uint64

	tcpStat, err := goss.ConnectionsWithProtocol(goss.AF_INET, syscall.IPPROTO_TCP)
	if err == nil {
		tcpConnCount = uint64(len(tcpStat))
	}

	udpStat, err := goss.ConnectionsWithProtocol(goss.AF_INET, syscall.IPPROTO_UDP)
	if err == nil {
		udpConnCount = uint64(len(udpStat))
	}

	tcpStat6, err := goss.ConnectionsWithProtocol(goss.AF_INET6, syscall.IPPROTO_TCP)
	if err == nil {
		tcpConnCount += uint64(len(tcpStat6))
	}

	udpStat6, err := goss.ConnectionsWithProtocol(goss.AF_INET6, syscall.IPPROTO_UDP)
	if err == nil {
		udpConnCount += uint64(len(udpStat6))
	}

	if tcpConnCount < 1 && udpConnCount < 1 {
		// fallback to parsing files
		conns, _ := net.Connections("all")
		for _, conn := range conns {
			switch conn.Type {
			case syscall.SOCK_STREAM:
				tcpConnCount++
			case syscall.SOCK_DGRAM:
				udpConnCount++
			}
		}
	}

	return []uint64{tcpConnCount, udpConnCount}, nil
}
