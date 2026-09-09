package model

import (
	pb "github.com/nezhahq/agent/proto"
)

type SensorTemperature struct {
	Name        string
	Temperature float64
}

type HostState struct {
	CPU            float64
	MemUsed        uint64
	SwapUsed       uint64
	DiskUsed       uint64
	NetInTransfer  uint64
	NetOutTransfer uint64
	NetInSpeed     uint64
	NetOutSpeed    uint64
	Uptime         uint64
	Load1          float64
	Load5          float64
	Load15         float64
	TcpConnCount   uint64
	UdpConnCount   uint64
	ProcessCount   uint64
	Temperatures   []SensorTemperature
	GPU            []float64
	GPUs           []GPUStat
}

// GPUStat carries per-card figures. Memory is in MiB and stays zero on
// vendors that do not report it, so MemoryTotal == 0 means "unknown".
type GPUStat struct {
	Utilization float64
	MemoryUsed  uint64
	MemoryTotal uint64
}

func (s *HostState) PB() *pb.State {
	var ts []*pb.State_SensorTemperature
	for _, t := range s.Temperatures {
		ts = append(ts, &pb.State_SensorTemperature{
			Name:        t.Name,
			Temperature: t.Temperature,
		})
	}

	gs := make([]*pb.State_GPU, 0, len(s.GPUs))
	for _, g := range s.GPUs {
		gs = append(gs, &pb.State_GPU{
			Utilization: g.Utilization,
			MemoryUsed:  g.MemoryUsed,
			MemoryTotal: g.MemoryTotal,
		})
	}

	return &pb.State{
		Cpu:            s.CPU,
		MemUsed:        s.MemUsed,
		SwapUsed:       s.SwapUsed,
		DiskUsed:       s.DiskUsed,
		NetInTransfer:  s.NetInTransfer,
		NetOutTransfer: s.NetOutTransfer,
		NetInSpeed:     s.NetInSpeed,
		NetOutSpeed:    s.NetOutSpeed,
		Uptime:         s.Uptime,
		Load1:          s.Load1,
		Load5:          s.Load5,
		Load15:         s.Load15,
		TcpConnCount:   s.TcpConnCount,
		UdpConnCount:   s.UdpConnCount,
		ProcessCount:   s.ProcessCount,
		Temperatures:   ts,
		Gpu:            s.GPU,
		Gpus:           gs,
	}
}

type Host struct {
	Platform        string
	PlatformVersion string
	CPU             []string
	MemTotal        uint64
	DiskTotal       uint64
	SwapTotal       uint64
	Arch            string
	Virtualization  string
	BootTime        uint64
	Version         string
	GPU             []string
}

func (h *Host) PB() *pb.Host {
	return &pb.Host{
		Platform:        h.Platform,
		PlatformVersion: h.PlatformVersion,
		Cpu:             h.CPU,
		MemTotal:        h.MemTotal,
		DiskTotal:       h.DiskTotal,
		SwapTotal:       h.SwapTotal,
		Arch:            h.Arch,
		Virtualization:  h.Virtualization,
		BootTime:        h.BootTime,
		Version:         h.Version,
		Gpu:             h.GPU,
	}
}

type GeoIP struct {
	IP          IP     `json:"ip,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
}

type IP struct {
	IPv4Addr string `json:"ipv4_addr,omitempty"`
	IPv6Addr string `json:"ipv6_addr,omitempty"`
}
