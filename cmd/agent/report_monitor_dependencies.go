package main

import (
	"github.com/nezhahq/agent/model"
	"github.com/nezhahq/agent/pkg/monitor"
	pb "github.com/nezhahq/agent/proto"
)

type reportMonitorDependencySet struct {
	trackNetworkSpeed func(*model.AgentConfig)
	getState          func(*model.AgentConfig, bool, bool) *model.HostState
	getHost           func(*model.AgentConfig) *model.Host
	fetchIP           func(*model.AgentConfig, bool) *pb.GeoIP
	geoIPChanged      func() bool
	markGeoIPReported func(string)
}

var reportMonitorDependencies = reportMonitorDependencySet{
	trackNetworkSpeed: monitor.TrackNetworkSpeed,
	getState:          monitor.GetState,
	getHost:           monitor.GetHost,
	fetchIP:           monitor.FetchIP,
	geoIPChanged:      monitor.GeoIPChanged,
	markGeoIPReported: monitor.MarkGeoIPReported,
}
