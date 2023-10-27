package util

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"
)

var DNSServersV4 = []string{"8.8.4.4:53", "223.5.5.5:53", "94.140.14.140:53", "119.29.29.29:53"}
var DNSServersV6 = []string{"[2001:4860:4860::8844]:53", "[2400:3200::1]:53", "[2a10:50c0::1:ff]:53", "[2402:4e00::]:53"}
var DNSServersAll = append(DNSServersV4, DNSServersV6...)

func NewSingleStackHTTPClient(httpTimeout, dialTimeout, keepAliveTimeout time.Duration, ipv6 bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: keepAliveTimeout,
	}

	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			ip, err := resolveIP(addr, ipv6)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, ip)
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   httpTimeout,
	}
}

func resolveIP(addr string, ipv6 bool) (string, error) {
	url := strings.Split(addr, ":")

	dnsServers := DNSServersV6
	if !ipv6 {
		dnsServers = DNSServersV4
	}

	res, err := net.LookupIP(url[0])
	if err != nil {
		for i := 0; i < len(dnsServers); i++ {
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Second * 10,
					}
					return d.DialContext(ctx, "udp", dnsServers[i])
				},
			}
			res, err = r.LookupIP(context.Background(), "ip", url[0])
			if err == nil {
				break
			}
		}
	}

	if err != nil {
		return "", err
	}

	var ipv4Resolved, ipv6Resolved bool

	for i := 0; i < len(res); i++ {
		ip := res[i].String()
		if strings.Contains(ip, ".") && !ipv6 {
			ipv4Resolved = true
			url[0] = ip
			break
		}
		if strings.Contains(ip, ":") && ipv6 {
			ipv6Resolved = true
			url[0] = "[" + ip + "]"
			break
		}
	}

	if ipv6 && !ipv6Resolved {
		return "", errors.New("the AAAA record not resolved")
	}

	if !ipv6 && !ipv4Resolved {
		return "", errors.New("the A record not resolved")
	}

	return strings.Join(url, ":"), nil
}
