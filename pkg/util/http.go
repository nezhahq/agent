package util

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

var (
	DNSServersV4  = []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"}
	DNSServersV6  = []string{"[2001:4860:4860::8888]:53", "[2001:4860:4860::8844]:53", "[2606:4700:4700::1111]:53", "[2606:4700:4700::1001]:53"}
	DNSServersAll = append(DNSServersV4, DNSServersV6...)
)

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
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	dnsServers := DNSServersV6
	if !ipv6 {
		dnsServers = DNSServersV4
	}

	res, err := LookupIP(host)
	if err != nil {
		for _, server := range dnsServers {
			r := &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Second * 10,
					}
					return d.DialContext(ctx, "udp", server)
				},
			}
			res, err = r.LookupIP(context.Background(), "ip", host)
			if err == nil {
				break
			}
		}
	}

	if err != nil {
		return "", err
	}

	var ipv4Resolved, ipv6Resolved bool
	var resolved string

	for _, r := range res {
		if r.To4() != nil {
			if !ipv6 {
				ipv4Resolved = true
				resolved = r.String()
				break
			}
		} else if ipv6 {
			ipv6Resolved = true
			resolved = r.String()
			break
		}
	}

	if ipv6 && !ipv6Resolved {
		return "", errors.New("the AAAA record not resolved")
	}

	if !ipv6 && !ipv4Resolved {
		return "", errors.New("the A record not resolved")
	}

	return net.JoinHostPort(resolved, port), nil
}
