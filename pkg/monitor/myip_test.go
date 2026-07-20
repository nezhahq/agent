package monitor

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nezhahq/agent/pkg/util"
)

const (
	localIPv4 = "192.0.2.44"
	localIPv6 = "2001:db8::44"
)

func TestHTTPGetWithUA_sendsAgentUserAgent(t *testing.T) {
	useLocalGeoIPClients(t)
	serverURL, observedUserAgent := newGeoIPContractServer(t, localIPv4)

	response, err := httpGetWithUA(httpClientV4, serverURL)
	if err != nil {
		t.Fatalf("GET local GeoIP server: %v", err)
	}
	t.Cleanup(func() { response.Body.Close() })
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatalf("read local GeoIP response: %v", err)
	}
	userAgent := <-observedUserAgent

	if userAgent != util.MacOSChromeUA {
		t.Fatalf("User-Agent = %q, want %q", userAgent, util.MacOSChromeUA)
	}
	t.Logf("server observed User-Agent=%q", userAgent)
}

func TestFetchIP_returnsPlainTextIPv4(t *testing.T) {
	useLocalGeoIPClients(t)
	serverURL, observedUserAgent := newGeoIPContractServer(t, "\n "+localIPv4+" \n")

	ip := fetchIP([]string{serverURL}, false)
	userAgent := <-observedUserAgent

	if ip != localIPv4 {
		t.Fatalf("IPv4 = %q, want %q", ip, localIPv4)
	}
	if userAgent != util.MacOSChromeUA {
		t.Fatalf("User-Agent = %q, want %q", userAgent, util.MacOSChromeUA)
	}
	t.Logf("plain-text address result=%q family=IPv4 User-Agent=%q", ip, userAgent)
}

func TestFetchIP_returnsIPv6FromCloudflareTrace(t *testing.T) {
	useLocalGeoIPClients(t)
	body := "fl=local\nip=" + localIPv6 + "\nloc=TEST\n"
	serverURL, observedUserAgent := newGeoIPContractServer(t, body)

	ip := fetchIP([]string{serverURL}, true)
	userAgent := <-observedUserAgent

	if ip != localIPv6 {
		t.Fatalf("IPv6 = %q, want %q", ip, localIPv6)
	}
	if userAgent != util.MacOSChromeUA {
		t.Fatalf("User-Agent = %q, want %q", userAgent, util.MacOSChromeUA)
	}
	t.Logf("Cloudflare-trace address result=%q family=IPv6 User-Agent=%q", ip, userAgent)
}

func TestFetchIP_rejectsWrongFamilyAndMalformedResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
		isV6 bool
	}{
		{
			name: "IPv4 requested as IPv6",
			body: localIPv4,
			isV6: true,
		},
		{
			name: "IPv6 requested as IPv4",
			body: "ip=" + localIPv6 + "\n",
		},
		{
			name: "malformed plain text",
			body: "not-an-address\n",
		},
		{
			name: "malformed trace",
			body: "fl=local\nip=not-an-address\n",
			isV6: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			useLocalGeoIPClients(t)
			serverURL, observedUserAgent := newGeoIPContractServer(t, test.body)

			ip := fetchIP([]string{serverURL}, test.isV6)
			userAgent := <-observedUserAgent

			if ip != "" {
				t.Fatalf("address = %q, want empty", ip)
			}
			if userAgent != util.MacOSChromeUA {
				t.Fatalf("User-Agent = %q, want %q", userAgent, util.MacOSChromeUA)
			}
			t.Logf("rejected body=%q requestedIPv6=%t User-Agent=%q", test.body, test.isV6, userAgent)
		})
	}
}

func useLocalGeoIPClients(t *testing.T) {
	t.Helper()
	originalV4 := httpClientV4
	originalV6 := httpClientV6
	transport := &http.Transport{Proxy: nil}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}
	httpClientV4 = client
	httpClientV6 = client
	t.Cleanup(func() {
		httpClientV4 = originalV4
		httpClientV6 = originalV6
		transport.CloseIdleConnections()
	})
}

func newGeoIPContractServer(t *testing.T, body string) (string, <-chan string) {
	t.Helper()
	observedUserAgent := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		observedUserAgent <- request.UserAgent()
		if _, err := fmt.Fprint(response, body); err != nil {
			t.Errorf("write local GeoIP response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL, observedUserAgent
}
