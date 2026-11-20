package monitor

import (
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
)

type failingGeoIPBody struct {
	closed *atomic.Bool
}

func (b failingGeoIPBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (b failingGeoIPBody) Close() error             { b.closed.Store(true); return nil }

type geoIPRoundTripper func(*http.Request) (*http.Response, error)

func (f geoIPRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func useGeoIPTransport(t *testing.T, transport http.RoundTripper) {
	t.Helper()
	originalClient := httpClientV4
	t.Cleanup(func() { httpClientV4 = originalClient })
	httpClientV4 = &http.Client{Transport: transport}
}

// A body that is never closed pins its connection (and goroutines) forever;
// the IP lookup runs for the lifetime of the agent.
func TestFetchIP_ClosesBodyWhenReadFails(t *testing.T) {
	var closed atomic.Bool
	useGeoIPTransport(t, geoIPRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: failingGeoIPBody{closed: &closed}}, nil
	}))

	ip := fetchIP([]string{"http://geoip.example/trace"}, false)

	if ip != "" {
		t.Fatalf("ip = %q, want empty when the body cannot be read", ip)
	}
	if !closed.Load() {
		t.Fatal("response body was not closed after the read failed")
	}
}

type endlessGeoIPBody struct {
	served int
}

func (b *endlessGeoIPBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.served += len(p)
	return len(p), nil
}
func (b *endlessGeoIPBody) Close() error { return nil }

func TestFetchIP_StopsReadingOversizedBody(t *testing.T) {
	body := &endlessGeoIPBody{}
	useGeoIPTransport(t, geoIPRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(body)}, nil
	}))

	ip := fetchIP([]string{"http://geoip.example/trace"}, false)

	if ip != "" {
		t.Fatalf("ip = %q, want empty for a body that is not an address", ip)
	}
	if body.served > 2*geoIPResponseBodyLimit {
		t.Fatalf("read %d bytes from an endless body, want at most about %d", body.served, geoIPResponseBodyLimit)
	}
}
