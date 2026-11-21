package utls

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// stalledTLSServer accepts TCP connections and never answers the ClientHello.
func stalledTLSServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var accepted []net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted = append(accepted, conn)
		}
	}()
	t.Cleanup(func() {
		listener.Close()
		<-done
		for _, conn := range accepted {
			conn.Close()
		}
	})
	return listener.Addr().String()
}

func roundTripWithin(t *testing.T, transport http.RoundTripper, url string, limit time.Duration) error {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	result := make(chan error, 1)
	go func() {
		response, err := transport.RoundTrip(request)
		if err == nil {
			response.Body.Close()
		}
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-time.After(limit):
		t.Fatalf("request to %s did not return within %s", url, limit)
		return nil
	}
}

// The dial runs under a lock shared by every HTTPS probe. A handshake without
// a deadline against a peer that never answers held that lock for ever, so
// one such target silently stopped all HTTPS monitoring until restart.
func TestRoundTrip_StalledHandshakeDoesNotBlockLaterRequests(t *testing.T) {
	originalTimeout := tlsDialTimeout
	t.Cleanup(func() { tlsDialTimeout = originalTimeout })
	tlsDialTimeout = 300 * time.Millisecond

	transport := NewUTLSHTTPRoundTripperWithProxy(utls.HelloChrome_Auto, &utls.Config{InsecureSkipVerify: true}, http.DefaultTransport, nil, http.Header{})
	stalled := "https://" + stalledTLSServer(t) + "/"

	if err := roundTripWithin(t, transport, stalled, 5*time.Second); err == nil {
		t.Fatal("request to a peer that never completes the handshake succeeded")
	}
	// The second request needs the same lock. It must fail on its own
	// deadline, not wait behind the first one.
	if err := roundTripWithin(t, transport, "https://"+stalledTLSServer(t)+"/", 5*time.Second); err == nil {
		t.Fatal("second request to a stalled peer succeeded")
	}
}

// With the deadline in place a stalled peer still held the shared lock for the
// whole handshake timeout, so every other HTTPS probe queued behind it for 20
// seconds per round. A healthy target must be reached while another handshake
// is still hanging.
func TestRoundTrip_HealthyTargetIsNotQueuedBehindStalledHandshake(t *testing.T) {
	originalTimeout := tlsDialTimeout
	t.Cleanup(func() { tlsDialTimeout = originalTimeout })
	tlsDialTimeout = 4 * time.Second

	healthy := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(healthy.Close)
	transport := NewUTLSHTTPRoundTripperWithProxy(utls.HelloChrome_Auto, &utls.Config{InsecureSkipVerify: true}, http.DefaultTransport, nil, http.Header{})

	stalledRequest, err := http.NewRequest(http.MethodGet, "https://"+stalledTLSServer(t)+"/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	stalledFinished := make(chan struct{})
	go func() {
		defer close(stalledFinished)
		if response, err := transport.RoundTrip(stalledRequest); err == nil {
			response.Body.Close()
		}
	}()
	t.Cleanup(func() { <-stalledFinished })
	// Give the stalled dial time to be in its handshake.
	time.Sleep(300 * time.Millisecond)

	started := time.Now()
	if err := roundTripWithin(t, transport, healthy.URL, 2*time.Second); err != nil {
		t.Fatalf("request to the healthy target failed: %v", err)
	}
	select {
	case <-stalledFinished:
		t.Fatal("test setup: the stalled handshake ended before the healthy request was measured")
	default:
	}
	t.Logf("healthy target answered in %s while another handshake was hanging", time.Since(started))
}
