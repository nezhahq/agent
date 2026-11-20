package utls

import (
	"net"
	"net/http"
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
