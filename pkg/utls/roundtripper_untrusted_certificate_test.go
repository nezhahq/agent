package utls_test

import (
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/nezhahq/agent/pkg/util"
	utlsx "github.com/nezhahq/agent/pkg/utls"
)

// TestUTLSRoundTripper_rejectsInvalidTLS only dials a plaintext server, which
// fails even when certificate verification is switched off. This test talks to
// a real TLS server whose certificate the client was never told to trust, so
// it fails if verification is ever disabled or skipped.
func TestUTLSRoundTripperRejectsUntrustedServerCertificate(t *testing.T) {
	var requestsServed atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requestsServed.Add(1)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	t.Cleanup(server.Close)

	newClient := func(tlsConfig *utls.Config) *http.Client {
		backdrop := &http.Transport{Proxy: nil}
		t.Cleanup(backdrop.CloseIdleConnections)
		return &http.Client{
			Transport: utlsx.NewUTLSHTTPRoundTripperWithProxy(
				utls.HelloChrome_Auto,
				tlsConfig,
				backdrop,
				nil,
				util.BrowserHeaders(),
			),
			Timeout: 5 * time.Second,
		}
	}

	response, err := newClient(new(utls.Config)).Get(server.URL)
	if err == nil {
		response.Body.Close()
		t.Fatal("GET succeeded against a certificate signed by an unknown authority")
	}
	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Fatalf("error = %v, want x509.UnknownAuthorityError", err)
	}
	if served := requestsServed.Load(); served != 0 {
		t.Fatalf("server handled %d requests over an unverified connection, want 0", served)
	}

	// Same server, same client code, certificate trusted: the rejection above
	// was caused by verification and not by an unrelated handshake problem.
	trustedRoots := x509.NewCertPool()
	trustedRoots.AddCert(server.Certificate())
	trustedResponse, err := newClient(&utls.Config{RootCAs: trustedRoots}).Get(server.URL)
	if err != nil {
		t.Fatalf("GET with the server certificate trusted: %v", err)
	}
	trustedResponse.Body.Close()
	if served := requestsServed.Load(); served != 1 {
		t.Fatalf("server handled %d requests after the trusted GET, want 1", served)
	}
}
