package utls_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/nezhahq/agent/pkg/util"
	utlsx "github.com/nezhahq/agent/pkg/utls"
)

type tlsRequestObservation struct {
	userAgent string
	alpn      string
	protocol  string
}

func TestUTLSRoundTripper_rejectsInvalidTLS(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()
	t.Cleanup(server.Close)

	backdrop := &http.Transport{Proxy: nil}
	t.Cleanup(backdrop.CloseIdleConnections)
	client := &http.Client{
		Transport: utlsx.NewUTLSHTTPRoundTripperWithProxy(
			utls.HelloChrome_Auto,
			new(utls.Config),
			backdrop,
			nil,
			util.BrowserHeaders(),
		),
		Timeout: 5 * time.Second,
	}
	invalidTLSURL := strings.Replace(server.URL, "http://", "https://", 1)

	response, err := client.Get(invalidTLSURL)

	if err == nil {
		response.Body.Close()
		t.Fatal("GET plaintext server over TLS succeeded, want handshake error")
	}
	if response != nil {
		response.Body.Close()
		t.Fatalf("response = %#v, want nil after handshake error", response)
	}
	t.Logf("invalid TLS rejected with error=%q", err)
}

func TestUTLSRoundTripper_selectsOrdinaryHTTPProtocol(t *testing.T) {
	tests := []struct {
		name          string
		enableHTTP2   bool
		nextProtocols []string
		wantALPN      string
		wantProtocol  string
	}{
		{
			name:          "HTTP/1.1",
			nextProtocols: []string{"http/1.1"},
			wantALPN:      "http/1.1",
			wantProtocol:  "HTTP/1.1",
		},
		{
			name:          "HTTP/2",
			enableHTTP2:   true,
			nextProtocols: []string{"h2", "http/1.1"},
			wantALPN:      "h2",
			wantProtocol:  "HTTP/2.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observed := make(chan tlsRequestObservation, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				observed <- tlsRequestObservation{
					userAgent: request.UserAgent(),
					alpn:      request.TLS.NegotiatedProtocol,
					protocol:  request.Proto,
				}
				_, err := response.Write([]byte("local tls response"))
				if err != nil {
					t.Errorf("write local TLS response: %v", err)
				}
			}))
			server.EnableHTTP2 = test.enableHTTP2
			server.TLS = &tls.Config{NextProtos: test.nextProtocols}
			server.StartTLS()
			t.Cleanup(func() {
				server.CloseClientConnections()
				server.Close()
			})

			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			backdrop := &http.Transport{Proxy: nil}
			t.Cleanup(backdrop.CloseIdleConnections)
			client := &http.Client{
				Transport: utlsx.NewUTLSHTTPRoundTripperWithProxy(
					utls.HelloChrome_Auto,
					&utls.Config{RootCAs: roots},
					backdrop,
					nil,
					util.BrowserHeaders(),
				),
				Timeout: 5 * time.Second,
			}

			response, err := client.Get(server.URL)
			if err != nil {
				t.Fatalf("GET local TLS server: %v", err)
			}
			t.Cleanup(func() { response.Body.Close() })
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatalf("read local TLS response: %v", err)
			}
			observation := <-observed

			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusOK)
			}
			if string(body) != "local tls response" {
				t.Fatalf("body = %q, want %q", body, "local tls response")
			}
			if observation.userAgent != util.MacOSChromeUA {
				t.Fatalf("User-Agent = %q, want %q", observation.userAgent, util.MacOSChromeUA)
			}
			if observation.alpn != test.wantALPN {
				t.Fatalf("ALPN = %q, want %q", observation.alpn, test.wantALPN)
			}
			if observation.protocol != test.wantProtocol {
				t.Fatalf("protocol = %q, want %q", observation.protocol, test.wantProtocol)
			}
			t.Logf("observed User-Agent=%q ALPN=%q protocol=%q body=%q", observation.userAgent, observation.alpn, observation.protocol, body)
		})
	}
}
