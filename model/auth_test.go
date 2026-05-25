package model

import (
	"context"
	"sync/atomic"
	"testing"
)

// AuthHandler reads the credentials on every gRPC call via the closures, not
// once at construction. The dashboard rotates ClientSecret during a server
// transfer; if the agent cached the credential at startup, the next reconnect
// would still present the old secret and never succeed.
func TestAuthHandlerReadsCredentialsPerCall(t *testing.T) {
	secret := "old-secret"
	uuid := "agent-uuid"

	a := &AuthHandler{
		Credentials: func() (string, string) { return secret, uuid },
	}

	md, err := a.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if md["client_secret"] != "old-secret" {
		t.Fatalf("expected old-secret, got %q", md["client_secret"])
	}

	// Rotate the credential the way handleApplyConfigTask's reload would after
	// the save-then-swap completes.
	secret = "new-secret"

	md, err = a.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if md["client_secret"] != "new-secret" {
		t.Fatalf("AuthHandler must read the closure on every call to pick up rotation, got %q", md["client_secret"])
	}
}

// TestAuthHandlerCoherentCredentialPair pins the invariant that one
// GetRequestMetadata call returns a (secret, uuid) pair from a single snapshot.
// Splitting the read across two separate snapshot loads (as the old AuthHandler
// did) can hand the dashboard a mixed (oldUUID, newSecret) pair during a
// transfer rotation, causing authentication failures.
func TestAuthHandlerCoherentCredentialPair(t *testing.T) {
	// Use a single atomic that flips both fields together so a torn read is
	// directly observable as a mismatch.
	type pair struct {
		secret string
		uuid   string
	}
	current := &atomic.Pointer[pair]{}
	current.Store(&pair{secret: "secret-A", uuid: "uuid-A"})

	a := &AuthHandler{
		Credentials: func() (string, string) {
			p := current.Load()
			return p.secret, p.uuid
		},
	}

	stop := make(chan struct{})
	defer close(stop)
	go func() {
		flip := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			if flip {
				current.Store(&pair{secret: "secret-A", uuid: "uuid-A"})
			} else {
				current.Store(&pair{secret: "secret-B", uuid: "uuid-B"})
			}
			flip = !flip
		}
	}()

	for i := 0; i < 100000; i++ {
		md, err := a.GetRequestMetadata(context.Background())
		if err != nil {
			t.Fatalf("GetRequestMetadata: %v", err)
		}
		s, u := md["client_secret"], md["client_uuid"]
		if (s == "secret-A" && u != "uuid-A") || (s == "secret-B" && u != "uuid-B") {
			t.Fatalf("torn credential pair: secret=%q uuid=%q (must come from a single snapshot)", s, u)
		}
	}
}

// AuthHandler.GetRequestMetadata must not panic on a zero-value or
// nil-Credentials handler. A panic inside grpc-go's metadata callback
// would propagate up the dial stack and crash the unattended agent
// process, masking the misconfiguration as a generic runtime failure.
func TestAuthHandlerGetRequestMetadataNilSafe(t *testing.T) {
	var nilHandler *AuthHandler
	if _, err := nilHandler.GetRequestMetadata(context.Background()); err == nil {
		t.Fatal("nil receiver must return an error, not nil")
	}

	zero := &AuthHandler{}
	if _, err := zero.GetRequestMetadata(context.Background()); err == nil {
		t.Fatal("zero-value AuthHandler (no Credentials closure) must return an error, not panic")
	}
}
