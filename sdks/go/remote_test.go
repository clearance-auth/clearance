package verification

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSecureURLAllowsOnlyLoopbackHTTP(t *testing.T) {
	for _, value := range []string{
		"http://127.0.0.1:8080",
		"http://127.42.0.1",
		"http://[::1]:8080",
		"http://localhost:8080",
	} {
		if _, err := secureURL(value, true); err != nil {
			t.Errorf("secureURL(%q) rejected a loopback development URL: %v", value, err)
		}
	}
	if _, err := secureURL("http://api.localhost:8080", true); err == nil {
		t.Error("secureURL accepted a localhost lookalike")
	}
	for _, value := range []string{"http://128.0.0.1", "http://example.com", "http://[::ffff:127.0.0.1]"} {
		if _, err := secureURL(value, true); err == nil {
			t.Errorf("secureURL(%q) accepted a non-loopback HTTP URL", value)
		}
	}
}

func TestUnknownKidsRefreshOncePerGeneration(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "conformance", "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var payload struct {
		JWKS json.RawMessage `json:"jwks"`
	}
	if err := json.Unmarshal(fixture, &payload); err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(payload.JWKS)
	}))
	defer server.Close()
	v, err := NewRemoteVerifier(RemoteOptions{
		Issuer: server.URL, JWKSURL: server.URL, AllowInsecureLoopback: true,
		Audience: "https://api.example.com", CacheTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, generation, _, err := v.load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.loadUnknown(context.Background(), "missing-one", generation); err != nil {
		t.Fatal(err)
	}
	if _, err := v.loadUnknown(context.Background(), "missing-two", generation+1); err == nil {
		t.Fatal("second unknown kid unexpectedly refreshed the current generation")
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want initial load plus one rotation refresh", requests)
	}
}
