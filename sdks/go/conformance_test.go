package verification

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureCase struct {
	Name  string `json:"name"`
	Valid bool   `json:"valid"`
	Kind  string `json:"kind"`
	Error string `json:"error"`
	Token string `json:"token"`
}

type fixtureFile struct {
	Now         int64               `json:"now"`
	Issuer      string              `json:"issuer"`
	Audience    string              `json:"audience"`
	JWKS        json.RawMessage     `json:"jwks"`
	RotatedJWKS json.RawMessage     `json:"rotated_jwks"`
	JWksCases   []fixtureJWKSCase   `json:"jwks_cases"`
	Cases       []fixtureCase       `json:"cases"`
	RemoteCases []fixtureRemoteCase `json:"remote_cases"`
}

type fixtureJWKSCase struct {
	Name     string `json:"name"`
	Error    string `json:"error"`
	Token    string `json:"token"`
	JWKSJSON string `json:"jwks_json"`
}

type fixtureRemoteCase struct {
	Name                                 string `json:"name"`
	Token                                string `json:"token"`
	SequentialToken                      string `json:"sequential_token"`
	ConcurrentRequests                   int    `json:"concurrent_requests"`
	ExpectedFetches                      int32  `json:"expected_fetches"`
	CacheTTLSeconds                      int    `json:"cache_ttl_seconds"`
	NormalRefreshAfterSeconds            int    `json:"normal_refresh_after_seconds"`
	CooldownSeconds                      int    `json:"cooldown_seconds"`
	RepeatedRequestsAfterSeconds         int    `json:"repeated_requests_after_seconds"`
	RepeatedRequestsInsideCooldown       int    `json:"repeated_requests_inside_cooldown"`
	ExpectedFetchesBeforeNormalRefresh   int32  `json:"expected_fetches_before_normal_refresh"`
	ExpectedFetchesAfterRepeatedRequests int32  `json:"expected_fetches_after_repeated_requests"`
	ExpectedFetchesAfterNormalRefresh    int32  `json:"expected_fetches_after_normal_refresh"`
	ExpectedFetchesAfterRotation         int32  `json:"expected_fetches_after_rotation"`
	Error                                string `json:"error"`
}

func loadFixture(t *testing.T) fixtureFile {
	t.Helper()
	path := filepath.Join("..", "conformance", "fixture.json")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture fixtureFile
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestSharedConformance(t *testing.T) {
	fixture := loadFixture(t)
	for _, example := range fixture.Cases {
		t.Run(example.Name, func(t *testing.T) {
			claims, err := Verify(example.Token, fixture.JWKS, VerifyOptions{
				Issuer: fixture.Issuer, Audience: fixture.Audience,
				Now: time.Unix(fixture.Now, 0), ClockSkew: 0,
			})
			if example.Valid {
				if err != nil {
					t.Fatal(err)
				}
				if claims.Kind != example.Kind {
					t.Fatalf("kind = %q, want %q", claims.Kind, example.Kind)
				}
				return
			}
			var verificationError *VerificationError
			if !errors.As(err, &verificationError) {
				t.Fatalf("error = %#v, want VerificationError", err)
			}
			if string(verificationError.Code) != example.Error {
				t.Fatalf("code = %q, want %q", verificationError.Code, example.Error)
			}
		})
	}
	for _, example := range fixture.JWksCases {
		t.Run(example.Name, func(t *testing.T) {
			_, err := Verify(example.Token, []byte(example.JWKSJSON), VerifyOptions{
				Issuer: fixture.Issuer, Audience: fixture.Audience,
				Now: time.Unix(fixture.Now, 0), ClockSkew: 0,
			})
			var verificationError *VerificationError
			if !errors.As(err, &verificationError) {
				t.Fatalf("error = %#v, want VerificationError", err)
			}
			if string(verificationError.Code) != example.Error {
				t.Fatalf("code = %q, want %q", verificationError.Code, example.Error)
			}
		})
	}
}

func TestRemoteUnknownKidSingleflightAndURLValidation(t *testing.T) {
	fixture := loadFixture(t)
	if _, err := NewRemoteVerifier(RemoteOptions{
		Issuer: "http://127.attacker.example:8787", Audience: fixture.Audience,
		AllowInsecureLoopback: true,
	}); err == nil {
		t.Fatal("lookalike loopback hostname was accepted")
	}

	var requests atomic.Int32
	var responseBody atomic.Value
	responseBody.Store([]byte(fixture.JWKS))
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write(responseBody.Load().([]byte))
	}))
	defer server.Close()
	zero := time.Duration(0)
	verifier, err := NewRemoteVerifier(RemoteOptions{
		Issuer: fixture.Issuer, Audience: fixture.Audience, JWKSURL: server.URL,
		AllowInsecureLoopback: true, ClockSkew: &zero,
	})
	if err != nil {
		t.Fatal(err)
	}
	if verifier.options.ClockSkew != 0 {
		t.Fatalf("clock skew = %s, want zero", verifier.options.ClockSkew)
	}
	if len(fixture.RemoteCases) != 2 {
		t.Fatalf("remote cases = %d, want 2", len(fixture.RemoteCases))
	}
	remoteCase := fixture.RemoteCases[0]
	var wait sync.WaitGroup
	for range remoteCase.ConcurrentRequests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, verifyErr := verifier.Verify(context.Background(), remoteCase.Token)
			var verificationError *VerificationError
			if !errors.As(verifyErr, &verificationError) || string(verificationError.Code) != remoteCase.Error {
				t.Errorf("error = %#v, want %s", verifyErr, remoteCase.Error)
			}
		}()
	}
	wait.Wait()
	if requests.Load() != remoteCase.ExpectedFetches {
		t.Fatalf("requests = %d, want %d", requests.Load(), remoteCase.ExpectedFetches)
	}
	_, err = verifier.Verify(context.Background(), remoteCase.SequentialToken)
	var verificationError *VerificationError
	if !errors.As(err, &verificationError) || string(verificationError.Code) != remoteCase.Error {
		t.Fatalf("sequential error = %#v, want %s", err, remoteCase.Error)
	}
	if requests.Load() != remoteCase.ExpectedFetches {
		t.Fatalf("sequential requests = %d, want %d", requests.Load(), remoteCase.ExpectedFetches)
	}

	rotationCase := fixture.RemoteCases[1]
	rotationNow := time.Unix(fixture.Now, 0)
	requests.Store(0)
	responseBody.Store([]byte(fixture.JWKS))
	rotationVerifier, err := NewRemoteVerifier(RemoteOptions{
		Issuer: fixture.Issuer, Audience: fixture.Audience, JWKSURL: server.URL,
		AllowInsecureLoopback: true, ClockSkew: &zero,
		CacheTTL: time.Duration(rotationCase.CacheTTLSeconds) * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	rotationVerifier.now = func() time.Time { return rotationNow }
	_, err = rotationVerifier.Verify(context.Background(), rotationCase.Token)
	if !errors.As(err, &verificationError) || string(verificationError.Code) != rotationCase.Error {
		t.Fatalf("initial rotation error = %#v, want %s", err, rotationCase.Error)
	}
	if requests.Load() != rotationCase.ExpectedFetchesBeforeNormalRefresh {
		t.Fatalf("initial requests = %d, want %d", requests.Load(), rotationCase.ExpectedFetchesBeforeNormalRefresh)
	}
	rotationNow = rotationNow.Add(time.Duration(rotationCase.NormalRefreshAfterSeconds) * time.Second)
	if _, err = rotationVerifier.Verify(context.Background(), fixture.Cases[0].Token); err != nil {
		t.Fatalf("normal TTL refresh failed: %v", err)
	}
	if requests.Load() != rotationCase.ExpectedFetchesAfterNormalRefresh {
		t.Fatalf("normal refresh requests = %d, want %d", requests.Load(), rotationCase.ExpectedFetchesAfterNormalRefresh)
	}
	rotationNow = time.Unix(fixture.Now+int64(rotationCase.RepeatedRequestsAfterSeconds), 0)
	for range rotationCase.RepeatedRequestsInsideCooldown {
		_, err = rotationVerifier.Verify(context.Background(), rotationCase.Token)
		if !errors.As(err, &verificationError) || string(verificationError.Code) != rotationCase.Error {
			t.Fatalf("repeated rotation error = %#v, want %s", err, rotationCase.Error)
		}
	}
	if requests.Load() != rotationCase.ExpectedFetchesAfterRepeatedRequests {
		t.Fatalf("repeated requests = %d, want %d", requests.Load(), rotationCase.ExpectedFetchesAfterRepeatedRequests)
	}
	responseBody.Store([]byte(fixture.RotatedJWKS))
	rotationNow = time.Unix(fixture.Now+int64(rotationCase.CooldownSeconds), 0)
	if _, err = rotationVerifier.Verify(context.Background(), rotationCase.Token); err != nil {
		t.Fatalf("rotated key did not recover: %v", err)
	}
	if requests.Load() != rotationCase.ExpectedFetchesAfterRotation {
		t.Fatalf("rotation requests = %d, want %d", requests.Load(), rotationCase.ExpectedFetchesAfterRotation)
	}
}
