// Package verification strictly verifies Clearance ES256 access tokens.
package verification

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	SessionDerivativeAuthority = "urn:clearance:claims:session-derivative-authority"
	SessionSourceSubject       = "urn:clearance:claims:session-source-subject"
	SessionSourceOrganization  = "urn:clearance:claims:session-source-organization"
	SubjectKind                = "urn:clearance:claims:subject-kind"
	OrganizationID             = "urn:clearance:claims:organization-id"
	Actions                    = "actions"
	AuthorizationRevision      = "authz_revision"
	unknownMissTTL             = 30 * time.Second
	maxUnknownMisses           = 128
)

type ErrorCode string

const (
	ErrTokenMalformed       ErrorCode = "token_malformed"
	ErrAlgorithmRejected    ErrorCode = "algorithm_rejected"
	ErrKeyNotFound          ErrorCode = "key_not_found"
	ErrJWKSInvalid          ErrorCode = "jwks_invalid"
	ErrJWKSUnavailable      ErrorCode = "jwks_unavailable"
	ErrSignatureInvalid     ErrorCode = "signature_invalid"
	ErrIssuerMismatch       ErrorCode = "issuer_mismatch"
	ErrAudienceMismatch     ErrorCode = "audience_mismatch"
	ErrTokenExpired         ErrorCode = "token_expired"
	ErrTokenNotActive       ErrorCode = "token_not_active"
	ErrClaimsInvalid        ErrorCode = "claims_invalid"
	ErrConfigurationInvalid ErrorCode = "configuration_invalid"
)

var errorMessages = map[ErrorCode]string{
	ErrTokenMalformed:       "Access token is malformed",
	ErrAlgorithmRejected:    "Access token algorithm is not allowed",
	ErrKeyNotFound:          "Access token verification key was not found",
	ErrJWKSInvalid:          "Verification key set is invalid",
	ErrJWKSUnavailable:      "Verification key set is unavailable",
	ErrSignatureInvalid:     "Access token signature is invalid",
	ErrIssuerMismatch:       "Access token issuer does not match",
	ErrAudienceMismatch:     "Access token audience does not match",
	ErrTokenExpired:         "Access token has expired",
	ErrTokenNotActive:       "Access token is not active",
	ErrClaimsInvalid:        "Access token claims are invalid",
	ErrConfigurationInvalid: "Verifier configuration is invalid",
}

type VerificationError struct{ Code ErrorCode }

func (e *VerificationError) Error() string { return errorMessages[e.Code] }
func fail(code ErrorCode) error            { return &VerificationError{Code: code} }

type Claims struct {
	Subject                    string
	Kind                       string
	Issuer                     string
	Audience                   []string
	ExpiresAt                  int64
	IssuedAt                   int64
	NotBefore                  *int64
	OrganizationID             string
	Actions                    []string
	AuthorizationRevision      string
	SessionDerivativeAuthority string
	SourceSubjectID            string
	SourceOrganizationID       *string
	Raw                        map[string]any
}

type VerifyOptions struct {
	Issuer    string
	Audience  string
	ClockSkew time.Duration
	Now       time.Time
}

type publicKey struct {
	kid string
	key *ecdsa.PublicKey
}

var (
	base64URLPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	kidPattern       = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	actionPattern    = regexp.MustCompile(`^[a-z][a-z0-9._:-]{0,127}$`)
	revisionPattern  = regexp.MustCompile(`^[1-9][0-9]*$`)
	maxRevision      = new(big.Int).SetUint64(9_223_372_036_854_775_807)
)

func decodeBase64URL(value string, code ErrorCode) ([]byte, error) {
	if value == "" || strings.Contains(value, "=") || !base64URLPattern.MatchString(value) || len(value)%4 == 1 {
		return nil, fail(code)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fail(code)
	}
	return decoded, nil
}

func parseJSON(raw []byte, code ErrorCode) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := parseJSONValue(decoder, code)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fail(code)
	}
	return value, nil
}

func parseJSONValue(decoder *json.Decoder, code ErrorCode) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, fail(code)
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return nil, fail(code)
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fail(code)
			}
			value, err := parseJSONValue(decoder, code)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return nil, fail(code)
		}
		return object, nil
	case '[':
		array := []any{}
		for decoder.More() {
			value, err := parseJSONValue(decoder, code)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return nil, fail(code)
		}
		return array, nil
	default:
		return nil, fail(code)
	}
}

type parsedToken struct {
	header       map[string]any
	payload      map[string]any
	signingInput []byte
	signature    []byte
}

func parseToken(token string) (*parsedToken, error) {
	if len([]byte(token)) > 16_384 {
		return nil, fail(ErrTokenMalformed)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, fail(ErrTokenMalformed)
	}
	headerBytes, err := decodeBase64URL(parts[0], ErrTokenMalformed)
	if err != nil || len(headerBytes) > 12_288 {
		return nil, fail(ErrTokenMalformed)
	}
	headerValue, err := parseJSON(headerBytes, ErrTokenMalformed)
	header, ok := headerValue.(map[string]any)
	if err != nil || !ok {
		return nil, fail(ErrTokenMalformed)
	}
	if header["alg"] != "ES256" {
		return nil, fail(ErrAlgorithmRejected)
	}
	kid, kidOK := header["kid"].(string)
	if !kidOK || !kidPattern.MatchString(kid) || (header["typ"] != nil && header["typ"] != "JWT") {
		return nil, fail(ErrTokenMalformed)
	}
	for key := range header {
		if key != "alg" && key != "kid" && key != "typ" {
			return nil, fail(ErrTokenMalformed)
		}
	}
	payloadBytes, err := decodeBase64URL(parts[1], ErrTokenMalformed)
	if err != nil || len(payloadBytes) > 12_288 {
		return nil, fail(ErrTokenMalformed)
	}
	payloadValue, err := parseJSON(payloadBytes, ErrTokenMalformed)
	payload, ok := payloadValue.(map[string]any)
	if err != nil || !ok {
		return nil, fail(ErrTokenMalformed)
	}
	signature, err := decodeBase64URL(parts[2], ErrTokenMalformed)
	if err != nil {
		return nil, fail(ErrTokenMalformed)
	}
	if len(signature) != 64 {
		return nil, fail(ErrSignatureInvalid)
	}
	return &parsedToken{
		header:       header,
		payload:      payload,
		signingInput: []byte(parts[0] + "." + parts[1]),
		signature:    signature,
	}, nil
}

func parseJWKS(value any) ([]publicKey, error) {
	root, ok := value.(map[string]any)
	if !ok {
		return nil, fail(ErrJWKSInvalid)
	}
	values, ok := root["keys"].([]any)
	if !ok || len(values) < 1 || len(values) > 32 {
		return nil, fail(ErrJWKSInvalid)
	}
	seen := map[string]bool{}
	keys := make([]publicKey, 0, len(values))
	for _, value := range values {
		jwk, ok := value.(map[string]any)
		allowed := map[string]bool{
			"kty": true, "crv": true, "x": true, "y": true,
			"kid": true, "use": true, "alg": true, "key_ops": true,
		}
		for member := range jwk {
			if !allowed[member] {
				return nil, fail(ErrJWKSInvalid)
			}
		}
		kid, kidOK := jwk["kid"].(string)
		xValue, xOK := jwk["x"].(string)
		yValue, yOK := jwk["y"].(string)
		if !ok || !kidOK || !xOK || !yOK ||
			jwk["kty"] != "EC" || jwk["crv"] != "P-256" ||
			jwk["use"] != "sig" || jwk["alg"] != "ES256" ||
			!kidPattern.MatchString(kid) || seen[kid] {
			return nil, fail(ErrJWKSInvalid)
		}
		if _, private := jwk["d"]; private {
			return nil, fail(ErrJWKSInvalid)
		}
		if operations, present := jwk["key_ops"]; present {
			list, ok := operations.([]any)
			if !ok || len(list) != 1 || list[0] != "verify" {
				return nil, fail(ErrJWKSInvalid)
			}
		}
		xBytes, xErr := decodeBase64URL(xValue, ErrJWKSInvalid)
		yBytes, yErr := decodeBase64URL(yValue, ErrJWKSInvalid)
		if xErr != nil || yErr != nil || len(xBytes) != 32 || len(yBytes) != 32 {
			return nil, fail(ErrJWKSInvalid)
		}
		x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
		if !elliptic.P256().IsOnCurve(x, y) {
			return nil, fail(ErrJWKSInvalid)
		}
		seen[kid] = true
		keys = append(keys, publicKey{kid: kid, key: &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}})
	}
	return keys, nil
}

func validateOptions(options VerifyOptions) (time.Time, error) {
	if options.Issuer == "" || options.Audience == "" || options.ClockSkew < 0 || options.ClockSkew > 5*time.Minute {
		return time.Time{}, fail(ErrConfigurationInvalid)
	}
	now := options.Now
	if now.IsZero() {
		now = time.Now()
	}
	if now.Unix() < 0 {
		return time.Time{}, fail(ErrConfigurationInvalid)
	}
	return now, nil
}

func exactInt(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok || strings.ContainsAny(string(number), ".eE") {
		return 0, false
	}
	integer, err := number.Int64()
	return integer, err == nil
}

func stringValue(value any) (string, bool) {
	text, ok := value.(string)
	return text, ok && text != ""
}

func parseActions(value any) ([]string, error) {
	values, ok := value.([]any)
	if !ok || len(values) > 256 {
		return nil, fail(ErrClaimsInvalid)
	}
	actions := make([]string, len(values))
	for index, value := range values {
		action, ok := value.(string)
		if !ok || !actionPattern.MatchString(action) || (index > 0 && action <= actions[index-1]) {
			return nil, fail(ErrClaimsInvalid)
		}
		actions[index] = action
	}
	return actions, nil
}

func parseRevision(value any) (string, error) {
	revision, ok := value.(string)
	if !ok || !revisionPattern.MatchString(revision) {
		return "", fail(ErrClaimsInvalid)
	}
	parsed, ok := new(big.Int).SetString(revision, 10)
	if !ok || parsed.Cmp(maxRevision) > 0 {
		return "", fail(ErrClaimsInvalid)
	}
	return revision, nil
}

func validateClaims(payload map[string]any, options VerifyOptions, now time.Time) (*Claims, error) {
	if payload["iss"] != options.Issuer {
		return nil, fail(ErrIssuerMismatch)
	}
	audiences := []string{}
	switch audience := payload["aud"].(type) {
	case string:
		if audience == "" {
			return nil, fail(ErrAudienceMismatch)
		}
		audiences = append(audiences, audience)
	case []any:
		if len(audience) == 0 {
			return nil, fail(ErrAudienceMismatch)
		}
		for _, item := range audience {
			text, ok := stringValue(item)
			if !ok {
				return nil, fail(ErrAudienceMismatch)
			}
			audiences = append(audiences, text)
		}
	default:
		return nil, fail(ErrAudienceMismatch)
	}
	audienceMatch := false
	for _, audience := range audiences {
		audienceMatch = audienceMatch || audience == options.Audience
	}
	if !audienceMatch {
		return nil, fail(ErrAudienceMismatch)
	}
	subject, subjectOK := stringValue(payload["sub"])
	exp, expOK := exactInt(payload["exp"])
	iat, iatOK := exactInt(payload["iat"])
	var nbf *int64
	if value, present := payload["nbf"]; present {
		parsed, ok := exactInt(value)
		if !ok {
			return nil, fail(ErrClaimsInvalid)
		}
		nbf = &parsed
	}
	if !subjectOK || !expOK || !iatOK || exp <= iat || exp-iat > 300 {
		return nil, fail(ErrClaimsInvalid)
	}
	skew := int64(options.ClockSkew / time.Second)
	if exp <= now.Unix()-skew {
		return nil, fail(ErrTokenExpired)
	}
	if (nbf != nil && *nbf > now.Unix()+skew) || iat > now.Unix()+skew {
		return nil, fail(ErrTokenNotActive)
	}

	_, hasActions := payload[Actions]
	_, hasRevision := payload[AuthorizationRevision]
	if hasActions != hasRevision {
		return nil, fail(ErrClaimsInvalid)
	}
	actions := []string{}
	revision := ""
	var err error
	if hasActions {
		if actions, err = parseActions(payload[Actions]); err != nil {
			return nil, err
		}
		if revision, err = parseRevision(payload[AuthorizationRevision]); err != nil {
			return nil, err
		}
	}
	_, hasKind := payload[SubjectKind]
	_, hasOrganization := payload[OrganizationID]
	if hasKind != hasOrganization {
		return nil, fail(ErrClaimsInvalid)
	}
	_, hasBinding := payload[SessionDerivativeAuthority]
	_, hasSourceSubject := payload[SessionSourceSubject]
	_, hasSourceOrganization := payload[SessionSourceOrganization]
	if hasBinding != hasSourceSubject || hasBinding != hasSourceOrganization {
		return nil, fail(ErrClaimsInvalid)
	}
	claims := &Claims{
		Subject: subject, Issuer: options.Issuer, Audience: audiences,
		ExpiresAt: exp, IssuedAt: iat, NotBefore: nbf, Actions: actions,
		AuthorizationRevision: revision, Raw: payload,
	}
	if hasKind {
		organization, ok := stringValue(payload[OrganizationID])
		if payload[SubjectKind] != "service_account" || !ok || !hasActions || hasBinding {
			return nil, fail(ErrClaimsInvalid)
		}
		claims.Kind, claims.OrganizationID = "service_account", organization
		return claims, nil
	}
	if hasActions && !hasBinding {
		return nil, fail(ErrClaimsInvalid)
	}
	if hasBinding {
		binding, bindingOK := stringValue(payload[SessionDerivativeAuthority])
		sourceSubject, sourceOK := stringValue(payload[SessionSourceSubject])
		var sourceOrganization *string
		if payload[SessionSourceOrganization] != nil {
			organization, ok := stringValue(payload[SessionSourceOrganization])
			if !ok {
				return nil, fail(ErrClaimsInvalid)
			}
			sourceOrganization = &organization
		}
		if !bindingOK || !sourceOK {
			return nil, fail(ErrClaimsInvalid)
		}
		if hasActions && sourceOrganization == nil {
			return nil, fail(ErrClaimsInvalid)
		}
		claims.SessionDerivativeAuthority = binding
		claims.SourceSubjectID = sourceSubject
		claims.SourceOrganizationID = sourceOrganization
	}
	claims.Kind = "human"
	return claims, nil
}

func verifyParsed(parsed *parsedToken, keys []publicKey, options VerifyOptions, now time.Time) (*Claims, error) {
	kid := parsed.header["kid"].(string)
	var key *ecdsa.PublicKey
	for _, candidate := range keys {
		if candidate.kid == kid {
			key = candidate.key
			break
		}
	}
	if key == nil {
		return nil, fail(ErrKeyNotFound)
	}
	digest := sha256.Sum256(parsed.signingInput)
	r := new(big.Int).SetBytes(parsed.signature[:32])
	s := new(big.Int).SetBytes(parsed.signature[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return nil, fail(ErrSignatureInvalid)
	}
	return validateClaims(parsed.payload, options, now)
}

func Verify(token string, jwks []byte, options VerifyOptions) (*Claims, error) {
	now, err := validateOptions(options)
	if err != nil {
		return nil, err
	}
	parsed, err := parseToken(token)
	if err != nil {
		return nil, err
	}
	value, err := parseJSON(jwks, ErrJWKSInvalid)
	if err != nil {
		return nil, err
	}
	keys, err := parseJWKS(value)
	if err != nil {
		return nil, err
	}
	return verifyParsed(parsed, keys, options, now)
}

type RemoteOptions struct {
	Issuer   string
	Audience string
	JWKSURL  string
	// AllowInsecureLoopback permits HTTP only for loopback development endpoints.
	AllowInsecureLoopback bool
	// ClockSkew defaults to 30 seconds. Point to Duration(0) for strict zero skew.
	ClockSkew        *time.Duration
	FetchTimeout     time.Duration
	MaxResponseBytes int64
	CacheTTL         time.Duration
	HTTPClient       *http.Client
}

type RemoteVerifier struct {
	options              VerifyOptions
	jwksURL              string
	client               *http.Client
	maxBytes             int64
	cacheTTL             time.Duration
	mu                   sync.Mutex
	keys                 []publicKey
	expires              time.Time
	generation           uint64
	nextUnknownRefreshAt time.Time
	unknownMisses        map[string]time.Time
	now                  func() time.Time
}

func secureURL(value string, allowInsecureLoopback bool) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return "", fail(ErrConfigurationInvalid)
	}
	host := strings.ToLower(parsed.Hostname())
	ip := net.ParseIP(host)
	loopback := host == "localhost" ||
		(ip != nil && ((ip.To4() != nil && !strings.Contains(host, ":") && ip.To4()[0] == 127) || ip.Equal(net.IPv6loopback)))
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && allowInsecureLoopback && loopback) {
		return "", fail(ErrConfigurationInvalid)
	}
	return parsed.String(), nil
}

func NewRemoteVerifier(options RemoteOptions) (*RemoteVerifier, error) {
	clockSkew := 30 * time.Second
	if options.ClockSkew != nil {
		clockSkew = *options.ClockSkew
	}
	if _, err := validateOptions(VerifyOptions{Issuer: options.Issuer, Audience: options.Audience, ClockSkew: clockSkew}); err != nil {
		return nil, err
	}
	issuer, err := secureURL(options.Issuer, options.AllowInsecureLoopback)
	if err != nil {
		return nil, err
	}
	jwksURL := options.JWKSURL
	if jwksURL == "" {
		base, _ := url.Parse(issuer)
		jwksURL = base.ResolveReference(&url.URL{Path: "/api/auth/jwks"}).String()
	}
	if jwksURL, err = secureURL(jwksURL, options.AllowInsecureLoopback); err != nil {
		return nil, err
	}
	timeout := options.FetchTimeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	maxBytes := options.MaxResponseBytes
	if maxBytes == 0 {
		maxBytes = 1_048_576
	}
	ttl := options.CacheTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	if timeout < 100*time.Millisecond || timeout > 30*time.Second || maxBytes < 1_024 || maxBytes > 4_194_304 || ttl < time.Second || ttl > time.Hour {
		return nil, fail(ErrConfigurationInvalid)
	}
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{}
	} else {
		// Preserve an injected transport (for proxies or tests), while keeping the
		// verifier's timeout and no-redirect invariants under its control.
		copy := *client
		client = &copy
	}
	client.Timeout = timeout
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &RemoteVerifier{
		options: VerifyOptions{Issuer: options.Issuer, Audience: options.Audience, ClockSkew: clockSkew},
		jwksURL: jwksURL, client: client, maxBytes: maxBytes, cacheTTL: ttl, now: time.Now,
	}, nil
}

func (v *RemoteVerifier) ClearCache() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keys, v.expires = nil, time.Time{}
	v.generation = 0
	v.nextUnknownRefreshAt = time.Time{}
	v.unknownMisses = nil
}

func (v *RemoteVerifier) load(ctx context.Context) ([]publicKey, uint64, bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.keys != nil && v.now().Before(v.expires) {
		return v.keys, v.generation, false, nil
	}
	keys, err := v.fetchLocked(ctx)
	return keys, v.generation, true, err
}

func (v *RemoteVerifier) loadUnknown(ctx context.Context, kid string, observedGeneration uint64) ([]publicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if containsKey(v.keys, kid) {
		return v.keys, nil
	}
	now := v.now()
	v.pruneUnknownMissesLocked(now)
	if until, known := v.unknownMisses[kid]; known && now.Before(until) {
		return nil, fail(ErrKeyNotFound)
	}
	if v.generation != observedGeneration || now.Before(v.nextUnknownRefreshAt) {
		v.rememberUnknownMissLocked(kid, now)
		return nil, fail(ErrKeyNotFound)
	}
	v.nextUnknownRefreshAt = now.Add(unknownMissTTL)
	keys, err := v.fetchLocked(ctx)
	if err != nil {
		return nil, err
	}
	if !containsKey(keys, kid) {
		v.rememberUnknownMissLocked(kid, now)
	}
	return keys, nil
}

func containsKey(keys []publicKey, kid string) bool {
	for _, key := range keys {
		if key.kid == kid {
			return true
		}
	}
	return false
}

func (v *RemoteVerifier) rememberUnknownMissLocked(kid string, now time.Time) {
	v.pruneUnknownMissesLocked(now)
	if v.unknownMisses == nil {
		v.unknownMisses = make(map[string]time.Time)
	}
	if _, exists := v.unknownMisses[kid]; exists {
		return
	}
	if _, exists := v.unknownMisses[kid]; !exists && len(v.unknownMisses) >= maxUnknownMisses {
		for candidate := range v.unknownMisses {
			delete(v.unknownMisses, candidate)
			break
		}
	}
	v.unknownMisses[kid] = now.Add(unknownMissTTL)
}

func (v *RemoteVerifier) pruneUnknownMissesLocked(now time.Time) {
	for kid, until := range v.unknownMisses {
		if !now.Before(until) {
			delete(v.unknownMisses, kid)
		}
	}
}

func (v *RemoteVerifier) fetchLocked(ctx context.Context) ([]publicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return nil, fail(ErrJWKSUnavailable)
	}
	request.Header.Set("Accept", "application/json")
	response, err := v.client.Do(request)
	if err != nil {
		return nil, fail(ErrJWKSUnavailable)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 ||
		(response.ContentLength >= 0 && response.ContentLength > v.maxBytes) {
		return nil, fail(ErrJWKSUnavailable)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, v.maxBytes+1))
	if err != nil || int64(len(body)) > v.maxBytes {
		return nil, fail(ErrJWKSUnavailable)
	}
	value, err := parseJSON(body, ErrJWKSInvalid)
	if err != nil {
		return nil, err
	}
	keys, err := parseJWKS(value)
	if err != nil {
		return nil, err
	}
	v.keys, v.expires = keys, v.now().Add(v.cacheTTL)
	v.generation++
	return keys, nil
}

func (v *RemoteVerifier) Verify(ctx context.Context, token string) (*Claims, error) {
	parsed, err := parseToken(token)
	if err != nil {
		return nil, err
	}
	keys, generation, _, err := v.load(ctx)
	if err != nil {
		return nil, err
	}
	kid := parsed.header["kid"].(string)
	if !containsKey(keys, kid) {
		if keys, err = v.loadUnknown(ctx, kid, generation); err != nil {
			return nil, err
		}
	}
	options := v.options
	options.Now = v.now()
	return verifyParsed(parsed, keys, options, options.Now)
}
