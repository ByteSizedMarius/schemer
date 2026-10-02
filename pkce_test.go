package schemer

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"testing"
)

func TestStartIssuesFreshVerifierAndState(t *testing.T) {
	a, b := start(t, testFlow()), start(t, testFlow())

	if a.pkce.verifier == b.pkce.verifier {
		t.Error("two sessions share a verifier")
	}
	if a.pkce.state == b.pkce.state {
		t.Error("two sessions share a state")
	}
}

func TestStartIssuesRFC7636VerifierAndChallenge(t *testing.T) {
	p := start(t, testFlow()).pkce

	// RFC 7636 section 4.1.
	if !regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`).MatchString(p.verifier) {
		t.Errorf("verifier %q (%d characters) is not 43 to 128 unreserved characters", p.verifier, len(p.verifier))
	}

	// RFC 7636 section 4.2 (S256).
	sum := sha256.Sum256([]byte(p.verifier))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); p.challenge != want {
		t.Errorf("challenge = %q, want the unpadded base64url SHA-256 of the verifier, %q", p.challenge, want)
	}
}
