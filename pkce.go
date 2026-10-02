package schemer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

type pkce struct {
	verifier  string
	challenge string
	state     string
}

const (
	verifierBytes = 64
	stateBytes    = 16
)

func newPKCE() pkce {
	verifier := randomBase64URL(verifierBytes)
	sum := sha256.Sum256([]byte(verifier))
	return pkce{
		verifier:  verifier,
		challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		state:     randomBase64URL(stateBytes),
	}
}

func randomBase64URL(nBytes int) string {
	b := make([]byte, nBytes)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
