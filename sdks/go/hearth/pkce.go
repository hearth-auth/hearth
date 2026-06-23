package hearth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// PKCEPair is a PKCE code verifier and its derived S256 challenge (RFC 7636).
//
// Hearth mandates PKCE for the authorization-code flow (RFC 9700 §2.1.1):
// every public client — and, by default, every confidential client — must
// supply a challenge at the authorize step and the matching verifier at the
// token step. Use [GeneratePKCE] to produce a pair, send Challenge/Method on
// the [AuthorizeRequest], and send Verifier on the [TokenRequest].
type PKCEPair struct {
	// Verifier is the high-entropy secret sent to the token endpoint as
	// code_verifier. Keep it out of the authorize request.
	Verifier string
	// Challenge is BASE64URL(SHA256(Verifier)), sent to the authorize
	// endpoint as code_challenge.
	Challenge string
	// Method is the challenge method. Always "S256" — Hearth rejects "plain".
	Method string
}

// GeneratePKCE returns a fresh PKCE pair built from a 32-byte CSPRNG verifier
// and the S256 challenge method. It returns an error only when the system
// random source is unavailable.
func GeneratePKCE() (PKCEPair, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return PKCEPair{}, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	return PKCEPair{
		Verifier:  verifier,
		Challenge: base64.RawURLEncoding.EncodeToString(sum[:]),
		Method:    "S256",
	}, nil
}
