package mint

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// CookieSource is used to create and verify a cookie
type CookieSource interface {
	// NewToken creates a new token
	NewToken([]byte) ([]byte, error)
	// DecodeToken decodes a token
	DecodeToken([]byte) ([]byte, error)
}

const cookieSecretSize = 32
const cookieNonceSize = 32

// The DefaultCookieSource is a simple implementation for the CookieSource.
type DefaultCookieSource struct {
	secret []byte
}

var _ CookieSource = &DefaultCookieSource{}

// NewDefaultCookieSource creates a source for source address tokens
func NewDefaultCookieSource() (CookieSource, error) {
	secret := make([]byte, cookieSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return &DefaultCookieSource{secret: secret}, nil
}

// NewToken encodes data into a new token.
func (s *DefaultCookieSource) NewToken(data []byte) ([]byte, error) {
	nonce := make([]byte, cookieNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aead, aeadNonce, err := s.createAEAD(nonce)
	if err != nil {
		return nil, err
	}
	return append(nonce, aead.Seal(nil, aeadNonce, data, nil)...), nil
}

// DecodeToken decodes a token.
func (s *DefaultCookieSource) DecodeToken(p []byte) ([]byte, error) {
	if len(p) < cookieNonceSize {
		return nil, fmt.Errorf("Token too short: %d", len(p))
	}
	nonce := p[:cookieNonceSize]
	aead, aeadNonce, err := s.createAEAD(nonce)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, aeadNonce, p[cookieNonceSize:], nil)
}

func (s *DefaultCookieSource) createAEAD(nonce []byte) (cipher.AEAD, []byte, error) {
	h := hkdf.New(sha256.New, s.secret, nonce, []byte("mint cookie source"))
	key := make([]byte, 32) // use a 32 byte key, in order to select AES-256
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, nil, err
	}
	aeadNonce := make([]byte, 12)
	if _, err := io.ReadFull(h, aeadNonce); err != nil {
		return nil, nil, err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(c)
	if err != nil {
		return nil, nil, err
	}
	return aead, aeadNonce, nil
}
