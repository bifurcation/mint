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

// CookieSource is used to create and verify source address tokens
type CookieSource interface {
	// NewToken creates a new token
	NewToken([]byte) ([]byte, error)
	// DecodeToken decodes a token
	DecodeToken([]byte) ([]byte, error)
}

type defaultCookieSource struct {
	aead cipher.AEAD
}

const tokenKeySize = 16
const tokenNonceSize = 16

// newDefaultCookieSource creates a source for source address tokens
func newDefaultCookieSource() (CookieSource, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	key, err := deriveKey(secret)
	if err != nil {
		return nil, err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(c, tokenNonceSize)
	if err != nil {
		return nil, err
	}
	return &defaultCookieSource{aead: aead}, nil
}

func (s *defaultCookieSource) NewToken(data []byte) ([]byte, error) {
	nonce := make([]byte, tokenNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, data, nil), nil
}

func (s *defaultCookieSource) DecodeToken(p []byte) ([]byte, error) {
	if len(p) < tokenNonceSize {
		return nil, fmt.Errorf("Token too short: %d", len(p))
	}
	nonce := p[:tokenNonceSize]
	return s.aead.Open(nil, nonce, p[tokenNonceSize:], nil)
}

func deriveKey(secret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, nil, []byte("mint TLS 1.3 cookie token key"))
	key := make([]byte, tokenKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}
