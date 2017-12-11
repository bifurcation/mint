package mint

import (
	"bytes"
	"testing"
)

func TestCookieProtector(t *testing.T) {
	cs, err := NewDefaultCookieProtector()
	assertNotError(t, err, "creating the cookie source failed")

	t.Run("handling valid tokens", func(t *testing.T) {
		cookie := []byte("foobar")
		token, err := cs.NewToken(cookie)
		assertNotError(t, err, "creating new token failed")
		decoded, err := cs.DecodeToken(token)
		assertNotError(t, err, "decoding the token failed")
		assertDeepEquals(t, cookie, decoded)
	})

	t.Run("handling invalid tokens", func(t *testing.T) {
		_, err := cs.DecodeToken([]byte("too short"))
		assertError(t, err, "it should reject too short tokens")
		_, err = cs.DecodeToken(append(bytes.Repeat([]byte{0}, cookieNonceSize), []byte("invalid token")...))
		assertError(t, err, "it should reject invalid tokens")
		// create a valid and modify the nonce
		token, err := cs.NewToken([]byte("foobar"))
		assertNotError(t, err, "creating new token failed")
		token[0]++
		_, err = cs.DecodeToken(token)
		assertError(t, err, "it should reject a token with the wrong nonce")
	})
}
