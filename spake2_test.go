package mint

import (
	"crypto"
	"testing"

	_ "crypto/sha256"
	_ "crypto/sha512"
)

var (
	client         = []byte("alice")
	server         = []byte("bob")
	spake2password = []byte("password")
	spake2Suites   = []struct {
		group NamedGroup
		hash  passwordHash
	}{
		{group: P256, hash: makeHash(crypto.SHA256)},
		{group: P384, hash: makeHash(crypto.SHA384)},
		{group: P521, hash: makeHash(crypto.SHA512)},
	}
)

func makeHash(hash crypto.Hash) passwordHash {
	return func(pw []byte) ([]byte, error) {
		h := hash.New()
		h.Write(pw)
		return h.Sum(nil), nil
	}
}

func TestSPAKE2(t *testing.T) {
	for _, c := range spake2Suites {
		w, err := encodeSPAKE2Password(c.group, c.hash, contextW, client, server, spake2password)
		assertNotError(t, err, "Failed to generate password hash")

		x, T, err := newSPAKE2KeyShare(c.group, true, w)
		assertNotError(t, err, "Failed to generate client key share")

		y, S, err := newSPAKE2KeyShare(c.group, false, w)
		assertNotError(t, err, "Failed to generate server key share")

		Kc, err := spake2KeyAgreement(c.group, true, S, x, w)
		assertNotError(t, err, "Failed to generate client key")

		Ks, err := spake2KeyAgreement(c.group, false, T, y, w)
		assertNotError(t, err, "Failed to generate server key")

		assertByteEquals(t, Ks, Kc)
	}
}

func TestSPAKE2Plus(t *testing.T) {
	for _, c := range spake2Suites {
		w0c, w1c, err := spake2pClientSetup(c.group, c.hash, client, server, spake2password)
		assertNotError(t, err, "Failed to generate client parameters")

		w0s, Ls, err := spake2pServerSetup(c.group, c.hash, client, server, spake2password)
		assertNotError(t, err, "Failed to generate server parameters")
		assertByteEquals(t, w0c, w0s)

		x, T, err := newSPAKE2KeyShare(c.group, true, w0c)
		assertNotError(t, err, "Failed to generate client key share")

		y, S, err := newSPAKE2KeyShare(c.group, false, w0s)
		assertNotError(t, err, "Failed to generate server key share")

		Zc, Vc, err := spake2pClient(c.group, S, x, w0c, w1c)
		assertNotError(t, err, "Failed to generate client key")

		Zs, Vs, err := spake2pServer(c.group, T, y, w0s, Ls)
		assertNotError(t, err, "Failed to generate server key")

		assertByteEquals(t, Zs, Zc)
		assertByteEquals(t, Vs, Vc)
	}
}
