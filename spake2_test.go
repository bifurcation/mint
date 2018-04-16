package mint

import (
	"testing"
)

var (
	nistGroupByName = map[string]NamedGroup{
		"P256": P256,
		"P384": P384,
		"P521": P521,
	}

	passwordHashByName = map[string]PasswordHash{
		"scrypt": PasswordHashScrypt,
		"argon2": PasswordHashArgon2,
	}
)

var (
	client         = []byte("alice")
	server         = []byte("bob")
	spake2password = []byte("password")

	spake2Algorithms = map[string][]string{
		"group": {"P256", "P384", "P521"},
		"hash":  {"argon2", "scrypt"},
	}
)

func testSPAKE2(t *testing.T, name string, p testInstanceState) {
	group, groupOK := nistGroupByName[p["group"]]
	hash, hashOK := passwordHashByName[p["hash"]]
	assertTrue(t, groupOK && hashOK, "Configuration error")

	w, err := encodeSPAKE2Password(group, hash, contextW, client, server, spake2password)
	assertNotError(t, err, "Failed to generate password hash")

	x, T, err := newSPAKE2KeyShare(group, true, w)
	assertNotError(t, err, "Failed to generate client key share")

	y, S, err := newSPAKE2KeyShare(group, false, w)
	assertNotError(t, err, "Failed to generate server key share")

	Kc, err := spake2KeyAgreement(group, true, S, x, w)
	assertNotError(t, err, "Failed to generate client key")

	Ks, err := spake2KeyAgreement(group, false, T, y, w)
	assertNotError(t, err, "Failed to generate server key")

	assertByteEquals(t, Ks, Kc)
}

func TestSPAKE2(t *testing.T) {
	runParametrizedTest(t, spake2Algorithms, testSPAKE2)
}

func testSPAKE2Plus(t *testing.T, name string, p testInstanceState) {
	group, groupOK := nistGroupByName[p["group"]]
	hash, hashOK := passwordHashByName[p["hash"]]
	assertTrue(t, groupOK && hashOK, "Configuration error")

	w0c, w1c, err := spake2pClientSetup(group, hash, client, server, spake2password)
	assertNotError(t, err, "Failed to generate client parameters")

	w0s, Ls, err := spake2pServerSetup(group, hash, client, server, spake2password)
	assertNotError(t, err, "Failed to generate server parameters")
	assertByteEquals(t, w0c, w0s)

	x, T, err := newSPAKE2KeyShare(group, true, w0c)
	assertNotError(t, err, "Failed to generate client key share")

	y, S, err := newSPAKE2KeyShare(group, false, w0s)
	assertNotError(t, err, "Failed to generate server key share")

	Zc, Vc, err := spake2pClient(group, S, x, w0c, w1c)
	assertNotError(t, err, "Failed to generate client key")

	Zs, Vs, err := spake2pServer(group, T, y, w0s, Ls)
	assertNotError(t, err, "Failed to generate server key")

	assertByteEquals(t, Zs, Zc)
	assertByteEquals(t, Vs, Vc)
}

func TestSPAKE2Plus(t *testing.T) {
	runParametrizedTest(t, spake2Algorithms, testSPAKE2Plus)
}
