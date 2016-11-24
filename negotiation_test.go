package mint

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestVersionNegotiation(t *testing.T) {
	// Test successful negotiation
	ok, negotiated := versionNegotiation([]uint16{0x0301, 0x7f12}, []uint16{0x0302, 0x7f12})
	assertEquals(t, ok, true)
	assertEquals(t, negotiated, uint16(0x7f12))

	// Test failed negotiation
	ok, negotiated = versionNegotiation([]uint16{0x0300}, []uint16{0x0400})
	assertEquals(t, ok, false)
}

func TestDHNegotiation(t *testing.T) {
	keyShares := []KeyShareEntry{
		{Group: P256, KeyExchange: random(keyExchangeSizeFromNamedGroup(P256))},
		{Group: X25519, KeyExchange: random(keyExchangeSizeFromNamedGroup(X25519))},
	}
	badKeyShares := []KeyShareEntry{
		{Group: P256, KeyExchange: random(keyExchangeSizeFromNamedGroup(P256) - 2)},
		{Group: X25519, KeyExchange: random(keyExchangeSizeFromNamedGroup(X25519))},
	}

	// Test successful negotiation
	ok, group, pub, secret := dhNegotiation(keyShares, []NamedGroup{X25519})
	assertEquals(t, ok, true)
	assertEquals(t, group, X25519)
	assertNotNil(t, pub, "Nil public key")
	assertNotNil(t, secret, "Nil DH secret")

	// Test continuation on newKeyShare failure
	// XXX: Would be better to test success, but more difficult.  This will at
	// least cover the branch
	originalPRNG := prng
	prng = bytes.NewBuffer(nil)
	ok, group, pub, secret = dhNegotiation(badKeyShares, []NamedGroup{P256, X25519})
	assertEquals(t, ok, false)
	prng = originalPRNG

	// Test continuation on keyAgreement failure
	ok, group, pub, secret = dhNegotiation(badKeyShares, []NamedGroup{P256, X25519})
	assertEquals(t, ok, true)
	assertEquals(t, group, X25519)
	assertNotNil(t, pub, "Nil public key")
	assertNotNil(t, secret, "Nil DH secret")

	// Test failure
	ok, _, _, _ = dhNegotiation(keyShares, []NamedGroup{P521})
	assertEquals(t, ok, false)
}

func TestPSKNegotiation(t *testing.T) {
	chTrunc, _ := hex.DecodeString("0001020304050607")
	binderValue, _ := hex.DecodeString("9c4bfad67420fbc3f03809744929f9f3d21030fd15e886881bbe21b7ca28ee16")

	identities := []PSKIdentity{
		{Identity: []byte{0, 1, 2, 3}},
		{Identity: []byte{4, 5, 6, 7}},
	}
	binders := []PSKBinderEntry{
		{Binder: binderValue},
		{Binder: binderValue},
	}
	badBinders := []PSKBinderEntry{
		{Binder: []byte{}},
		{Binder: []byte{}},
	}
	psks := map[string]PreSharedKey{
		"example.com": {
			CipherSuite: TLS_AES_128_GCM_SHA256,
			Identity:    []byte{4, 5, 6, 7},
			Key:         []byte{0, 1, 2, 3},
		},
	}

	// Test successful negotiation
	ok, selected, psk, ctx, err := pskNegotiation(identities, binders, chTrunc, psks)
	assertEquals(t, ok, true)
	assertEquals(t, selected, 1)
	assertNotNil(t, psk, "PSK not set")
	assertNotNil(t, ctx.pskSecret, "PSK secret not set")
	assertNotError(t, err, "Valid PSK negotiation failed")

	// Test negotiation failure on binder value failure
	ok, _, _, _, err = pskNegotiation(identities, badBinders, chTrunc, psks)
	assertEquals(t, ok, false)
	assertError(t, err, "Failed to error on binder failure")

	// Test negotiation failure on no PSK overlap
	ok, _, _, _, err = pskNegotiation(identities, binders, chTrunc, map[string]PreSharedKey{})
	assertEquals(t, ok, false)
	assertNotError(t, err, "Errored on PSK negotiation failure")
}

func TestPSKModeNegotiation(t *testing.T) {
	// Test that everything that's allowed gets used
	usingDH, usingPSK := pskModeNegotiation(true, true, []PSKKeyExchangeMode{PSKModeKE, PSKModeDHEKE})
	assert(t, usingDH, "Unnecessarily disabled DH")
	assert(t, usingPSK, "Unnecessarily disabled PSK")

	// Test that DH is disabled when not allowed with the PSK
	usingDH, usingPSK = pskModeNegotiation(true, true, []PSKKeyExchangeMode{PSKModeKE})
	assert(t, !usingDH, "Should not have enabled DH")
	assert(t, usingPSK, "Unnecessarily disabled PSK")

	// Test that the PSK is disabled when DH is required but not possible
	usingDH, usingPSK = pskModeNegotiation(false, true, []PSKKeyExchangeMode{PSKModeDHEKE})
	assert(t, !usingDH, "Should not have enabled DH")
	assert(t, !usingPSK, "Should not have enabled PSK")
}

func TestCertificateSelection(t *testing.T) {
	rsa := []SignatureScheme{RSA_PKCS1_SHA256}
	eddsa := []SignatureScheme{Ed25519}

	// Test success
	cert, scheme, err := certificateSelection("example.com", rsa, certificates)
	assertNotError(t, err, "Failed to find certificate in a valid set")
	assertNotNil(t, cert, "Failed to set certificate")
	assertEquals(t, scheme, RSA_PKCS1_SHA256)

	// Test failure on no certs matching host name
	cert, scheme, err = certificateSelection("not-example.com", rsa, certificates)
	assertError(t, err, "Found a certificate for an incorrect host name")

	// Test failure on no certs matching signature scheme
	cert, scheme, err = certificateSelection("example.com", eddsa, certificates)
	assertError(t, err, "Found a certificate for an incorrect signature scheme")
}

func TestEarlyDataNegotiation(t *testing.T) {
	useEarlyData := earlyDataNegotiation(true, true, true)
	assert(t, useEarlyData, "Did not use early data when allowed")

	useEarlyData = earlyDataNegotiation(false, true, true)
	assert(t, !useEarlyData, "Allowed early data when not using PSK")

	useEarlyData = earlyDataNegotiation(true, false, true)
	assert(t, !useEarlyData, "Allowed early data when not signaled")

	useEarlyData = earlyDataNegotiation(true, true, false)
	assert(t, !useEarlyData, "Allowed early data when not allowed")
}

func TestCipherSuiteNegotiation(t *testing.T) {
	offered := []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}
	supported := []CipherSuite{TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}
	psk := &PreSharedKey{CipherSuite: TLS_CHACHA20_POLY1305_SHA256}

	// Test success with PSK-specified suite
	suite, err := cipherSuiteNegotiation(psk, offered, supported)
	assertNotError(t, err, "CipherSuite negotiation with PSK failed")
	assertEquals(t, suite, psk.CipherSuite)

	// Test success with no PSK
	suite, err = cipherSuiteNegotiation(nil, offered, supported)
	assertNotError(t, err, "CipherSuite negotiation without PSK failed")
	assertEquals(t, suite, TLS_AES_256_GCM_SHA384)

	// Test failure
	_, err = cipherSuiteNegotiation(nil, []CipherSuite{TLS_AES_128_GCM_SHA256}, supported)
	assertError(t, err, "CipherSuite negotiation succeeded with no overlap")
}

func TestALPNNegotiation(t *testing.T) {
	offered := []string{"http/1.1", "h2"}
	supported := []string{"h2", "spdy/1.1"}
	psk := &PreSharedKey{NextProto: "h2", IsResumption: true}

	// Test success with PSK-specified protocol
	proto, err := alpnNegotiation(psk, offered, supported)
	assertNotError(t, err, "ALPN negotiation with PSK failed")
	assertEquals(t, proto, psk.NextProto)

	// Test success with no PSK
	proto, err = alpnNegotiation(nil, offered, supported)
	assertNotError(t, err, "ALPN negotiation without PSK failed")
	assertEquals(t, proto, "h2")

	// Test failure on resumption and mismatch
	proto, err = alpnNegotiation(psk, []string{"http/1.1"}, []string{})
	assertError(t, err, "Resumption allowed without offer having previous ALPN")

	// Test failure without resumption
	proto, err = alpnNegotiation(nil, []string{"http/1.1"}, []string{})
	assertNotError(t, err, "ALPN mismatch caused an error")
	assertEquals(t, proto, "")
}
