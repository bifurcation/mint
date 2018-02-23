package mint

import (
	"bytes"
	"testing"
)

func TestVersionNegotiation(t *testing.T) {
	// Test successful negotiation
	ok, negotiated := VersionNegotiation([]uint16{0x0301, 0x7f12}, []uint16{0x0302, 0x7f12})
	assertEquals(t, ok, true)
	assertEquals(t, negotiated, uint16(0x7f12))

	// Test failed negotiation
	ok, negotiated = VersionNegotiation([]uint16{0x0300}, []uint16{0x0400})
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
	ok, group, pub, secret := DHNegotiation(keyShares, []NamedGroup{X25519})
	assertEquals(t, ok, true)
	assertEquals(t, group, X25519)
	assertNotNil(t, pub, "Nil public key")
	assertNotNil(t, secret, "Nil DH secret")

	// Test continuation on newKeyShare failure
	// XXX: Would be better to test success, but more difficult.  This will at
	// least cover the branch
	originalPRNG := prng
	prng = bytes.NewBuffer(nil)
	ok, group, pub, secret = DHNegotiation(badKeyShares, []NamedGroup{P256, X25519})
	assertEquals(t, ok, false)
	prng = originalPRNG

	// Test continuation on keyAgreement failure
	ok, group, pub, secret = DHNegotiation(badKeyShares, []NamedGroup{P256, X25519})
	assertEquals(t, ok, true)
	assertEquals(t, group, X25519)
	assertNotNil(t, pub, "Nil public key")
	assertNotNil(t, secret, "Nil DH secret")

	// Test failure
	ok, _, _, _ = DHNegotiation(keyShares, []NamedGroup{P521})
	assertEquals(t, ok, false)
}

func TestPSKNegotiation(t *testing.T) {
	chTrunc := unhex("0001020304050607")
	binderValue := unhex("13a468af471adc19b94dcc0b888135423a11911f2c13050238b579d0f19d41c9")

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
	psks := &PSKMapCache{
		"04050607": {
			CipherSuite: TLS_AES_128_GCM_SHA256,
			Identity:    []byte{4, 5, 6, 7},
			Key:         []byte{0, 1, 2, 3},
		},
	}

	// Test successful negotiation
	ok, selected, psk, params, err := PSKNegotiation(identities, binders, chTrunc, psks)
	assertEquals(t, ok, true)
	assertEquals(t, selected, 1)
	assertNotNil(t, psk, "PSK not set")
	assertEquals(t, params.Suite, psk.CipherSuite)
	assertNotError(t, err, "Valid PSK negotiation failed")

	// Test negotiation failure on binder value failure
	ok, _, _, _, err = PSKNegotiation(identities, badBinders, chTrunc, psks)
	assertEquals(t, ok, false)
	assertError(t, err, "Failed to error on binder failure")

	// Test negotiation failure on no PSK overlap
	ok, _, _, _, err = PSKNegotiation(identities, binders, chTrunc, &PSKMapCache{})
	assertEquals(t, ok, false)
	assertNotError(t, err, "Errored on PSK negotiation failure")
}

func TestPSKModeNegotiation(t *testing.T) {
	// Test that everything that's allowed gets used
	usingDH, usingPSK := PSKModeNegotiation(true, true, []PSKKeyExchangeMode{PSKModeKE, PSKModeDHEKE})
	assertTrue(t, usingDH, "Unnecessarily disabled DH")
	assertTrue(t, usingPSK, "Unnecessarily disabled PSK")

	// Test that DH is disabled when not allowed with the PSK
	usingDH, usingPSK = PSKModeNegotiation(true, true, []PSKKeyExchangeMode{PSKModeKE})
	assertTrue(t, !usingDH, "Should not have enabled DH")
	assertTrue(t, usingPSK, "Unnecessarily disabled PSK")

	// Test that the PSK is disabled when DH is required but not possible
	usingDH, usingPSK = PSKModeNegotiation(false, true, []PSKKeyExchangeMode{PSKModeDHEKE})
	assertTrue(t, !usingDH, "Should not have enabled DH")
	assertTrue(t, !usingPSK, "Should not have enabled PSK")
}

func TestCertificateSelection(t *testing.T) {
	goodName := "example.com"
	badName := "not-example.com"
	rsa := []SignatureScheme{ECDSA_P256_SHA256}
	eddsa := []SignatureScheme{Ed25519}

	// Test success
	cert, scheme, err := CertificateSelection(&goodName, rsa, certificates)
	assertNotError(t, err, "Failed to find certificate in a valid set")
	assertNotNil(t, cert, "Failed to set certificate")
	assertEquals(t, scheme, ECDSA_P256_SHA256)

	// Test success with no name specified
	cert, scheme, err = CertificateSelection(nil, rsa, certificates)
	assertNotError(t, err, "Failed to find certificate in a valid set")
	assertNotNil(t, cert, "Failed to set certificate")
	assertEquals(t, scheme, ECDSA_P256_SHA256)

	// Test failure on no certs matching host name
	_, _, err = CertificateSelection(&badName, rsa, certificates)
	assertError(t, err, "Found a certificate for an incorrect host name")

	// Test failure on no certs matching signature scheme
	_, _, err = CertificateSelection(&goodName, eddsa, certificates)
	assertError(t, err, "Found a certificate for an incorrect signature scheme")
}

func TestEarlyDataNegotiation(t *testing.T) {
	useEarlyData, rejected := EarlyDataNegotiation(true, true, true)
	assertTrue(t, useEarlyData, "Did not use early data when allowed")
	assertTrue(t, !rejected, "Rejected when allowed")

	useEarlyData, rejected = EarlyDataNegotiation(false, true, true)
	assertTrue(t, !useEarlyData, "Allowed early data when not using PSK")
	assertTrue(t, rejected, "Rejected not set")

	useEarlyData, rejected = EarlyDataNegotiation(true, false, true)
	assertTrue(t, !useEarlyData, "Allowed early data when not signaled")
	assertTrue(t, !rejected, "Rejected when not signaled")

	useEarlyData, rejected = EarlyDataNegotiation(true, true, false)
	assertTrue(t, !useEarlyData, "Allowed early data when not allowed")
	assertTrue(t, rejected, "Rejected not set")
}

func TestCipherSuiteNegotiation(t *testing.T) {
	offered := []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}
	supported := []CipherSuite{TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}
	psk := &PreSharedKey{CipherSuite: TLS_CHACHA20_POLY1305_SHA256}

	// Test success with PSK-specified suite
	suite, err := CipherSuiteNegotiation(psk, offered, supported)
	assertNotError(t, err, "CipherSuite negotiation with PSK failed")
	assertEquals(t, suite, psk.CipherSuite)

	// Test success with no PSK
	suite, err = CipherSuiteNegotiation(nil, offered, supported)
	assertNotError(t, err, "CipherSuite negotiation without PSK failed")
	assertEquals(t, suite, TLS_AES_256_GCM_SHA384)

	// Test failure
	_, err = CipherSuiteNegotiation(nil, []CipherSuite{TLS_AES_128_GCM_SHA256}, supported)
	assertError(t, err, "CipherSuite negotiation succeeded with no overlap")
}

func TestALPNNegotiation(t *testing.T) {
	offered := []string{"http/1.1", "h2"}
	supported := []string{"h2", "spdy/1.1"}
	psk := &PreSharedKey{NextProto: "h2", IsResumption: true}

	// Test success with PSK-specified protocol
	proto, err := ALPNNegotiation(psk, offered, supported)
	assertNotError(t, err, "ALPN negotiation with PSK failed")
	assertEquals(t, proto, psk.NextProto)

	// Test success with no PSK
	proto, err = ALPNNegotiation(nil, offered, supported)
	assertNotError(t, err, "ALPN negotiation without PSK failed")
	assertEquals(t, proto, "h2")

	// Test failure on resumption and mismatch
	proto, err = ALPNNegotiation(psk, []string{"http/1.1"}, []string{})
	assertError(t, err, "Resumption allowed without offer having previous ALPN")

	// Test failure without resumption
	proto, err = ALPNNegotiation(nil, []string{"http/1.1"}, []string{})
	assertNotError(t, err, "ALPN mismatch caused an error")
	assertEquals(t, proto, "")
}
