package mint

import (
	"crypto/x509"
	"testing"
)

func TestCTLSRecordLayer(t *testing.T) {
	configServer := &Config{
		RequireClientAuth: true,
		Certificates:      certificates,
		RecordLayer:       CTLSRecordLayerFactory{IsServer: true},
	}
	configClient := &Config{
		ServerName:         serverName,
		Certificates:       clientCertificates,
		InsecureSkipVerify: true,
		RecordLayer:        CTLSRecordLayerFactory{IsServer: false},
	}

	cConn, sConn := pipe()
	client := Client(cConn, configClient)
	server := Server(sConn, configServer)

	var clientAlert, serverAlert Alert
	done := make(chan bool)
	go func(t *testing.T) {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		done <- true
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	<-done

	checkConsistency(t, client, server)
	assertTrue(t, client.state.Params.UsingClientAuth, "Session did not negotiate client auth")
}

func TestCTLSRPK(t *testing.T) {
	suite := TLS_AES_128_GCM_SHA256
	group := X25519
	scheme := ECDSA_P256_SHA256
	zeroRandom := true

	allCertificates := map[string]*Certificate{
		"a": {
			Chain:      []*x509.Certificate{serverCert},
			PrivateKey: serverKey,
		},
		"b": {
			Chain:      []*x509.Certificate{clientCert},
			PrivateKey: clientKey,
		},
	}

	compression := &RPKCompression{
		SupportedVersion: tls13Version,
		ServerName:       serverName,
		CipherSuite:      suite,
		SignatureScheme:  scheme,
		SupportedGroup:   group,
		Certificates:     allCertificates,
		ZeroRandom:       zeroRandom,
	}

	configServer := &Config{
		RequireClientAuth: true,
		Certificates:      certificates,
		CipherSuites:      []CipherSuite{suite},
		SignatureSchemes:  []SignatureScheme{scheme},
		Groups:            []NamedGroup{group},
		ZeroRandom:        zeroRandom,
		RecordLayer: CTLSRecordLayerFactory{
			IsServer:    true,
			Compression: compression,
		},
	}
	configClient := &Config{
		ServerName:         serverName,
		Certificates:       clientCertificates,
		InsecureSkipVerify: true,
		CipherSuites:       []CipherSuite{suite},
		SignatureSchemes:   []SignatureScheme{scheme},
		Groups:             []NamedGroup{group},
		ZeroRandom:         zeroRandom,
		RecordLayer: CTLSRecordLayerFactory{
			IsServer:    false,
			Compression: compression,
		},
	}

	cConn, sConn := pipe()
	client := Client(cConn, configClient)
	server := Server(sConn, configServer)

	var clientAlert, serverAlert Alert
	done := make(chan bool)
	go func(t *testing.T) {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		done <- true
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	<-done

	checkConsistency(t, client, server)
	assertTrue(t, client.state.Params.UsingClientAuth, "Session did not negotiate client auth")
}

// This test lets us see the impact of various compression schemes
// on the size of the flights in a TLS handshake.  To get the
// lengths, run:
//
//   MINT_LOG=pipe go test -run CTLS
//
// In the notes below, the messages M1, M2, and M3, correspond to
// the clients first flight, the server's first flight, and the
// client's second flight, respectively.
//
//   M1 = ClientHello
//   M2 = ServerHello, [EncryptedExtensions, CertificateRequest,
//											Certificate, CertificateVerify, Finished]
//   M3 = [Certificate, CertificateVerify, Finished]
//
// Base case (no compression)
//		M1: 156
//		M2: 717
//		M3: 548
//
// Record consolidation (one AEAD invocation)
//		M1: 156
//		M2: 630
//		M3: 501
//
// Lossless / stateless compression of handshake bodies
// (Remove legacy pieces, unnecessary lengths)
//		M1: 149
//		M2: 614
//		M3: 498
//
// Certificate compression as uint32 index into a list
// (Prenegotiate certificates, signature algorithms)
//    M1: 139 (b/c fewer signature algorithms)
//    M2: 240
//    M3: 143
//
// Prenegotiate groups, signature algorithms, versions
// (And strip the relevant extensions)
//    M1: 116
//    M2: 234
//    M3: 144
//
// Theoretical optimum:
//    M1:  64 = 32(rand) + 32(DH)
//		M2:	160	= 32(rand) + 32(DH)  + 64(sig) + 32(MAC)
//		M3:  96 = 64(sig)  + 32(MAC)
//
// EDHOC claimed:
//    M1:  39
//    M2: 120
//    M3:  85

/*
func TestCTLSBaseSession(t *testing.T) {
	schemes := []SignatureScheme{ECDSA_P256_SHA256}

	compression := ctlsCompression{
		SupportedVersion: tls13Version,
		SignatureScheme:  ECDSA_P256_SHA256,
		SupportedGroup:   X25519,
		Certificates:     allCertificates,
	}

	configServer := &Config{
		RequireClientAuth:    true,
		Certificates:         certificates,
		SignatureSchemes:     schemes,
		HandshakeCompression: compression,
	}
	configClient := &Config{
		ServerName:           serverName,
		Certificates:         clientCertificates,
		InsecureSkipVerify:   true,
		Groups:               []NamedGroup{X25519},
		SignatureSchemes:     schemes,
		HandshakeCompression: compression,
	}

	cConn, sConn := pipe()
	client := Client(cConn, configClient)
	server := Server(sConn, configServer)

	var clientAlert, serverAlert Alert
	done := make(chan bool)
	go func(t *testing.T) {
		serverAlert = server.Handshake()
		assertEquals(t, serverAlert, AlertNoAlert)
		done <- true
	}(t)

	clientAlert = client.Handshake()
	assertEquals(t, clientAlert, AlertNoAlert)

	<-done

	checkConsistency(t, client, server)
	assertTrue(t, client.state.Params.UsingClientAuth, "Session did not negotiate client auth")
}
*/
