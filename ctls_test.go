package mint

import (
	"testing"
)

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
//   M2 = ServerHello, [EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, Finished]
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

func TestCTLSBaseSession(t *testing.T) {
	configServer := &Config{
		RequireClientAuth:    true,
		Certificates:         certificates,
		HandshakeCompression: ctlsCompression{},
	}
	configClient := &Config{
		ServerName:           serverName,
		Certificates:         clientCertificates,
		InsecureSkipVerify:   true,
		Groups:               []NamedGroup{X25519},
		HandshakeCompression: ctlsCompression{},
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
