package mint

import (
	"fmt"
	"testing"
)

func TestCTLSRecordLayer(t *testing.T) {
	suite := TLS_AES_128_CCM_SHA256

	configServer := &Config{
		RequireClientAuth: true,
		CipherSuites:      []CipherSuite{suite},
		Certificates:      certificates,
		RecordLayer:       CTLSRecordLayerFactory{IsServer: true},
	}
	configClient := &Config{
		ServerName:         serverName,
		CipherSuites:       []CipherSuite{suite},
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
	suite := TLS_AES_128_CCM_8_SHA256
	group := X25519
	scheme := ECDSA_P256_SHA256
	shortRandom := true
	randomSize := 8
	shortFinished := true
	finishedSize := 8

	compression := &SlimCompression{
		CipherSuite: &suite,

		ClientHello: ClientHelloConstraints{
			RandomSize: randomSize,
			Extensions: PredefinedExtensions{
				ExtensionTypeServerName:          unhex("000e00000b6578616d706c652e636f6d"),
				ExtensionTypeSupportedGroups:     unhex(fmt.Sprintf("0002%04x", group)),
				ExtensionTypeSignatureAlgorithms: unhex(fmt.Sprintf("0002%04x", scheme)),
				ExtensionTypeSupportedVersions:   unhex("020304"),
			},
		},

		ServerHello: ServerHelloConstraints{
			RandomSize: randomSize,
			Extensions: PredefinedExtensions{
				ExtensionTypeSupportedVersions: unhex("0304"),
			},
		},

		CertificateRequest: CertificateRequestConstraints{
			Extensions: PredefinedExtensions{
				ExtensionTypeSignatureAlgorithms: unhex(fmt.Sprintf("0002%04x", scheme)),
			},
		},

		Certificate: CertificateConstraints{
			KnownCerts: map[string][]byte{
				"a": serverCert.Raw,
				"b": clientCert.Raw,
			},
		},
	}

	configServer := &Config{
		RequireClientAuth: true,
		Certificates:      certificates,
		CipherSuites:      []CipherSuite{suite},
		SignatureSchemes:  []SignatureScheme{scheme},
		Groups:            []NamedGroup{group},
		ShortRandom:       shortRandom,
		RandomSize:        randomSize,
		ShortFinished:     shortFinished,
		FinishedSize:      finishedSize,

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
		ShortRandom:        shortRandom,
		RandomSize:         randomSize,
		ShortFinished:      shortFinished,
		FinishedSize:       finishedSize,

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

func TestCTLSPSK(t *testing.T) {
	suite := TLS_AES_128_CCM_8_SHA256
	group := X25519
	scheme := ECDSA_P256_SHA256
	pskMode := PSKModeKE
	shortRandom := true
	randomSize := 16
	shortFinished := true
	finishedSize := 0
	shortBinder := false
	binderSize := 32

	psk := PreSharedKey{
		CipherSuite:  TLS_AES_128_CCM_8_SHA256,
		IsResumption: false,
		Identity:     []byte{0, 1, 2, 3},
		Key:          []byte{4, 5, 6, 7},
	}

	psks := &PSKMapCache{
		serverName: psk,
		"00010203": psk,
	}

	compression := &SlimCompression{
		CipherSuite: &suite,

		ClientHello: ClientHelloConstraints{
			RandomSize: randomSize,
			Extensions: PredefinedExtensions{
				ExtensionTypeServerName:          unhex("000e00000b6578616d706c652e636f6d"),
				ExtensionTypeSupportedGroups:     unhex(fmt.Sprintf("0002%04x", group)),
				ExtensionTypeSignatureAlgorithms: unhex(fmt.Sprintf("0002%04x", scheme)),
				ExtensionTypeSupportedVersions:   unhex("020304"),
				ExtensionTypePSKKeyExchangeModes: unhex("0100"),
			},
		},

		ServerHello: ServerHelloConstraints{
			RandomSize: randomSize,
			Extensions: PredefinedExtensions{
				ExtensionTypeSupportedVersions: unhex("0304"),
				ExtensionTypePreSharedKey:      unhex("0000"),
			},
		},

		CertificateRequest: CertificateRequestConstraints{Omit: true},
		Certificate:        CertificateConstraints{Omit: true},
	}

	configClient := &Config{
		ServerName:       serverName,
		CipherSuites:     []CipherSuite{suite},
		PSKs:             psks,
		Groups:           []NamedGroup{group},
		SignatureSchemes: []SignatureScheme{scheme},
		PSKModes:         []PSKKeyExchangeMode{pskMode},
		ShortRandom:      shortRandom,
		RandomSize:       randomSize,
		ShortFinished:    shortFinished,
		FinishedSize:     finishedSize,
		ShortBinder:      shortBinder,
		BinderSize:       binderSize,
		RecordLayer: CTLSRecordLayerFactory{
			IsServer:    false,
			Compression: compression,
		},
	}
	configServer := &Config{
		ServerName:       serverName,
		CipherSuites:     []CipherSuite{suite},
		PSKs:             psks,
		Groups:           []NamedGroup{group},
		SignatureSchemes: []SignatureScheme{scheme},
		PSKModes:         []PSKKeyExchangeMode{pskMode},
		ShortRandom:      shortRandom,
		RandomSize:       randomSize,
		ShortFinished:    shortFinished,
		FinishedSize:     finishedSize,
		ShortBinder:      shortBinder,
		BinderSize:       binderSize,
		RecordLayer: CTLSRecordLayerFactory{
			IsServer:    true,
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
}
