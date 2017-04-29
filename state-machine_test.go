package mint

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestClientStateStart(t *testing.T) {
	state := ClientStateStart{
		state: &connectionState{
			Caps: Capabilities{
				Groups:           []NamedGroup{P256},
				SignatureSchemes: []SignatureScheme{ECDSA_P256_SHA256},
				PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
				CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
				PSKs:             &PSKMapCache{},
			},
			Opts: ConnectionOptions{
				ServerName: "example.com",
				NextProtos: []string{"h2"},
			},
		},
	}

	// Test success (first try)
	// TODO: Verify that the returned ClientHello has the right contents
	nextState, toSend, alert := state.Next(nil)
	_, stateTypeOK := nextState.(ClientStateWaitSH)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 1)
	assertEquals(t, toSend[0].Type(), HandshakeTypeClientHello)
	assertEquals(t, alert, AlertNoAlert)

	fmt.Printf("%+v\n", toSend[0].(*ClientHelloBody))

	// TODO: Test success (with PSK)
	// TODO: Test success (with PSK and early data)
	// TODO: Test success with cookie / HRR (if we go that way, vs. WAIT_SH -> WAIT_SH)

	// Test failure on non-nil message
	_, _, alert = state.Next(&ClientHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)

	// TODO: Test failure on DH key generation failure
	// TODO: Test failure on random generation failure
	// TODO: Test failure on extension marshal failure
	// TODO: Test failure on ALPN marshal failure
	// TODO: Test failure on unknown PSK ciphersuite
	// TODO: Test failure on truncated CH marshal failure
	// TODO: Test failure on CH marshal failure
}

func TestClientStateWaitSH(t *testing.T) {
	clientHelloBodyHex := "0303d225c4a8862b1264f937184480ec8c1c70292096b7eb74def37ef1af7d6" +
		"18e2e000002130101000085002b0003027f1200000010000e00000b6578616d" +
		"706c652e636f6d0028004700450017004104031f35c184fad1fe7cbb9358b5a" +
		"76e29b9a1f558263d3120ed0ee73e84f6f05e7346538f84253cbfa7331cf8f2" +
		"32d5677b6c36ec9a6ff43bb2a628e940c79af2000a000400020017000d00040" +
		"0020403002d00020101001000050003026832"
	clientHelloBody, _ := hex.DecodeString(clientHelloBodyHex)
	dhPrivateKeyHex := "51720e0c02e4e59baea5a80ee897968eb543b5fa4de895cc6226c663685bac78"
	dhPrivateKey, _ := hex.DecodeString(dhPrivateKeyHex)

	state := ClientStateWaitSH{
		state: &connectionState{
			Caps: Capabilities{
				Groups:           []NamedGroup{P256},
				SignatureSchemes: []SignatureScheme{ECDSA_P256_SHA256},
				PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
				CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
				PSKs:             &PSKMapCache{},
			},
			Opts: ConnectionOptions{
				ServerName: "example.com",
				NextProtos: []string{"h2"},
			},
			Context: cryptoContext{},
			OfferedDH: map[NamedGroup][]byte{
				P256: dhPrivateKey,
			},
			clientHello: &HandshakeMessage{
				msgType: HandshakeTypeClientHello,
				body:    clientHelloBody,
			},
		},
	}

	sh := &ServerHelloBody{
		Version:     supportedVersion,
		CipherSuite: TLS_AES_128_GCM_SHA256,
		Extensions: []Extension{
			{
				ExtensionType: ExtensionTypeKeyShare,
				ExtensionData: unhex("001700410453878857547c46a2be0f6a7ed624685616047913a2d9ef8f7d80bf" +
					"ff0f7c2d9ad689c09cebb6f181ca2f26993ecdbf13aab10b04d6f8d16836b6050d90a126c5"),
			},
		},
	}
	shRandom := unhex("0889892920c3d73de2657e89fbf66f9ce6a1d9f68debdbd1654027c7d4a4a99e")
	copy(sh.Random[:], shRandom)

	// Test success (HelloRetryRequest)
	nextState, toSend, alert := state.Next(&HelloRetryRequestBody{})
	_, stateTypeOK := nextState.(ClientStateWaitSH)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 1)
	assertEquals(t, toSend[0].Type(), HandshakeTypeClientHello)
	assertEquals(t, alert, AlertNoAlert)

	// Test success (ServerHello)
	nextState, toSend, alert = state.Next(sh)
	_, stateTypeOK = nextState.(ClientStateWaitEE)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// TODO: Test with various negotiation cases

	// Test nil message
	_, _, alert = state.Next(nil)
	assertEquals(t, alert, AlertUnexpectedMessage)

	// Test unknown message
	_, _, alert = state.Next(&ClientHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestClientStateWaitEE(t *testing.T) {
	connState0 := connectionState{}

	ee := &EncryptedExtensionsBody{
		Extensions: []Extension{
			{ExtensionType: ExtensionTypeALPN, ExtensionData: unhex("0003026832")},
			{ExtensionType: ExtensionTypeEarlyData, ExtensionData: []byte{}},
		},
	}

	// Test success (PSK)
	connState1 := connState0
	state := ClientStateWaitEE{state: &connState1}
	state.state.Params.UsingPSK = true
	nextState, toSend, alert := state.Next(ee)
	_, stateTypeOK := nextState.(ClientStateWaitFinished)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test success (no PSK)
	state.state.Params.UsingPSK = false
	nextState, toSend, alert = state.Next(ee)
	_, stateTypeOK = nextState.(ClientStateWaitCertCR)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test unexpected message
	_, _, alert = state.Next(&ClientHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestClientStateWaitCertCR(t *testing.T) {
	state := ClientStateWaitCertCR{state: &connectionState{}}

	// Test success (Certificate)
	nextState, toSend, alert := state.Next(&CertificateBody{})
	_, stateTypeOK := nextState.(ClientStateWaitCV)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test success (CertificateRequest)
	nextState, toSend, alert = state.Next(&CertificateRequestBody{})
	_, stateTypeOK = nextState.(ClientStateWaitCert)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test nil message
	_, _, alert = state.Next(nil)
	assertEquals(t, alert, AlertUnexpectedMessage)

	// Test unexpected message
	_, _, alert = state.Next(&ClientHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestClientStateWaitCert(t *testing.T) {
	state := ClientStateWaitCert{state: &connectionState{}}

	// Test success
	nextState, toSend, alert := state.Next(&CertificateBody{})
	_, stateTypeOK := nextState.(ClientStateWaitCV)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test unexpected message
	_, _, alert = state.Next(&ClientHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestClientStateWaitCV(t *testing.T) {
	state := ClientStateWaitCV{state: &connectionState{}}

	// Test success
	nextState, toSend, alert := state.Next(&CertificateVerifyBody{})
	_, stateTypeOK := nextState.(ClientStateWaitFinished)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test unexpected message
	_, _, alert = state.Next(&ClientHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestClientStateWaitFinished(t *testing.T) {
	state := ClientStateWaitFinished{state: &connectionState{}}

	// Test success
	nextState, _, alert := state.Next(&FinishedBody{})
	_, stateTypeOK := nextState.(StateConnected)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, alert, AlertNoAlert)

	// Test unexpected message
	_, _, alert = state.Next(&ClientHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

//////////

func TestServerStateStart(t *testing.T) {
	state := ServerStateStart{state: &connectionState{
		Caps: Capabilities{
			Groups:           []NamedGroup{P256},
			SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
			PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
			CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
			PSKs:             &PSKMapCache{},
			Certificates:     certificates,
		},
	}}

	ch := &ClientHelloBody{
		CipherSuites: []CipherSuite{TLS_AES_128_GCM_SHA256},
		Extensions: []Extension{
			{
				ExtensionType: ExtensionTypeSupportedVersions,
				ExtensionData: unhex("027f12"),
			},
			{
				ExtensionType: ExtensionTypeServerName,
				ExtensionData: unhex("000e00000b6578616d706c652e636f6d"),
			},
			{
				ExtensionType: ExtensionTypeKeyShare,
				ExtensionData: unhex("00450017004104754cbbf711d89a4e272bc3685c50fbcd0e5b7db9518433fafc" +
					"11a10ecd4408cb48c5292b2da7977ef934148bb5a875b6b133dcf28e9973b33e" +
					"6d6e8a2bdac809"),
			},
			{
				ExtensionType: ExtensionTypeSupportedGroups,
				ExtensionData: unhex("00020017"),
			},
			{
				ExtensionType: ExtensionTypeSignatureAlgorithms,
				ExtensionData: unhex("00020804"),
			},
			{
				ExtensionType: ExtensionTypePSKKeyExchangeModes,
				ExtensionData: unhex("0101"),
			},
			{
				ExtensionType: ExtensionTypeALPN,
				ExtensionData: unhex("0003026832"),
			},
		},
	}

	chRandom := unhex("d1e2089c3d5ac0fddba4b1a19661f146843f5f475889152236d73191b33039f3")
	copy(ch.Random[:], chRandom)

	// Test success (normal)
	// NB: This falls through a few additional states
	//	ServerStateStart
	//	-> ServerStateNegotiated{Using0xRTT: false}
	//	-> ServerStateWaitFlight2{UsingClientAuth: false}
	//	-> ServerStateWaitFinished{}
	state.state.Caps.RequireCookie = false
	nextState, toSend, alert := state.Next(ch)
	_, stateTypeOK := nextState.(ServerStateWaitFinished)
	assert(t, stateTypeOK, "Incorrect next state type")
	assert(t, len(toSend) >= 1, "No messages provided to send")
	assertEquals(t, alert, AlertNoAlert)
	// TODO: Verify that parameters are negotiated as expected

	// Test success (HelloRetryRequest)
	state.state.Caps.RequireCookie = true
	nextState, toSend, alert = state.Next(ch)
	_, stateTypeOK = nextState.(ServerStateStart)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 1)
	assertEquals(t, toSend[0].Type(), HandshakeTypeHelloRetryRequest)
	assertEquals(t, alert, AlertNoAlert)

	// Test unexpected message
	_, _, alert = state.Next(&ServerHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestServerStateNegotiated(t *testing.T) {
	initState := connectionState{
		Caps: Capabilities{
			SignatureSchemes:  []SignatureScheme{ECDSA_P256_SHA256},
			RequireClientAuth: true,
		},
		Params: ConnectionParameters{
			CipherSuite:    TLS_AES_128_GCM_SHA256,
			NextProto:      "h2",
			UsingDH:        true,
			UsingPSK:       false,
			UsingEarlyData: false,
		},

		cert:       certificates[0],
		certScheme: RSA_PSS_SHA256,
		dhGroup:    P256,
		dhPublic: unhex("0453878857547c46a2be0f6a7ed624685616047913a2d9ef8f7d80bfff0f7c2d" +
			"9ad689c09cebb6f181ca2f26993ecdbf13aab10b04d6f8d16836b6050d90a126c5"),
		dhSecret: unhex("0000000000000000000000000000000000000000000000000000000000000000"),

		clientHello:       &HandshakeMessage{msgType: HandshakeTypeClientHello, body: []byte{}},
		helloRetryRequest: &HandshakeMessage{msgType: HandshakeTypeHelloRetryRequest, body: []byte{}},
		retryClientHello:  &HandshakeMessage{msgType: HandshakeTypeClientHello, body: []byte{}},
	}

	// Test success (normal)
	// NB: This falls through a few additional states
	// ServerStateNegotiated
	//	-> ServerStateWaitFlight2{UsingClientAuth: false}
	//	-> ServerStateWaitCert{}
	connState1 := initState
	state := ServerStateNegotiated{state: &connState1}
	state.state.Params.UsingEarlyData = false
	nextState, toSend, alert := state.Next(nil)
	_, stateTypeOK := nextState.(ServerStateWaitCert)
	t.Logf("%+v", nextState)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 6)
	assertEquals(t, toSend[0].Type(), HandshakeTypeServerHello)
	assertEquals(t, toSend[1].Type(), HandshakeTypeEncryptedExtensions)
	assertEquals(t, toSend[2].Type(), HandshakeTypeCertificateRequest)
	assertEquals(t, toSend[3].Type(), HandshakeTypeCertificate)
	assertEquals(t, toSend[4].Type(), HandshakeTypeCertificateVerify)
	assertEquals(t, toSend[5].Type(), HandshakeTypeFinished)
	assertEquals(t, alert, AlertNoAlert)

	fmt.Printf("!!! %+v\n", toSend[0])

	// Test success (0xRTT)
	connState2 := initState
	state = ServerStateNegotiated{state: &connState2}
	state.state.Params.UsingEarlyData = true
	nextState, toSend, alert = state.Next(nil)
	_, stateTypeOK = nextState.(ServerStateWaitEOED)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 6)
	assertEquals(t, toSend[0].Type(), HandshakeTypeServerHello)
	assertEquals(t, toSend[1].Type(), HandshakeTypeEncryptedExtensions)
	assertEquals(t, toSend[2].Type(), HandshakeTypeCertificateRequest)
	assertEquals(t, toSend[3].Type(), HandshakeTypeCertificate)
	assertEquals(t, toSend[4].Type(), HandshakeTypeCertificateVerify)
	assertEquals(t, toSend[5].Type(), HandshakeTypeFinished)
	assertEquals(t, alert, AlertNoAlert)

	// Test unexpected message
	_, _, alert = state.Next(&ServerHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestServerStateWaitEOED(t *testing.T) {
	state := ServerStateWaitEOED{state: &connectionState{}}

	// Test success
	nextState, toSend, alert := state.Next(&EndOfEarlyDataBody{})
	_, stateTypeOK := nextState.(ServerStateWaitFinished)
	t.Logf("%+v", nextState)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test unexpected message
	_, _, alert = state.Next(&ServerHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestServerStateWaitFlight2(t *testing.T) {
	state := ServerStateWaitFlight2{state: &connectionState{}}

	// Test success (normal)
	state.state.Params.UsingClientAuth = false
	nextState, toSend, alert := state.Next(nil)
	_, stateTypeOK := nextState.(ServerStateWaitFinished)
	t.Logf("%+v", nextState)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test success (client auth)
	state.state.Params.UsingClientAuth = true
	nextState, toSend, alert = state.Next(nil)
	_, stateTypeOK = nextState.(ServerStateWaitCert)
	t.Logf("%+v", nextState)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test unexpected message
	_, _, alert = state.Next(&ServerHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestServerStateWaitCert(t *testing.T) {
	state := ServerStateWaitCert{state: &connectionState{}}

	// Test success (normal)
	state.CertificateEmpty = false
	nextState, toSend, alert := state.Next(&CertificateBody{})
	_, stateTypeOK := nextState.(ServerStateWaitCV)
	t.Logf("%+v", nextState)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test success (empty certificate)
	state.CertificateEmpty = true
	nextState, toSend, alert = state.Next(&CertificateBody{})
	_, stateTypeOK = nextState.(ServerStateWaitFinished)
	t.Logf("%+v", nextState)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test unexpected message
	_, _, alert = state.Next(&ServerHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestServerStateWaitCV(t *testing.T) {
	state := ServerStateWaitCV{state: &connectionState{}}

	// Test success
	nextState, toSend, alert := state.Next(&CertificateVerifyBody{})
	_, stateTypeOK := nextState.(ServerStateWaitFinished)
	t.Logf("%+v", nextState)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test unexpected message
	_, _, alert = state.Next(&ServerHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestServerStateWaitFinished(t *testing.T) {
	state := ServerStateWaitFinished{state: &connectionState{}}

	// Test success
	nextState, toSend, alert := state.Next(&FinishedBody{})
	_, stateTypeOK := nextState.(StateConnected)
	t.Logf("%+v", nextState)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test unexpected message
	_, _, alert = state.Next(&ServerHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

//////////

func TestConnectedState(t *testing.T) {
	state := StateConnected{state: &connectionState{}}

	// TODO: Test KeyUpdate
	nextState, toSend, alert := state.Next(&KeyUpdateBody{})
	assertEquals(t, nextState, state)
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// TODO: Test NewSessionTicket
	nextState, toSend, alert = state.Next(&NewSessionTicketBody{})
	assertEquals(t, nextState, state)
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test nil message
	_, _, alert = state.Next(nil)
	assertEquals(t, alert, AlertUnexpectedMessage)

	// Test Unexpected message type
	_, _, alert = state.Next(&ClientHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}
