package mint

import (
	"testing"
)

func TestClientStateStart(t *testing.T) {
	state := ClientStateStart{}

	// Test success (first try)
	nextState, toSend, alert := state.Next(nil)
	assertEquals(t, nextState, ClientStateWaitSH{})
	assertEquals(t, len(toSend), 1)
	assertEquals(t, toSend[0].Type(), HandshakeTypeClientHello)
	assertEquals(t, alert, AlertNoAlert)

	// TODO: Test with cookie / HRR

	// Test non-nil message
	_, _, alert = state.Next(&ClientHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestClientStateWaitSH(t *testing.T) {
	state := ClientStateWaitSH{}

	// Test success (HelloRetryRequest)
	nextState, toSend, alert := state.Next(&HelloRetryRequestBody{})
	_, stateTypeOK := nextState.(ClientStateWaitSH)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 1)
	assertEquals(t, toSend[0].Type(), HandshakeTypeClientHello)
	assertEquals(t, alert, AlertNoAlert)

	// Test success (ServerHello)
	nextState, toSend, alert = state.Next(&ServerHelloBody{})
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
	state := ClientStateWaitEE{}

	// Test success (PSK)
	state.UsingPSK = true
	nextState, toSend, alert := state.Next(&EncryptedExtensionsBody{})
	_, stateTypeOK := nextState.(ClientStateWaitFinished)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test success (no PSK)
	state.UsingPSK = false
	nextState, toSend, alert = state.Next(&EncryptedExtensionsBody{})
	_, stateTypeOK = nextState.(ClientStateWaitCertCR)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test unexpected message
	_, _, alert = state.Next(&ClientHelloBody{})
	assertEquals(t, alert, AlertUnexpectedMessage)
}

func TestClientStateWaitCertCR(t *testing.T) {
	state := ClientStateWaitCertCR{}

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
	state := ClientStateWaitCert{}

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
	state := ClientStateWaitCV{}

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
	state := ClientStateWaitFinished{}

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
	state := ServerStateStart{}

	// Test success (normal)
	// NB: This falls through a few additional states
	//	ServerStateStart
	//	-> ServerStateNegotiated{Using0xRTT: false}
	//	-> ServerStateWaitFlight2{UsingClientAuth: false}
	//	-> ServerStateWaitFinished{}
	state.SendHRR = false
	nextState, toSend, alert := state.Next(&ClientHelloBody{})
	_, stateTypeOK := nextState.(ServerStateWaitFinished)
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

	// Test success (HelloRetryRequest)
	state.SendHRR = true
	nextState, toSend, alert = state.Next(&ClientHelloBody{})
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
	state := ServerStateNegotiated{}

	// Test success (normal)
	// NB: This falls through a few additional states
	// ServerStateNegotiated
	//	-> ServerStateWaitFlight2{UsingClientAuth: false}
	//	-> ServerStateWaitFinished{}
	state.Using0xRTT = false
	nextState, toSend, alert := state.Next(nil)
	_, stateTypeOK := nextState.(ServerStateWaitFinished)
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

	// Test success (0xRTT)
	state.Using0xRTT = true
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
	state := ServerStateWaitEOED{}

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
	state := ServerStateWaitFlight2{}

	// Test success (normal)
	state.UsingClientAuth = false
	nextState, toSend, alert := state.Next(nil)
	_, stateTypeOK := nextState.(ServerStateWaitFinished)
	t.Logf("%+v", nextState)
	assert(t, stateTypeOK, "Incorrect next state type")
	assertEquals(t, len(toSend), 0)
	assertEquals(t, alert, AlertNoAlert)

	// Test success (client auth)
	state.UsingClientAuth = true
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
	state := ServerStateWaitCert{}

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
	state := ServerStateWaitCV{}

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
	state := ServerStateWaitFinished{}

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
	state := StateConnected{}

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
