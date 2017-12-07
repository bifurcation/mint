package mint

import (
	"fmt"
	"reflect"
	"testing"
)

type mockHandshakeMessageReader struct {
	queue []*HandshakeMessage
}

var _ handshakeMessageReader = &mockHandshakeMessageReader{}

func (m *mockHandshakeMessageReader) ReadMessage() (*HandshakeMessage, Alert) {
	if len(m.queue) == 0 {
		return nil, AlertWouldBlock
	}
	message := m.queue[0]
	m.queue = m.queue[1:]
	return message, AlertNoAlert
}

// TODO: Track instructions other than state changes
func messagesFromActions(instructions []HandshakeAction) []*HandshakeMessage {
	msgs := []*HandshakeMessage{}
	for _, instr := range instructions {
		msg, ok := instr.(SendHandshakeMessage)
		if !ok {
			continue
		}
		msgs = append(msgs, msg.Message)
	}
	return msgs
}

// TODO: Unit tests for individual states
func TestStateMachineIntegration(t *testing.T) {
	cookieProtector, err := NewDefaultCookieProtector()
	assertNotError(t, err, "error creating cookie source")

	var (
		stateMachineIntegrationCases = map[string]struct {
			clientCapabilities  Capabilities
			clientOptions       ConnectionOptions
			serverCapabilities  Capabilities
			clientStateSequence []HandshakeState
			serverStateSequence []HandshakeState
		}{
			"normal": {
				clientCapabilities: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
				},
				clientOptions: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				},
				serverCapabilities: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
					Certificates:     certificates,
					CookieProtector:  cookieProtector,
				},
				clientStateSequence: []HandshakeState{
					ClientStateStart{},
					ClientStateWaitSH{},
					ClientStateWaitEE{},
					ClientStateWaitCertCR{},
					ClientStateWaitCV{},
					ClientStateWaitFinished{},
					StateConnected{},
				},
				serverStateSequence: []HandshakeState{
					ServerStateStart{},
					ServerStateNegotiated{},
					ServerStateWaitFlight2{},
					ServerStateWaitFinished{},
					StateConnected{},
				},
			},

			"helloRetryRequest": {
				clientCapabilities: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
				},
				clientOptions: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				},
				serverCapabilities: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
					Certificates:     certificates,
					RequireCookie:    true,
					CookieProtector:  cookieProtector,
				},
				clientStateSequence: []HandshakeState{
					ClientStateStart{},
					ClientStateWaitSH{},
					ClientStateStart{},
					ClientStateWaitSH{},
					ClientStateWaitEE{},
					ClientStateWaitCertCR{},
					ClientStateWaitCV{},
					ClientStateWaitFinished{},
					StateConnected{},
				},
				serverStateSequence: []HandshakeState{
					ServerStateStart{},
					ServerStateStart{},
					ServerStateNegotiated{},
					ServerStateWaitFlight2{},
					ServerStateWaitFinished{},
					StateConnected{},
				},
			},

			// PSK case, no early data
			"psk": {
				clientCapabilities: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs: &PSKMapCache{
						"example.com": psk,
					},
				},
				clientOptions: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				},
				serverCapabilities: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs: &PSKMapCache{
						"00010203": psk,
					},
					Certificates: certificates,
				},
				clientStateSequence: []HandshakeState{
					ClientStateStart{},
					ClientStateWaitSH{},
					ClientStateWaitEE{},
					ClientStateWaitFinished{},
					StateConnected{},
				},
				serverStateSequence: []HandshakeState{
					ServerStateStart{},
					ServerStateNegotiated{},
					ServerStateWaitFlight2{},
					ServerStateWaitFinished{},
					StateConnected{},
				},
			},

			// PSK case, with early data
			"pskWithEarlyData": {
				clientCapabilities: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs: &PSKMapCache{
						"example.com": psk,
					},
				},
				clientOptions: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
					EarlyData:  []byte{0, 1, 2, 3},
				},
				serverCapabilities: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs: &PSKMapCache{
						"00010203": psk,
					},
					Certificates:   certificates,
					AllowEarlyData: true,
				},
				clientStateSequence: []HandshakeState{
					ClientStateStart{},
					ClientStateWaitSH{},
					ClientStateWaitEE{},
					ClientStateWaitFinished{},
					StateConnected{},
				},
				serverStateSequence: []HandshakeState{
					ServerStateStart{},
					ServerStateNegotiated{},
					ServerStateWaitEOED{},
					ServerStateWaitFlight2{},
					ServerStateWaitFinished{},
					StateConnected{},
				},
			},

			// PSK case, server rejects PSK
			"pskRejected": {
				clientCapabilities: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs: &PSKMapCache{
						"example.com": psk,
					},
				},
				clientOptions: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				},
				serverCapabilities: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
					Certificates:     certificates,
				},
				clientStateSequence: []HandshakeState{
					ClientStateStart{},
					ClientStateWaitSH{},
					ClientStateWaitEE{},
					ClientStateWaitCertCR{},
					ClientStateWaitCV{},
					ClientStateWaitFinished{},
					StateConnected{},
				},
				serverStateSequence: []HandshakeState{
					ServerStateStart{},
					ServerStateNegotiated{},
					ServerStateWaitFlight2{},
					ServerStateWaitFinished{},
					StateConnected{},
				},
			},

			// Client auth, successful
			"clientAuth": {
				clientCapabilities: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
					Certificates:     certificates,
				},
				clientOptions: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				},
				serverCapabilities: Capabilities{
					Groups:            []NamedGroup{P256},
					SignatureSchemes:  []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:          []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:      []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:              &PSKMapCache{},
					Certificates:      certificates,
					RequireClientAuth: true,
				},
				clientStateSequence: []HandshakeState{
					ClientStateStart{},
					ClientStateWaitSH{},
					ClientStateWaitEE{},
					ClientStateWaitCertCR{},
					ClientStateWaitCert{},
					ClientStateWaitCV{},
					ClientStateWaitFinished{},
					StateConnected{},
				},
				serverStateSequence: []HandshakeState{
					ServerStateStart{},
					ServerStateNegotiated{},
					ServerStateWaitFlight2{},
					ServerStateWaitCert{},
					ServerStateWaitCV{},
					ServerStateWaitFinished{},
					StateConnected{},
				},
			},

			// Client auth, no certificate found
			"clientAuthNoCertificate": {
				clientCapabilities: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
				},
				clientOptions: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				},
				serverCapabilities: Capabilities{
					Groups:            []NamedGroup{P256},
					SignatureSchemes:  []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:          []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:      []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:              &PSKMapCache{},
					Certificates:      certificates,
					RequireClientAuth: true,
				},
				clientStateSequence: []HandshakeState{
					ClientStateStart{},
					ClientStateWaitSH{},
					ClientStateWaitEE{},
					ClientStateWaitCertCR{},
					ClientStateWaitCert{},
					ClientStateWaitCV{},
					ClientStateWaitFinished{},
					StateConnected{},
				},
				serverStateSequence: []HandshakeState{
					ServerStateStart{},
					ServerStateNegotiated{},
					ServerStateWaitFlight2{},
					ServerStateWaitCert{},
					ServerStateWaitFinished{},
					StateConnected{},
				},
			},
		}
	)

	for caseName, params := range stateMachineIntegrationCases {
		t.Run(caseName, func(t *testing.T) {
			var clientState, serverState HandshakeState
			clientState = ClientStateStart{
				Caps: params.clientCapabilities,
				Opts: params.clientOptions,
			}
			serverState = ServerStateStart{Caps: params.serverCapabilities}
			t.Logf("Client: %s", reflect.TypeOf(clientState).Name())
			t.Logf("Server: %s", reflect.TypeOf(serverState).Name())

			clientStateSequence := []HandshakeState{clientState}
			serverStateSequence := []HandshakeState{serverState}

			serverHandshakeMessageReader := &mockHandshakeMessageReader{}
			clientHandshakeMessageReader := &mockHandshakeMessageReader{}

			// Create the ClientHello
			clientState, clientInstr, alert := clientState.Next(nil)
			serverHandshakeMessageReader.queue = append(serverHandshakeMessageReader.queue, messagesFromActions(clientInstr)...)
			assertEquals(t, alert, AlertNoAlert)
			t.Logf("Client: %s", reflect.TypeOf(clientState).Name())
			clientStateSequence = append(clientStateSequence, clientState)
			assertEquals(t, len(serverHandshakeMessageReader.queue), 1)

			for {
				var clientInstr, serverInstr []HandshakeAction
				var alert Alert

				// Client -> Server
				for {
					if _, connected := serverState.(StateConnected); connected {
						break
					}
					var nextState HandshakeState
					nextState, serverInstr, alert = serverState.Next(serverHandshakeMessageReader)
					if alert == AlertWouldBlock {
						break
					}
					serverState = nextState
					serverResponses := messagesFromActions(serverInstr)
					assert(t, alert == AlertNoAlert || alert == AlertStatelessRetry, fmt.Sprintf("Alert from server [%v]", alert))
					serverStateSequence = append(serverStateSequence, serverState)
					t.Logf("Server: %s", reflect.TypeOf(serverState).Name())
					clientHandshakeMessageReader.queue = append(clientHandshakeMessageReader.queue, serverResponses...)
				}

				// Server -> Client
				for {
					if _, connected := clientState.(StateConnected); connected {
						break
					}
					var nextState HandshakeState
					nextState, clientInstr, alert = clientState.Next(clientHandshakeMessageReader)
					if alert == AlertWouldBlock {
						break
					}
					clientState = nextState
					clientResponses := messagesFromActions(clientInstr)
					assert(t, alert == AlertNoAlert, fmt.Sprintf("Alert from client [%v]", alert))
					clientStateSequence = append(clientStateSequence, clientState)
					t.Logf("Client: %s", reflect.TypeOf(clientState).Name())
					serverHandshakeMessageReader.queue = append(serverHandshakeMessageReader.queue, clientResponses...)
				}

				clientConnected := reflect.TypeOf(clientState) == reflect.TypeOf(StateConnected{})
				serverConnected := reflect.TypeOf(serverState) == reflect.TypeOf(StateConnected{})
				if clientConnected && serverConnected {
					c := clientState.(StateConnected)
					s := serverState.(StateConnected)

					// Test that we ended up at the same state
					assertDeepEquals(t, c.Params, s.Params)
					assertCipherSuiteParamsEquals(t, c.cryptoParams, s.cryptoParams)
					assertByteEquals(t, c.resumptionSecret, s.resumptionSecret)
					assertByteEquals(t, c.clientTrafficSecret, s.clientTrafficSecret)
					assertByteEquals(t, c.serverTrafficSecret, s.serverTrafficSecret)

					// Test that the client went through the expected sequence of states
					assertEquals(t, len(clientStateSequence), len(params.clientStateSequence))
					for i, state := range clientStateSequence {
						t.Logf("-- %d %s", i, reflect.TypeOf(state).Name())
						assertSameType(t, state, params.clientStateSequence[i])
					}

					// Test that the server went through the expected sequence of states
					assertEquals(t, len(serverStateSequence), len(params.serverStateSequence))
					for i, state := range serverStateSequence {
						t.Logf("-- %d %s", i, reflect.TypeOf(state).Name())
						assertSameType(t, state, params.serverStateSequence[i])
					}

					break
				}
			}
		})
	}
}
