package mint

import (
	"fmt"
	"reflect"
	"testing"
)

var (
	stateMachineIntegrationCases = map[string]struct {
		clientConnState     *connectionState
		serverConnState     *connectionState
		clientStateSequence []HandshakeState
		serverStateSequence []HandshakeState
	}{
		"normal": {
			clientConnState: &connectionState{
				Caps: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
				},
				Opts: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				},
			},
			serverConnState: &connectionState{
				Caps: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
					Certificates:     certificates,
				},
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
				ServerStateWaitFinished{},
				StateConnected{},
			},
		},

		"helloRetryRequest": {
			clientConnState: &connectionState{
				Caps: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
				},
				Opts: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				},
			},
			serverConnState: &connectionState{
				Caps: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
					Certificates:     certificates,
					RequireCookie:    true,
				},
			},
			clientStateSequence: []HandshakeState{
				ClientStateStart{},
				ClientStateWaitSH{},
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
				ServerStateWaitFinished{},
				StateConnected{},
			},
		},

		// PSK case, no early data
		"psk": {
			clientConnState: &connectionState{
				Caps: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs: &PSKMapCache{
						"example.com": psk,
					},
				},
				Opts: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				},
			},
			serverConnState: &connectionState{
				Caps: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs: &PSKMapCache{
						"00010203": psk,
					},
					Certificates: certificates,
				},
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
				ServerStateWaitFinished{},
				StateConnected{},
			},
		},

		// PSK case, with early data
		"pskWithEarlyData": {
			clientConnState: &connectionState{
				Caps: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs: &PSKMapCache{
						"example.com": psk,
					},
				},
				Opts: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
					EarlyData:  []byte{0, 1, 2, 3},
				},
			},
			serverConnState: &connectionState{
				Caps: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs: &PSKMapCache{
						"00010203": psk,
					},
					Certificates: certificates,
				},
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
				ServerStateWaitEOED{},
				ServerStateWaitFinished{},
				StateConnected{},
			},
		},

		// PSK case, server rejects PSK
		"pskRejected": {
			clientConnState: &connectionState{
				Caps: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs: &PSKMapCache{
						"example.com": psk,
					},
				},
				Opts: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				},
			},
			serverConnState: &connectionState{
				Caps: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
					Certificates:     certificates,
				},
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
				ServerStateWaitFinished{},
				StateConnected{},
			},
		},

		// Client auth, successful
		"clientAuth": {
			clientConnState: &connectionState{
				Caps: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
					Certificates:     certificates,
				},
				Opts: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				},
			},
			serverConnState: &connectionState{
				Caps: Capabilities{
					Groups:            []NamedGroup{P256},
					SignatureSchemes:  []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:          []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:      []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:              &PSKMapCache{},
					Certificates:      certificates,
					RequireClientAuth: true,
				},
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
				ServerStateWaitCert{},
				ServerStateWaitCV{},
				ServerStateWaitFinished{},
				StateConnected{},
			},
		},

		// Client auth, no certificate found
		"clientAuthNoCertificate": {
			clientConnState: &connectionState{
				Caps: Capabilities{
					Groups:           []NamedGroup{P256},
					SignatureSchemes: []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:         []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:     []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:             &PSKMapCache{},
				},
				Opts: ConnectionOptions{
					ServerName: "example.com",
					NextProtos: []string{"h2"},
				},
			},
			serverConnState: &connectionState{
				Caps: Capabilities{
					Groups:            []NamedGroup{P256},
					SignatureSchemes:  []SignatureScheme{RSA_PSS_SHA256},
					PSKModes:          []PSKKeyExchangeMode{PSKModeDHEKE},
					CipherSuites:      []CipherSuite{TLS_AES_128_GCM_SHA256},
					PSKs:              &PSKMapCache{},
					Certificates:      certificates,
					RequireClientAuth: true,
				},
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
				ServerStateWaitCert{},
				ServerStateWaitFinished{},
				StateConnected{},
			},
		},
	}
)

// TODO: Track instructions other than state changes
func messagesFromInstructions(instructions []HandshakeInstruction) []*HandshakeMessage {
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
	for caseName, params := range stateMachineIntegrationCases {
		t.Logf("=== Integration Test (%s) ===", caseName)

		var clientState, serverState HandshakeState
		clientState = ClientStateStart{state: params.clientConnState}
		serverState = ServerStateStart{state: params.serverConnState}
		t.Logf("Client: %s", reflect.TypeOf(clientState).Name())
		t.Logf("Server: %s", reflect.TypeOf(serverState).Name())

		clientStateSequence := []HandshakeState{clientState}
		serverStateSequence := []HandshakeState{serverState}

		// Create the ClientHello
		clientState, clientInstr, alert := clientState.Next(nil)
		clientToSend := messagesFromInstructions(clientInstr)
		assertEquals(t, alert, AlertNoAlert)
		t.Logf("Client: %s", reflect.TypeOf(clientState).Name())
		clientStateSequence = append(clientStateSequence, clientState)
		assertEquals(t, len(clientToSend), 1)

		for {
			var clientInstr, serverInstr []HandshakeInstruction
			var alert Alert

			// Client -> Server
			serverToSend := []*HandshakeMessage{}
			for _, body := range clientToSend {
				t.Logf("C->S: %d", body.msgType)
				serverState, serverInstr, alert = serverState.Next(body)
				serverResponses := messagesFromInstructions(serverInstr)
				assert(t, alert == AlertNoAlert, fmt.Sprintf("Alert from server [%v]", alert))
				serverStateSequence = append(serverStateSequence, serverState)
				t.Logf("Server: %s", reflect.TypeOf(serverState).Name())
				serverToSend = append(serverToSend, serverResponses...)
			}

			// Server -> Client
			clientToSend = []*HandshakeMessage{}
			for _, body := range serverToSend {
				t.Logf("S->C: %d", body.msgType)
				clientState, clientInstr, alert = clientState.Next(body)
				clientResponses := messagesFromInstructions(clientInstr)
				assert(t, alert == AlertNoAlert, fmt.Sprintf("Alert from client [%v]", alert))
				clientStateSequence = append(clientStateSequence, clientState)
				t.Logf("Client: %s", reflect.TypeOf(clientState).Name())
				clientToSend = append(clientToSend, clientResponses...)
			}

			clientConnected := reflect.TypeOf(clientState) == reflect.TypeOf(StateConnected{})
			serverConnected := reflect.TypeOf(serverState) == reflect.TypeOf(StateConnected{})
			if clientConnected && serverConnected {
				c := clientState.(StateConnected)
				s := serverState.(StateConnected)

				// Test that we ended up at the same state
				assertDeepEquals(t, c.state.Params, s.state.Params)
				assertContextEquals(t, &c.state.Context, &s.state.Context)

				// Test that the client went through the expected sequence of states
				//assertEquals(t, len(clientStateSequence), len(params.clientStateSequence))
				for i, state := range clientStateSequence {
					t.Logf("-- %d %s", i, reflect.TypeOf(state).Name())
					//assertSameType(t, state, params.clientStateSequence[i])
				}

				// Test that the server went through the expected sequence of states
				assertEquals(t, len(serverStateSequence), len(params.serverStateSequence))
				for i, state := range serverStateSequence {
					assertSameType(t, state, params.serverStateSequence[i])
				}

				break
			}

			clientStateName := reflect.TypeOf(clientState).Name()
			serverStateName := reflect.TypeOf(serverState).Name()
			if len(clientToSend) == 0 {
				t.Fatalf("Deadlock at client=[%s] server=[%s]", clientStateName, serverStateName)
			}
		}
	}
}
