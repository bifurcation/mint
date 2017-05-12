package mint

import (
	"time"
)

// Marker interface for actions that an implementation should take based on
// state transitions.
type HandshakeAction interface{}

type SendHandshakeMessage struct {
	Message *HandshakeMessage
}

type SendEarlyData struct{}

type ReadEarlyData struct{}

type ReadPastEarlyData struct{}

type RekeyIn struct {
	Label  string
	KeySet keySet
}

type RekeyOut struct {
	Label  string
	KeySet keySet
}

type StorePSK struct {
	PSK PreSharedKey
}

type HandshakeState interface {
	Next(hm *HandshakeMessage) (HandshakeState, []HandshakeAction, Alert)
}

// Capabilities objects represent the capabilities of a TLS client or server,
// as an input to TLS negotiation
type Capabilities struct {
	// For both client and server
	CipherSuites     []CipherSuite
	Groups           []NamedGroup
	SignatureSchemes []SignatureScheme
	PSKs             PreSharedKeyCache
	Certificates     []*Certificate
	AuthCertificate  func(chain []CertificateEntry) error

	// For client
	PSKModes []PSKKeyExchangeMode

	// For server
	NextProtos        []string
	AllowEarlyData    bool
	RequireCookie     bool
	RequireClientAuth bool
}

// ConnectionOptions objects represent per-connection settings for a client
// initiating a connection
type ConnectionOptions struct {
	ServerName string
	NextProtos []string
	EarlyData  []byte
}

// ConnectionParameters objects represent the parameters negotiated for a
// connection.
type ConnectionParameters struct {
	UsingPSK               bool
	UsingDH                bool
	ClientSendingEarlyData bool
	UsingEarlyData         bool
	UsingClientAuth        bool

	CipherSuite CipherSuite
	ServerName  string
	NextProto   string
}

// StateConnected is symmetric between client and server
type StateConnected struct {
	Params              ConnectionParameters
	isClient            bool
	cryptoParams        cipherSuiteParams
	resumptionSecret    []byte
	clientTrafficSecret []byte
	serverTrafficSecret []byte
}

func (state *StateConnected) KeyUpdate(request KeyUpdateRequest) ([]HandshakeAction, Alert) {
	var trafficKeys keySet
	if state.isClient {
		state.clientTrafficSecret = hkdfExpandLabel(state.cryptoParams.hash, state.clientTrafficSecret,
			labelClientApplicationTrafficSecret, []byte{}, state.cryptoParams.hash.Size())
		trafficKeys = makeTrafficKeys(state.cryptoParams, state.clientTrafficSecret)
	} else {
		state.serverTrafficSecret = hkdfExpandLabel(state.cryptoParams.hash, state.serverTrafficSecret,
			labelServerApplicationTrafficSecret, []byte{}, state.cryptoParams.hash.Size())
		trafficKeys = makeTrafficKeys(state.cryptoParams, state.serverTrafficSecret)
	}

	kum, err := HandshakeMessageFromBody(&KeyUpdateBody{KeyUpdateRequest: request})
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error marshaling key update message: %v", err)
		return nil, AlertInternalError
	}

	toSend := []HandshakeAction{
		SendHandshakeMessage{kum},
		RekeyOut{Label: "update", KeySet: trafficKeys},
	}
	return toSend, AlertNoAlert
}

func (state *StateConnected) NewSessionTicket(length int, lifetime, earlyDataLifetime uint32) ([]HandshakeAction, Alert) {
	tkt, err := NewSessionTicket(length, lifetime)
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error generating NewSessionTicket: %v", err)
		return nil, AlertInternalError
	}

	err = tkt.Extensions.Add(&TicketEarlyDataInfoExtension{earlyDataLifetime})
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error adding extension to NewSessionTicket: %v", err)
		return nil, AlertInternalError
	}

	newPSK := PreSharedKey{
		CipherSuite:  state.cryptoParams.suite,
		IsResumption: true,
		Identity:     tkt.Ticket,
		Key:          state.resumptionSecret,
		NextProto:    state.Params.NextProto,
		ReceivedAt:   time.Now(),
		ExpiresAt:    time.Now().Add(time.Duration(tkt.TicketLifetime) * time.Second),
		TicketAgeAdd: tkt.TicketAgeAdd,
	}

	tktm, err := HandshakeMessageFromBody(tkt)
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error marshaling NewSessionTicket: %v", err)
		return nil, AlertInternalError
	}

	toSend := []HandshakeAction{
		StorePSK{newPSK},
		SendHandshakeMessage{tktm},
	}
	return toSend, AlertNoAlert
}

func (state StateConnected) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeAction, Alert) {
	if hm == nil {
		logf(logTypeHandshake, "[StateConnected] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	bodyGeneric, err := hm.ToBody()
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	switch body := bodyGeneric.(type) {
	case *KeyUpdateBody:
		var trafficKeys keySet
		if !state.isClient {
			state.clientTrafficSecret = hkdfExpandLabel(state.cryptoParams.hash, state.clientTrafficSecret,
				labelClientApplicationTrafficSecret, []byte{}, state.cryptoParams.hash.Size())
			trafficKeys = makeTrafficKeys(state.cryptoParams, state.clientTrafficSecret)
		} else {
			state.serverTrafficSecret = hkdfExpandLabel(state.cryptoParams.hash, state.serverTrafficSecret,
				labelServerApplicationTrafficSecret, []byte{}, state.cryptoParams.hash.Size())
			trafficKeys = makeTrafficKeys(state.cryptoParams, state.serverTrafficSecret)
		}

		toSend := []HandshakeAction{RekeyIn{Label: "update", KeySet: trafficKeys}}

		// If requested, roll outbound keys and send a KeyUpdate
		if body.KeyUpdateRequest == KeyUpdateRequested {
			moreToSend, alert := state.KeyUpdate(KeyUpdateNotRequested)
			if alert != AlertNoAlert {
				return nil, nil, alert
			}

			toSend = append(toSend, moreToSend...)
		}

		return state, toSend, AlertNoAlert

	case *NewSessionTicketBody:
		// XXX: Allow NewSessionTicket in both directions?
		if !state.isClient {
			return nil, nil, AlertUnexpectedMessage
		}

		psk := PreSharedKey{
			CipherSuite:  state.cryptoParams.suite,
			IsResumption: true,
			Identity:     body.Ticket,
			Key:          state.resumptionSecret,
			NextProto:    state.Params.NextProto,
			ReceivedAt:   time.Now(),
			ExpiresAt:    time.Now().Add(time.Duration(body.TicketLifetime) * time.Second),
			TicketAgeAdd: body.TicketAgeAdd,
		}

		toSend := []HandshakeAction{StorePSK{psk}}
		return state, toSend, AlertNoAlert
	}

	logf(logTypeHandshake, "[StateConnected] Unexpected message type %v", hm.msgType)
	return nil, nil, AlertUnexpectedMessage
}
