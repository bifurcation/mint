package mint

import (
	"bytes"
	"hash"
	"reflect"
)

// Filler interface for instructions provided on state transitions
type HandshakeInstruction interface{}

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
	Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert)
}

// XXX: We just use a big bucket of all the previously-defined state values for
// now.  We should trim this down to the minimum needed by each state.
type Capabilities struct {
	// For both client and server
	CipherSuites     []CipherSuite
	Groups           []NamedGroup
	SignatureSchemes []SignatureScheme
	PSKs             PreSharedKeyCache
	Certificates     []*Certificate

	// For client
	PSKModes []PSKKeyExchangeMode

	// For server
	NextProtos        []string
	AllowEarlyData    bool
	RequireCookie     bool
	RequireClientAuth bool
}

type ConnectionOptions struct {
	ServerName string
	NextProtos []string
	EarlyData  []byte
}

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

type connectionState struct {
	Conn    *Conn
	Caps    Capabilities
	Opts    ConnectionOptions
	Params  ConnectionParameters
	Context cryptoContext

	AuthCertificate func(chain []CertificateEntry) error

	// Client semi-transient state
	OfferedDH                map[NamedGroup][]byte
	OfferedPSK               PreSharedKey
	PSK                      []byte
	firstClientHello         *HandshakeMessage
	helloRetryRequest        *HandshakeMessage
	clientHello              *HandshakeMessage
	serverHello              *HandshakeMessage
	serverFirstFlight        []*HandshakeMessage
	serverFinished           *HandshakeMessage
	serverHRR                *HelloRetryRequestBody
	serverCertificate        *CertificateBody
	serverCertificateRequest *CertificateRequestBody

	// Server semi-transient state
	cookie             []byte
	cert               *Certificate
	certScheme         SignatureScheme
	dhGroup            NamedGroup
	dhPublic           []byte
	dhSecret           []byte
	selectedPSK        int
	clientSecondFlight []*HandshakeMessage
	clientCertificate  *CertificateBody
}

// Client State Machine
//
//                            START <----+
//             Send ClientHello |        | Recv HelloRetryRequest
//          /                   v        |
//         |                  WAIT_SH ---+
//     Can |                    | Recv ServerHello
//    send |                    V
//   early |                 WAIT_EE
//    data |                    | Recv EncryptedExtensions
//         |           +--------+--------+
//         |     Using |                 | Using certificate
//         |       PSK |                 v
//         |           |            WAIT_CERT_CR
//         |           |        Recv |       | Recv CertificateRequest
//         |           | Certificate |       v
//         |           |             |    WAIT_CERT
//         |           |             |       | Recv Certificate
//         |           |             v       v
//         |           |              WAIT_CV
//         |           |                 | Recv CertificateVerify
//         |           +> WAIT_FINISHED <+
//         |                  | Recv Finished
//         \                  |
//                            | [Send EndOfEarlyData]
//                            | [Send Certificate [+ CertificateVerify]]
//                            | Send Finished
//  Can send                  v
//  app data -->          CONNECTED
//  after
//  here
//
//  State							Instructions
//  START							Send(CH); [RekeyOut; SendEarlyData]
//  WAIT_SH						Send(CH) || RekeyIn
//  WAIT_EE						{}
//  WAIT_CERT_CR			{}
//  WAIT_CERT					{}
//  WAIT_CV						{}
//  WAIT_FINISHED			RekeyIn; [Send(EOED);] RekeyOut; [SendCert; SendCV;] SendFin; RekeyOut;
//  CONNECTED					StoreTicket || (RekeyIn; [RekeyOut])

type ClientStateStart struct {
	state *connectionState
}

func (state ClientStateStart) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm != nil {
		logf(logTypeHandshake, "[ClientStateStart] Unexpected non-nil message")
		return nil, nil, AlertUnexpectedMessage
	}

	// key_shares
	state.state.OfferedDH = map[NamedGroup][]byte{}
	ks := KeyShareExtension{
		HandshakeType: HandshakeTypeClientHello,
		Shares:        make([]KeyShareEntry, len(state.state.Caps.Groups)),
	}
	for i, group := range state.state.Caps.Groups {
		pub, priv, err := newKeyShare(group)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error generating key share [%v]", err)
			return nil, nil, AlertInternalError
		}

		ks.Shares[i].Group = group
		ks.Shares[i].KeyExchange = pub
		state.state.OfferedDH[group] = priv
	}

	// supported_versions, supported_groups, signature_algorithms, server_name
	sv := SupportedVersionsExtension{Versions: []uint16{supportedVersion}}
	sni := ServerNameExtension(state.state.Opts.ServerName)
	sg := SupportedGroupsExtension{Groups: state.state.Caps.Groups}
	sa := SignatureAlgorithmsExtension{Algorithms: state.state.Caps.SignatureSchemes}

	state.state.Params.ServerName = state.state.Opts.ServerName

	// Application Layer Protocol Negotiation
	var alpn *ALPNExtension
	if (state.state.Opts.NextProtos != nil) && (len(state.state.Opts.NextProtos) > 0) {
		alpn = &ALPNExtension{Protocols: state.state.Opts.NextProtos}
	}

	// Construct base ClientHello
	ch := &ClientHelloBody{
		CipherSuites: state.state.Caps.CipherSuites,
	}
	_, err := prng.Read(ch.Random[:])
	if err != nil {
		logf(logTypeHandshake, "[ClientStateStart] Error creating ClientHello random [%v]", err)
		return nil, nil, AlertInternalError
	}
	for _, ext := range []ExtensionBody{&sv, &sni, &ks, &sg, &sa} {
		err := ch.Extensions.Add(ext)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error adding extension type=[%v] [%v]", ext.Type(), err)
			return nil, nil, AlertInternalError
		}
	}
	// XXX: These optional extensions can't be folded into the above because Go
	// interface-typed values are never reported as nil
	if alpn != nil {
		err := ch.Extensions.Add(alpn)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error adding ALPN extension [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	if state.state.cookie != nil {
		err := ch.Extensions.Add(&CookieExtension{Cookie: state.state.cookie})
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error adding ALPN extension [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	// Handle PSK and EarlyData just before transmitting, so that we can
	// calculate the PSK binder value
	var psk *PreSharedKeyExtension
	var ed *EarlyDataExtension
	if key, ok := state.state.Caps.PSKs.Get(state.state.Opts.ServerName); ok {
		state.state.OfferedPSK = key

		// Narrow ciphersuites to ones that match PSK hash
		keyParams, ok := cipherSuiteMap[key.CipherSuite]
		if !ok {
			logf(logTypeHandshake, "[ClientStateStart] PSK for unknown ciphersuite")
			return nil, nil, AlertInternalError
		}

		compatibleSuites := []CipherSuite{}
		for _, suite := range ch.CipherSuites {
			if cipherSuiteMap[suite].hash == keyParams.hash {
				compatibleSuites = append(compatibleSuites, suite)
			}
		}
		ch.CipherSuites = compatibleSuites

		// Signal early data if we're going to do it
		if len(state.state.Opts.EarlyData) > 0 {
			state.state.Params.ClientSendingEarlyData = true
			ed = &EarlyDataExtension{}
			err = ch.Extensions.Add(ed)
			if err != nil {
				logf(logTypeHandshake, "Error adding early data extension: %v", err)
				return nil, nil, AlertInternalError
			}
		}

		// Signal supported PSK key exchange modes
		if len(state.state.Caps.PSKModes) == 0 {
			logf(logTypeHandshake, "PSK selected, but no PSKModes")
			return nil, nil, AlertInternalError
		}
		kem := &PSKKeyExchangeModesExtension{KEModes: state.state.Caps.PSKModes}
		err = ch.Extensions.Add(kem)
		if err != nil {
			logf(logTypeHandshake, "Error adding PSKKeyExchangeModes extension: %v", err)
			return nil, nil, AlertInternalError
		}

		// Add the shim PSK extension to the ClientHello
		logf(logTypeHandshake, "Adding PSK extension with id = %x", key.Identity)
		psk = &PreSharedKeyExtension{
			HandshakeType: HandshakeTypeClientHello,
			Identities: []PSKIdentity{
				{Identity: key.Identity},
			},
			Binders: []PSKBinderEntry{
				// Note: Stub to get the length fields right
				{Binder: bytes.Repeat([]byte{0x00}, keyParams.hash.Size())},
			},
		}
		ch.Extensions.Add(psk)

		// Pre-Initialize the crypto context and compute the binder value
		state.state.Context.preInit(key)

		// Compute the binder value
		trunc, err := ch.Truncated()
		if err != nil {
			logf(logTypeHandshake, "[ClientStateStart] Error marshaling truncated ClientHello [%v]", err)
			return nil, nil, AlertInternalError
		}

		truncHash := state.state.Context.params.hash.New()
		truncHash.Write(trunc)

		binder := computeFinishedData(state.state.Context.params, state.state.Context.binderKey, truncHash.Sum(nil))

		// Replace the PSK extension
		psk.Binders[0].Binder = binder
		ch.Extensions.Add(psk)

		// If we got here, the earlier marshal succeeded (in ch.Truncated()), so
		// this one should too.
		state.state.clientHello, _ = HandshakeMessageFromBody(ch)
		state.state.Context.earlyUpdateWithClientHello(state.state.clientHello)
	} else if len(state.state.Opts.EarlyData) > 0 {
		logf(logTypeHandshake, "[ClientStateWaitSH] Early data without PSK")
		return nil, nil, AlertInternalError
	}

	state.state.clientHello, err = HandshakeMessageFromBody(ch)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateStart] Error marshaling ClientHello [%v]", err)
		return nil, nil, AlertInternalError
	}

	logf(logTypeHandshake, "[ClientStateStart] -> [ClientStateWaitSH]")
	nextState := ClientStateWaitSH{state: state.state}
	toSend := []HandshakeInstruction{
		SendHandshakeMessage{state.state.clientHello},
	}
	if state.state.Params.ClientSendingEarlyData {
		toSend = append(toSend, []HandshakeInstruction{
			RekeyOut{Label: "early", KeySet: state.state.Context.clientEarlyTrafficKeys},
			SendEarlyData{},
		}...)
	}
	return nextState, toSend, AlertNoAlert
}

type ClientStateWaitSH struct {
	state *connectionState
}

func (state ClientStateWaitSH) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm == nil {
		logf(logTypeHandshake, "[ClientStateWaitSH] Unexpected nil message")
		return nil, nil, AlertUnexpectedMessage
	}

	bodyGeneric, err := hm.ToBody()
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitSH] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	switch body := bodyGeneric.(type) {
	case *HelloRetryRequestBody:
		hrr := body

		if state.state.helloRetryRequest != nil {
			logf(logTypeHandshake, "[ClientStateWaitSH] Received a second HelloRetryRequest")
			return nil, nil, AlertUnexpectedMessage
		}
		state.state.helloRetryRequest = hm

		// XXX: Ignoring error

		// Check that the version sent by the server is the one we support
		if hrr.Version != supportedVersion {
			logf(logTypeHandshake, "[ClientStateWaitSH] Unsupported version [%v]", hrr.Version)
			return nil, nil, AlertProtocolVersion
		}

		// Check that the server provided a supported ciphersuite
		supportedCipherSuite := false
		for _, suite := range state.state.Caps.CipherSuites {
			supportedCipherSuite = supportedCipherSuite || (suite == hrr.CipherSuite)
		}
		if !supportedCipherSuite {
			logf(logTypeHandshake, "[ClientStateWaitSH] Unsupported ciphersuite [%04x]", hrr.CipherSuite)
			return nil, nil, AlertHandshakeFailure
		}

		// Narrow the supported ciphersuites to the server-provided one
		state.state.Caps.CipherSuites = []CipherSuite{hrr.CipherSuite}

		// The only thing we know how to respond to in an HRR is the Cookie
		// extension, so if there is either no Cookie extension or anything other
		// than a Cookie extension, we have to fail.
		serverCookie := new(CookieExtension)
		foundCookie := hrr.Extensions.Find(serverCookie)
		if !foundCookie || len(hrr.Extensions) != 1 {
			logf(logTypeHandshake, "[ClientStateWaitSH] No Cookie or extra extensions [%v] [%d]", foundCookie, len(hrr.Extensions))
			return nil, nil, AlertIllegalParameter
		}

		state.state.cookie = serverCookie.Cookie

		// Hash the body into a pseudo-message
		// XXX: Ignoring some errors here
		params := cipherSuiteMap[hrr.CipherSuite]
		h := params.hash.New()
		h.Write(state.state.clientHello.Marshal())
		state.state.firstClientHello = &HandshakeMessage{
			msgType: HandshakeTypeMessageHash,
			body:    h.Sum(nil),
		}

		logf(logTypeHandshake, "[ClientStateWaitSH] -> [ClientStateStart]")
		return ClientStateStart{state: state.state}.Next(nil)

	case *ServerHelloBody:
		sh := body
		state.state.serverHello = hm

		// Check that the version sent by the server is the one we support
		if sh.Version != supportedVersion {
			logf(logTypeHandshake, "[ClientStateWaitSH] Unsupported version [%v]", sh.Version)
			return nil, nil, AlertProtocolVersion
		}

		// Check that the server provided a supported ciphersuite
		supportedCipherSuite := false
		for _, suite := range state.state.Caps.CipherSuites {
			supportedCipherSuite = supportedCipherSuite || (suite == sh.CipherSuite)
		}
		if !supportedCipherSuite {
			logf(logTypeHandshake, "[ClientStateWaitSH] Unsupported ciphersuite [%04x]", sh.CipherSuite)
			return nil, nil, AlertHandshakeFailure
		}

		// Do PSK or key agreement depending on extensions
		serverPSK := PreSharedKeyExtension{HandshakeType: HandshakeTypeServerHello}
		serverKeyShare := KeyShareExtension{HandshakeType: HandshakeTypeServerHello}

		foundPSK := sh.Extensions.Find(&serverPSK)
		foundKeyShare := sh.Extensions.Find(&serverKeyShare)

		if foundPSK && (serverPSK.SelectedIdentity == 0) {
			state.state.PSK = state.state.OfferedPSK.Key
			state.state.Params.UsingPSK = true
		} else {
			// If the server rejected our PSK, then we have to re-start without it
			state.state.Context = cryptoContext{}
		}

		var dhSecret []byte
		if foundKeyShare {
			sks := serverKeyShare.Shares[0]
			priv, ok := state.state.OfferedDH[sks.Group]
			if !ok {
				logf(logTypeHandshake, "[ClientStateWaitSH] Key share for unknown group")
				return nil, nil, AlertIllegalParameter
			}

			state.state.Params.UsingDH = true
			dhSecret, _ = keyAgreement(sks.Group, sks.KeyExchange, priv)
		}

		state.state.Params.CipherSuite = sh.CipherSuite
		err = state.state.Context.init(sh.CipherSuite,
			state.state.firstClientHello,
			state.state.helloRetryRequest,
			state.state.clientHello)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateWaitSH] Error initializing crypto context [%v]", err)
			return nil, nil, AlertInternalError
		}

		state.state.Context.init(sh.CipherSuite, state.state.firstClientHello, state.state.helloRetryRequest, state.state.clientHello)
		state.state.Context.updateWithServerHello(state.state.serverHello, dhSecret)

		logf(logTypeHandshake, "[ClientStateWaitSH] -> [ClientStateWaitEE]")
		nextState := ClientStateWaitEE{state: state.state}
		toSend := []HandshakeInstruction{
			RekeyIn{Label: "handshake", KeySet: state.state.Context.serverHandshakeKeys},
		}
		return nextState, toSend, AlertNoAlert
	}

	logf(logTypeHandshake, "[ClientStateWaitSH] Unexpected message [%s]", hm.msgType)
	return nil, nil, AlertUnexpectedMessage
}

type ClientStateWaitEE struct {
	state *connectionState
}

func (state ClientStateWaitEE) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeEncryptedExtensions {
		logf(logTypeHandshake, "[ClientStateWaitEE] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	ee := EncryptedExtensionsBody{}
	_, err := ee.Unmarshal(hm.body)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitEE] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	serverALPN := ALPNExtension{}
	serverEarlyData := EarlyDataExtension{}

	gotALPN := ee.Extensions.Find(&serverALPN)
	state.state.Params.UsingEarlyData = ee.Extensions.Find(&serverEarlyData)

	if gotALPN && len(serverALPN.Protocols) > 0 {
		state.state.Params.NextProto = serverALPN.Protocols[0]
	}

	state.state.serverFirstFlight = []*HandshakeMessage{hm}

	if state.state.Params.UsingPSK {
		// XXX
		handshakeHash := state.state.Context.params.hash.New()
		handshakeHash.Write(state.state.firstClientHello.Marshal())
		handshakeHash.Write(state.state.helloRetryRequest.Marshal())
		handshakeHash.Write(state.state.clientHello.Marshal())
		handshakeHash.Write(state.state.serverHello.Marshal())
		for _, msg := range state.state.serverFirstFlight {
			handshakeHash.Write(msg.Marshal())
		}

		logf(logTypeHandshake, "[ClientStateWaitEE] -> [ClientStateWaitFinished]")
		nextState := ClientStateWaitFinished{
			Params:                       state.state.Params,
			cryptoParams:                 state.state.Context.params,
			handshakeHash:                handshakeHash,
			certificates:                 state.state.Caps.Certificates,
			masterSecret:                 state.state.Context.masterSecret,
			clientHandshakeTrafficSecret: state.state.Context.clientHandshakeTrafficSecret,
			serverHandshakeTrafficSecret: state.state.Context.serverHandshakeTrafficSecret,
		}
		return nextState, nil, AlertNoAlert
	}

	logf(logTypeHandshake, "[ClientStateWaitEE] -> [ClientStateWaitCertCR]")
	nextState := ClientStateWaitCertCR{state: state.state}
	return nextState, nil, AlertNoAlert
}

type ClientStateWaitCertCR struct {
	state *connectionState
}

func (state ClientStateWaitCertCR) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm == nil {
		logf(logTypeHandshake, "[ClientStateWaitCertCR] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	bodyGeneric, err := hm.ToBody()
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitCertCR] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	switch body := bodyGeneric.(type) {
	case *CertificateBody:
		state.state.serverCertificate = body
		state.state.serverFirstFlight = append(state.state.serverFirstFlight, hm)
		logf(logTypeHandshake, "[ClientStateWaitCertCR] -> [ClientStateWaitCV]")
		nextState := ClientStateWaitCV{state: state.state}
		return nextState, nil, AlertNoAlert

	case *CertificateRequestBody:
		// A certificate request in the handshake should have a zero-length context
		if len(body.CertificateRequestContext) > 0 {
			logf(logTypeHandshake, "[ClientStateWaitCertCR] Certificate request with non-empty context: %v", err)
			return nil, nil, AlertIllegalParameter
		}

		state.state.Params.UsingClientAuth = true
		state.state.serverCertificateRequest = body
		state.state.serverFirstFlight = append(state.state.serverFirstFlight, hm)
		logf(logTypeHandshake, "[ClientStateWaitCertCR] -> [ClientStateWaitCert]")
		nextState := ClientStateWaitCert{state: state.state}
		return nextState, nil, AlertNoAlert
	}

	return nil, nil, AlertUnexpectedMessage
}

type ClientStateWaitCert struct {
	state *connectionState
}

func (state ClientStateWaitCert) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeCertificate {
		logf(logTypeHandshake, "[ClientStateWaitCert] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	cert := &CertificateBody{}
	_, err := cert.Unmarshal(hm.body)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitCert] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	state.state.serverCertificate = cert
	state.state.serverFirstFlight = append(state.state.serverFirstFlight, hm)
	logf(logTypeHandshake, "[ClientStateWaitCert] -> [ClientStateWaitCV]")
	nextState := ClientStateWaitCV{state: state.state}
	return nextState, nil, AlertNoAlert
}

type ClientStateWaitCV struct {
	state *connectionState
}

func (state ClientStateWaitCV) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeCertificateVerify {
		logf(logTypeHandshake, "[ClientStateWaitCV] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	certVerify := CertificateVerifyBody{}
	_, err := certVerify.Unmarshal(hm.body)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitCV] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	cvTranscript := []*HandshakeMessage{
		state.state.firstClientHello,
		state.state.helloRetryRequest,
		state.state.clientHello,
		state.state.serverHello,
	}
	cvTranscript = append(cvTranscript, state.state.serverFirstFlight...)
	hashed := certVerify.ComputeContext(state.state.Context, cvTranscript)

	serverPublicKey := state.state.serverCertificate.CertificateList[0].CertData.PublicKey
	if err := certVerify.Verify(serverPublicKey, hashed); err != nil {
		logf(logTypeHandshake, "[ClientStateWaitCV] Server signature failed to verify")
		return nil, nil, AlertHandshakeFailure
	}

	if state.state.AuthCertificate != nil {
		err := state.state.AuthCertificate(state.state.serverCertificate.CertificateList)
		if err != nil {
			logf(logTypeHandshake, "[ClientStateWaitCV] Application rejected server certificate")
			return nil, nil, AlertBadCertificate
		}
	} else {
		logf(logTypeHandshake, "[ClientStateWaitCV] WARNING: No verification of server certificate")
	}

	state.state.serverFirstFlight = append(state.state.serverFirstFlight, hm)

	// XXX
	handshakeHash := state.state.Context.params.hash.New()
	handshakeHash.Write(state.state.firstClientHello.Marshal())
	logf(logTypeCrypto, "! input to handshake hash [%d]: %x", len(state.state.firstClientHello.Marshal()), state.state.firstClientHello.Marshal())
	handshakeHash.Write(state.state.helloRetryRequest.Marshal())
	logf(logTypeCrypto, "! input to handshake hash [%d]: %x", len(state.state.helloRetryRequest.Marshal()), state.state.helloRetryRequest.Marshal())
	handshakeHash.Write(state.state.clientHello.Marshal())
	logf(logTypeCrypto, "! input to handshake hash [%d]: %x", len(state.state.clientHello.Marshal()), state.state.clientHello.Marshal())
	handshakeHash.Write(state.state.serverHello.Marshal())
	logf(logTypeCrypto, "! input to handshake hash [%d]: %x", len(state.state.serverHello.Marshal()), state.state.serverHello.Marshal())
	for _, msg := range state.state.serverFirstFlight {
		logf(logTypeCrypto, "! input to handshake hash [%d]: %x", len(msg.Marshal()), msg.Marshal())
		handshakeHash.Write(msg.Marshal())
	}
	logf(logTypeCrypto, "handshake hash pre-3 [%d] %x", len(handshakeHash.Sum(nil)), handshakeHash.Sum(nil))

	logf(logTypeHandshake, "[ClientStateWaitCV] -> [ClientStateWaitFinished]")
	nextState := ClientStateWaitFinished{
		Params:                       state.state.Params,
		cryptoParams:                 state.state.Context.params,
		handshakeHash:                handshakeHash,
		certificates:                 state.state.Caps.Certificates,
		serverCertificateRequest:     state.state.serverCertificateRequest,
		masterSecret:                 state.state.Context.masterSecret,
		clientHandshakeTrafficSecret: state.state.Context.clientHandshakeTrafficSecret,
		serverHandshakeTrafficSecret: state.state.Context.serverHandshakeTrafficSecret,
	}
	return nextState, nil, AlertNoAlert
}

type ClientStateWaitFinished struct {
	Params        ConnectionParameters
	cryptoParams  cipherSuiteParams
	handshakeHash hash.Hash

	certificates             []*Certificate
	serverCertificateRequest *CertificateRequestBody

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
}

func (state ClientStateWaitFinished) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeFinished {
		logf(logTypeHandshake, "[ClientStateWaitFinished] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	// Verify server's Finished
	h3 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 3 [%d] %x", len(h3), h3)
	logf(logTypeCrypto, "handshake hash for server Finished: [%d] %x", len(h3), h3)

	serverFinishedData := computeFinishedData(state.cryptoParams, state.serverHandshakeTrafficSecret, h3)
	logf(logTypeCrypto, "server finished data: [%d] %x", len(serverFinishedData), serverFinishedData)

	fin := &FinishedBody{VerifyDataLen: len(serverFinishedData)}
	_, err := fin.Unmarshal(hm.body)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitFinished] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	if !bytes.Equal(fin.VerifyData, serverFinishedData) {
		logf(logTypeHandshake, "[ClientStateWaitFinished] Server's Finished failed to verify [%x] != [%x]",
			fin.VerifyData, serverFinishedData)
		return nil, nil, AlertHandshakeFailure
	}

	// Update the handshake hash with the Finished
	state.handshakeHash.Write(hm.Marshal())
	logf(logTypeCrypto, "input to handshake hash [%d]: %x", len(hm.Marshal()), hm.Marshal())
	h4 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 4 [%d]: %x", len(h4), h4)

	// Compute traffic secrets and keys
	clientTrafficSecret := deriveSecret(state.cryptoParams, state.masterSecret, labelClientApplicationTrafficSecret, h4)
	serverTrafficSecret := deriveSecret(state.cryptoParams, state.masterSecret, labelServerApplicationTrafficSecret, h4)
	logf(logTypeCrypto, "client traffic secret: [%d] %x", len(clientTrafficSecret), clientTrafficSecret)
	logf(logTypeCrypto, "server traffic secret: [%d] %x", len(serverTrafficSecret), serverTrafficSecret)

	clientTrafficKeys := makeTrafficKeys(state.cryptoParams, clientTrafficSecret)
	serverTrafficKeys := makeTrafficKeys(state.cryptoParams, serverTrafficSecret)

	// Assemble client's second flight
	toSend := []HandshakeInstruction{}

	if state.Params.UsingEarlyData {
		// Note: We only send EOED if the server is actually going to use the early
		// data.  Otherwise, it will never see it, and the transcripts will
		// mismatch.
		// EOED marshal is infallible
		eoedm, _ := HandshakeMessageFromBody(&EndOfEarlyDataBody{})
		toSend = append(toSend, SendHandshakeMessage{eoedm})
		state.handshakeHash.Write(eoedm.Marshal())
		logf(logTypeCrypto, "input to handshake hash [%d]: %x", len(eoedm.Marshal()), eoedm.Marshal())
	}

	clientHandshakeKeys := makeTrafficKeys(state.cryptoParams, state.clientHandshakeTrafficSecret)
	toSend = append(toSend, RekeyOut{Label: "handshake", KeySet: clientHandshakeKeys})

	if state.Params.UsingClientAuth {
		// Extract constraints from certicateRequest
		schemes := SignatureAlgorithmsExtension{}
		gotSchemes := state.serverCertificateRequest.Extensions.Find(&schemes)
		if !gotSchemes {
			logf(logTypeHandshake, "[ClientStateWaitFinished] WARNING no appropriate certificate found [%v]", err)
			return nil, nil, AlertIllegalParameter
		}

		// Select a certificate
		cert, certScheme, err := CertificateSelection(nil, schemes.Algorithms, state.certificates)
		if err != nil {
			// XXX: Signal this to the application layer?
			logf(logTypeHandshake, "[ClientStateWaitFinished] WARNING no appropriate certificate found [%v]", err)

			certificate := &CertificateBody{}
			certm, err := HandshakeMessageFromBody(certificate)
			if err != nil {
				logf(logTypeHandshake, "[ClientStateWaitFinished] Error marshaling Certificate [%v]", err)
				return nil, nil, AlertInternalError
			}

			toSend = append(toSend, SendHandshakeMessage{certm})
			state.handshakeHash.Write(certm.Marshal())
		} else {
			// Create and send Certificate, CertificateVerify
			certificate := &CertificateBody{
				CertificateList: make([]CertificateEntry, len(cert.Chain)),
			}
			for i, entry := range cert.Chain {
				certificate.CertificateList[i] = CertificateEntry{CertData: entry}
			}
			certm, err := HandshakeMessageFromBody(certificate)
			if err != nil {
				logf(logTypeHandshake, "[ClientStateWaitFinished] Error marshaling Certificate [%v]", err)
				return nil, nil, AlertInternalError
			}

			toSend = append(toSend, SendHandshakeMessage{certm})
			state.handshakeHash.Write(certm.Marshal())

			hcv := state.handshakeHash.Sum(nil)
			logf(logTypeHandshake, "Handshake Hash to be verified: [%d] %x", len(hcv), hcv)

			certificateVerify := &CertificateVerifyBody{Algorithm: certScheme}
			logf(logTypeHandshake, "Creating CertVerify: %04x %v", certScheme, state.cryptoParams.hash)

			err = certificateVerify.Sign(cert.PrivateKey, hcv)
			if err != nil {
				logf(logTypeHandshake, "[ClientStateWaitFinished] Error signing CertificateVerify [%v]", err)
				return nil, nil, AlertInternalError
			}
			certvm, err := HandshakeMessageFromBody(certificateVerify)
			if err != nil {
				logf(logTypeHandshake, "[ClientStateWaitFinished] Error marshaling CertificateVerify [%v]", err)
				return nil, nil, AlertInternalError
			}

			toSend = append(toSend, SendHandshakeMessage{certvm})
			state.handshakeHash.Write(certvm.Marshal())
		}
	}

	// Compute the client's Finished message
	h5 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash for client Finished: [%d] %x", len(h5), h5)

	clientFinishedData := computeFinishedData(state.cryptoParams, state.clientHandshakeTrafficSecret, h5)
	logf(logTypeCrypto, "client Finished data: [%d] %x", len(clientFinishedData), clientFinishedData)

	fin = &FinishedBody{
		VerifyDataLen: len(clientFinishedData),
		VerifyData:    clientFinishedData,
	}
	finm, err := HandshakeMessageFromBody(fin)
	if err != nil {
		logf(logTypeHandshake, "[ClientStateWaitFinished] Error marshaling client Finished [%v]", err)
		return nil, nil, AlertInternalError
	}

	// Compute the resumption secret
	state.handshakeHash.Write(finm.Marshal())
	h6 := state.handshakeHash.Sum(nil)

	resumptionSecret := deriveSecret(state.cryptoParams, state.masterSecret, labelResumptionSecret, h6)
	logf(logTypeCrypto, "resumption secret: [%d] %x", len(resumptionSecret), resumptionSecret)

	toSend = append(toSend, []HandshakeInstruction{
		SendHandshakeMessage{finm},
		RekeyIn{Label: "application", KeySet: serverTrafficKeys},
		RekeyOut{Label: "application", KeySet: clientTrafficKeys},
	}...)

	logf(logTypeHandshake, "[ClientStateWaitFinished] -> [StateConnected]")
	nextState := StateConnected{
		Params:              state.Params,
		isClient:            true,
		cryptoParams:        state.cryptoParams,
		resumptionSecret:    resumptionSecret,
		clientTrafficSecret: clientTrafficSecret,
		serverTrafficSecret: serverTrafficSecret,
	}
	return nextState, toSend, AlertNoAlert
}

// Server State Machine
//
//                              START <-----+
//               Recv ClientHello |         | Send HelloRetryRequest
//                                v         |
//                             RECVD_CH ----+
//                                | Select parameters
//                                | Send ServerHello
//                                v
//                             NEGOTIATED
//                                | Send EncryptedExtensions
//                                | [Send CertificateRequest]
// Can send                       | [Send Certificate + CertificateVerify]
// app data -->                   | Send Finished
// after                 +--------+--------+
// here         No 0-RTT |                 | 0-RTT
//                       |                 v
//                       |             WAIT_EOED <---+
//                       |            Recv |   |     | Recv
//                       |  EndOfEarlyData |   |     | early data
//                       |                 |   +-----+
//                       +> WAIT_FLIGHT2 <-+
//                                |
//                       +--------+--------+
//               No auth |                 | Client auth
//                       |                 |
//                       |                 v
//                       |             WAIT_CERT
//                       |        Recv |       | Recv Certificate
//                       |       empty |       v
//                       | Certificate |    WAIT_CV
//                       |             |       | Recv
//                       |             v       | CertificateVerify
//                       +-> WAIT_FINISHED <---+
//                                | Recv Finished
//                                v
//                            CONNECTED
//
// NB: Not using state RECVD_CH
//
//  State							Instructions
//  START							{}
//  NEGOTIATED				Send(SH); [RekeyIn;] RekeyOut; Send(EE); [Send(CertReq);] [Send(Cert); Send(CV)]
//  WAIT_EOED					RekeyIn;
//  WAIT_FLIGHT2			{}
//  WAIT_CERT_CR			{}
//  WAIT_CERT					{}
//  WAIT_CV						{}
//  WAIT_FINISHED			RekeyIn; RekeyOut;
//  CONNECTED					StoreTicket || (RekeyIn; [RekeyOut])

type ServerStateStart struct {
	SendHRR bool
	state   *connectionState
}

func (state ServerStateStart) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeClientHello {
		logf(logTypeHandshake, "[ServerStateStart] unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	ch := &ClientHelloBody{}
	_, err := ch.Unmarshal(hm.body)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateStart] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	state.state.clientHello = hm

	supportedVersions := new(SupportedVersionsExtension)
	serverName := new(ServerNameExtension)
	supportedGroups := new(SupportedGroupsExtension)
	signatureAlgorithms := new(SignatureAlgorithmsExtension)
	clientKeyShares := &KeyShareExtension{HandshakeType: HandshakeTypeClientHello}
	clientPSK := &PreSharedKeyExtension{HandshakeType: HandshakeTypeClientHello}
	clientEarlyData := &EarlyDataExtension{}
	clientALPN := new(ALPNExtension)
	clientPSKModes := new(PSKKeyExchangeModesExtension)
	clientCookie := new(CookieExtension)

	gotSupportedVersions := ch.Extensions.Find(supportedVersions)
	gotServerName := ch.Extensions.Find(serverName)
	gotSupportedGroups := ch.Extensions.Find(supportedGroups)
	gotSignatureAlgorithms := ch.Extensions.Find(signatureAlgorithms)
	gotEarlyData := ch.Extensions.Find(clientEarlyData)
	ch.Extensions.Find(clientKeyShares)
	ch.Extensions.Find(clientPSK)
	ch.Extensions.Find(clientALPN)
	ch.Extensions.Find(clientPSKModes)
	ch.Extensions.Find(clientCookie)

	if gotServerName {
		state.state.Params.ServerName = string(*serverName)
	}

	// If the client didn't send supportedVersions or doesn't support 1.3,
	// then we're done here.
	if !gotSupportedVersions {
		logf(logTypeHandshake, "[ServerStateStart] Client did not send supported_versions")
		return nil, nil, AlertProtocolVersion
	}
	versionOK, _ := VersionNegotiation(supportedVersions.Versions, []uint16{supportedVersion})
	if !versionOK {
		logf(logTypeHandshake, "[ServerStateStart] Client does not support the same version")
		return nil, nil, AlertProtocolVersion
	}

	if state.state.Caps.RequireCookie && state.state.cookie != nil && !bytes.Equal(state.state.cookie, clientCookie.Cookie) {
		logf(logTypeHandshake, "[ServerStateStart] Cookie mismatch [%x] != [%x]", clientCookie.Cookie, state.state.cookie)
		return nil, nil, AlertAccessDenied
	}

	// Figure out if we can do DH
	canDoDH := false
	canDoDH, state.state.dhGroup, state.state.dhPublic, state.state.dhSecret = DHNegotiation(clientKeyShares.Shares, state.state.Caps.Groups)

	// Figure out if we can do PSK
	canDoPSK := false
	var psk *PreSharedKey
	var ctx cryptoContext
	if len(clientPSK.Identities) > 0 {
		contextBase := []byte{}
		if state.state.helloRetryRequest != nil {
			chBytes := state.state.clientHello.Marshal()
			hrrBytes := state.state.helloRetryRequest.Marshal()
			contextBase = append(chBytes, hrrBytes...)
		}

		chTrunc, err := ch.Truncated()
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error computing truncated ClientHello [%v]", err)
			return nil, nil, AlertDecodeError
		}

		context := append(contextBase, chTrunc...)

		canDoPSK, state.state.selectedPSK, psk, ctx, err = PSKNegotiation(clientPSK.Identities, clientPSK.Binders, context, state.state.Caps.PSKs)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error in PSK negotiation [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	state.state.Context = ctx

	// Figure out if we actually should do DH / PSK
	state.state.Params.UsingDH, state.state.Params.UsingPSK = PSKModeNegotiation(canDoDH, canDoPSK, clientPSKModes.KEModes)

	// Select a ciphersuite
	state.state.Params.CipherSuite, err = CipherSuiteNegotiation(psk, ch.CipherSuites, state.state.Caps.CipherSuites)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateStart] No common ciphersuite found [%v]", err)
		return nil, nil, AlertHandshakeFailure
	}

	// Send a cookie if required
	// NB: Need to do this here because it's after ciphersuite selection, which
	// has to be after PSK selection.
	// XXX: Doing this statefully for now, could be stateless
	if state.state.Caps.RequireCookie && state.state.cookie == nil {
		cookie, err := NewCookie()
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error generating cookie [%v]", err)
			return nil, nil, AlertInternalError
		}
		state.state.cookie = cookie.Cookie

		// Ignoring errors because everything here is newly constructed, so there
		// shouldn't be marshal errors
		hrr := &HelloRetryRequestBody{
			Version:     supportedVersion,
			CipherSuite: state.state.Params.CipherSuite,
		}
		hrr.Extensions.Add(cookie)

		state.state.helloRetryRequest, err = HandshakeMessageFromBody(hrr)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error marshaling HRR [%v]", err)
			return nil, nil, AlertInternalError
		}

		params := cipherSuiteMap[state.state.Params.CipherSuite]
		h := params.hash.New()
		h.Write(state.state.clientHello.Marshal())
		state.state.firstClientHello = &HandshakeMessage{
			msgType: HandshakeTypeMessageHash,
			body:    h.Sum(nil),
		}

		nextState := ServerStateStart{state: state.state}
		toSend := []HandshakeInstruction{SendHandshakeMessage{state.state.helloRetryRequest}}
		logf(logTypeHandshake, "[ServerStateStart] -> [ServerStateStart]")
		return nextState, toSend, AlertNoAlert
	}

	// If we've got no entropy to make keys from, fail
	if !state.state.Params.UsingDH && !state.state.Params.UsingPSK {
		logf(logTypeHandshake, "[ServerStateStart] Neither DH nor PSK negotiated")
		return nil, nil, AlertHandshakeFailure
	}

	if !state.state.Params.UsingPSK {
		psk = nil
		state.state.Context = cryptoContext{}

		// If we're not using a PSK mode, then we need to have certain extensions
		if !gotServerName || !gotSupportedGroups || !gotSignatureAlgorithms {
			logf(logTypeHandshake, "[ServerStateStart] Insufficient extensions (%v %v %v)",
				gotServerName, gotSupportedGroups, gotSignatureAlgorithms)
			return nil, nil, AlertMissingExtension
		}

		// Select a certificate
		name := string(*serverName)
		var err error
		state.state.cert, state.state.certScheme, err = CertificateSelection(&name, signatureAlgorithms.Algorithms, state.state.Caps.Certificates)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] No appropriate certificate found [%v]", err)
			return nil, nil, AlertAccessDenied
		}
	}

	if !state.state.Params.UsingDH {
		state.state.dhSecret = nil
	}

	// Figure out if we're going to do early data
	state.state.Params.ClientSendingEarlyData = gotEarlyData
	state.state.Params.UsingEarlyData = EarlyDataNegotiation(state.state.Params.UsingPSK, gotEarlyData, state.state.Caps.AllowEarlyData)
	if state.state.Params.UsingEarlyData {
		state.state.Context.earlyUpdateWithClientHello(state.state.clientHello)
	}

	// Select a next protocol
	state.state.Params.NextProto, err = ALPNNegotiation(psk, clientALPN.Protocols, state.state.Caps.NextProtos)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateStart] No common application-layer protocol found [%v]", err)
		return nil, nil, AlertNoApplicationProtocol
	}

	logf(logTypeHandshake, "[ServerStateStart] -> [ServerStateNegotiated]")
	return ServerStateNegotiated{state: state.state}.Next(nil)
}

type ServerStateNegotiated struct {
	state *connectionState
}

func (state ServerStateNegotiated) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	// Create the ServerHello
	sh := &ServerHelloBody{
		Version:     supportedVersion,
		CipherSuite: state.state.Params.CipherSuite,
	}
	_, err := prng.Read(sh.Random[:])
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error creating server random [%v]", err)
		return nil, nil, AlertInternalError
	}
	if state.state.Params.UsingDH {
		logf(logTypeHandshake, "[ServerStateNegotiated] sending DH extension")
		err = sh.Extensions.Add(&KeyShareExtension{
			HandshakeType: HandshakeTypeServerHello,
			Shares:        []KeyShareEntry{{Group: state.state.dhGroup, KeyExchange: state.state.dhPublic}},
		})
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error adding key_shares extension [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	if state.state.Params.UsingPSK {
		logf(logTypeHandshake, "[ServerStateNegotiated] sending PSK extension")
		err = sh.Extensions.Add(&PreSharedKeyExtension{
			HandshakeType:    HandshakeTypeServerHello,
			SelectedIdentity: uint16(state.state.selectedPSK),
		})
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error adding PSK extension [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	state.state.serverHello, err = HandshakeMessageFromBody(sh)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling ServerHello [%v]", err)
		return nil, nil, AlertInternalError
	}

	// Crank up the crypto context
	err = state.state.Context.init(sh.CipherSuite, state.state.firstClientHello, state.state.helloRetryRequest, state.state.clientHello)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error initializing crypto context [%v]", err)
		return nil, nil, AlertInternalError
	}

	err = state.state.Context.updateWithServerHello(state.state.serverHello, state.state.dhSecret)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error updating crypto context with ServerHello [%v]", err)
		return nil, nil, AlertInternalError
	}

	// Send an EncryptedExtensions message (even if it's empty)
	eeList := ExtensionList{}
	if state.state.Params.NextProto != "" {
		logf(logTypeHandshake, "[server] sending ALPN extension")
		err = eeList.Add(&ALPNExtension{Protocols: []string{state.state.Params.NextProto}})
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error adding ALPN to EncryptedExtensions [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	if state.state.Params.UsingEarlyData {
		logf(logTypeHandshake, "[server] sending EDI extension")
		err = eeList.Add(&EarlyDataExtension{})
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error adding EDI to EncryptedExtensions [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	ee := &EncryptedExtensionsBody{eeList}
	eem, err := HandshakeMessageFromBody(ee)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling EncryptedExtensions [%v]", err)
		return nil, nil, AlertInternalError
	}

	transcript := []*HandshakeMessage{eem}
	toSend := []HandshakeInstruction{
		SendHandshakeMessage{state.state.serverHello},
		RekeyOut{Label: "handshake", KeySet: state.state.Context.serverHandshakeKeys},
		SendHandshakeMessage{eem},
	}

	// Authenticate with a certificate if required
	if !state.state.Params.UsingPSK {
		// Send a CertificateRequest message if we want client auth
		if state.state.Caps.RequireClientAuth {
			state.state.Params.UsingClientAuth = true

			// XXX: We don't support sending any constraints besides a list of
			// supported signature algorithms
			cr := &CertificateRequestBody{}
			schemes := &SignatureAlgorithmsExtension{Algorithms: state.state.Caps.SignatureSchemes}
			err := cr.Extensions.Add(schemes)
			if err != nil {
				logf(logTypeHandshake, "[ServerStateNegotiated] Error adding supported schemes to CertificateRequest [%v]", err)
				return nil, nil, AlertInternalError
			}

			crm, err := HandshakeMessageFromBody(cr)
			if err != nil {
				logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling CertificateRequest [%v]", err)
				return nil, nil, AlertInternalError
			}
			state.state.serverCertificateRequest = cr

			transcript = append(transcript, crm)
			toSend = append(toSend, SendHandshakeMessage{crm})
		}

		// Create and send Certificate, CertificateVerify
		certificate := &CertificateBody{
			CertificateList: make([]CertificateEntry, len(state.state.cert.Chain)),
		}
		for i, entry := range state.state.cert.Chain {
			certificate.CertificateList[i] = CertificateEntry{CertData: entry}
		}
		certm, err := HandshakeMessageFromBody(certificate)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling Certificate [%v]", err)
			return nil, nil, AlertInternalError
		}

		transcript = append(transcript, certm)
		toSend = append(toSend, SendHandshakeMessage{certm})

		certificateVerify := &CertificateVerifyBody{Algorithm: state.state.certScheme}
		logf(logTypeHandshake, "Creating CertVerify: %04x %v", state.state.certScheme, state.state.Context.params.hash)

		h := state.state.Context.params.hash.New()
		h.Write(state.state.firstClientHello.Marshal())
		h.Write(state.state.helloRetryRequest.Marshal())
		h.Write(state.state.clientHello.Marshal())
		h.Write(state.state.serverHello.Marshal())
		for _, msg := range transcript {
			h.Write(msg.Marshal())
		}

		err = certificateVerify.Sign(state.state.cert.PrivateKey, h.Sum(nil))
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error signing CertificateVerify [%v]", err)
			return nil, nil, AlertInternalError
		}
		certvm, err := HandshakeMessageFromBody(certificateVerify)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling CertificateVerify [%v]", err)
			return nil, nil, AlertInternalError
		}

		transcript = append(transcript, certvm)
		toSend = append(toSend, SendHandshakeMessage{certvm})
	}

	// Crank the crypto context
	err = state.state.Context.updateWithServerFirstFlight(transcript)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error updating crypto context with server's first flight [%v]", err)
		return nil, nil, AlertInternalError
	}

	fin := state.state.Context.serverFinished
	finm, _ := HandshakeMessageFromBody(fin)
	state.state.serverFirstFlight = append(state.state.serverFirstFlight, finm)

	transcript = append(transcript, finm)
	toSend = append(toSend, []HandshakeInstruction{
		SendHandshakeMessage{finm},
		RekeyOut{Label: "application", KeySet: state.state.Context.serverTrafficKeys},
	}...)

	state.state.serverFirstFlight = transcript

	// XXX
	handshakeHash := state.state.Context.params.hash.New()
	handshakeHash.Write(state.state.firstClientHello.Marshal())
	handshakeHash.Write(state.state.helloRetryRequest.Marshal())
	handshakeHash.Write(state.state.clientHello.Marshal())
	handshakeHash.Write(state.state.serverHello.Marshal())
	for _, msg := range transcript {
		handshakeHash.Write(msg.Marshal())
	}

	if state.state.Params.UsingEarlyData {
		logf(logTypeHandshake, "[ServerStateNegotiated] -> [ServerStateWaitEOED]")
		nextState := ServerStateWaitEOED{
			AuthCertificate:              state.state.AuthCertificate,
			Params:                       state.state.Params,
			cryptoParams:                 state.state.Context.params,
			handshakeHash:                handshakeHash,
			masterSecret:                 state.state.Context.masterSecret,
			clientHandshakeTrafficSecret: state.state.Context.clientHandshakeTrafficSecret,
			clientTrafficSecret:          state.state.Context.clientTrafficSecret,
			serverTrafficSecret:          state.state.Context.serverTrafficSecret,
		}
		toSend = append(toSend, []HandshakeInstruction{
			RekeyIn{Label: "early", KeySet: state.state.Context.clientEarlyTrafficKeys},
			ReadEarlyData{},
		}...)
		return nextState, toSend, AlertNoAlert
	}

	logf(logTypeHandshake, "[ServerStateNegotiated] -> [ServerStateWaitFlight2]")
	toSend = append(toSend, []HandshakeInstruction{
		RekeyIn{Label: "handshake", KeySet: state.state.Context.clientHandshakeKeys},
		ReadPastEarlyData{},
	}...)
	waitFlight2 := ServerStateWaitFlight2{
		AuthCertificate:              state.state.AuthCertificate,
		Params:                       state.state.Params,
		cryptoParams:                 state.state.Context.params,
		handshakeHash:                handshakeHash,
		masterSecret:                 state.state.Context.masterSecret,
		clientHandshakeTrafficSecret: state.state.Context.clientHandshakeTrafficSecret,
		clientTrafficSecret:          state.state.Context.clientTrafficSecret,
		serverTrafficSecret:          state.state.Context.serverTrafficSecret,
	}
	nextState, moreToSend, alert := waitFlight2.Next(nil)
	toSend = append(toSend, moreToSend...)
	return nextState, toSend, alert
}

type ServerStateWaitEOED struct {
	AuthCertificate              func(chain []CertificateEntry) error
	Params                       ConnectionParameters
	cryptoParams                 cipherSuiteParams
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	handshakeHash                hash.Hash
	clientTrafficSecret          []byte
	serverTrafficSecret          []byte
}

func (state ServerStateWaitEOED) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeEndOfEarlyData {
		logf(logTypeHandshake, "[ServerStateWaitEOED] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	if len(hm.body) > 0 {
		logf(logTypeHandshake, "[ServerStateWaitEOED] Error decoding message [len > 0]")
		return nil, nil, AlertDecodeError
	}

	state.handshakeHash.Write(hm.Marshal())

	clientHandshakeKeys := makeTrafficKeys(state.cryptoParams, state.clientHandshakeTrafficSecret)

	logf(logTypeHandshake, "[ServerStateWaitEOED] -> [ServerStateWaitFlight2]")
	toSend := []HandshakeInstruction{
		RekeyIn{Label: "handshake", KeySet: clientHandshakeKeys},
	}
	waitFlight2 := ServerStateWaitFlight2{
		AuthCertificate:              state.AuthCertificate,
		Params:                       state.Params,
		cryptoParams:                 state.cryptoParams,
		handshakeHash:                state.handshakeHash,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		clientTrafficSecret:          state.clientTrafficSecret,
		serverTrafficSecret:          state.serverTrafficSecret,
	}
	nextState, moreToSend, alert := waitFlight2.Next(nil)
	toSend = append(toSend, moreToSend...)
	return nextState, toSend, alert
}

type ServerStateWaitFlight2 struct {
	AuthCertificate              func(chain []CertificateEntry) error
	Params                       ConnectionParameters
	cryptoParams                 cipherSuiteParams
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	handshakeHash                hash.Hash
	clientTrafficSecret          []byte
	serverTrafficSecret          []byte
}

func (state ServerStateWaitFlight2) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm != nil {
		logf(logTypeHandshake, "[ServerStateWaitFlight2] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	if state.Params.UsingClientAuth {
		logf(logTypeHandshake, "[ServerStateWaitFlight2] -> [ServerStateWaitCert]")
		nextState := ServerStateWaitCert{
			AuthCertificate:              state.AuthCertificate,
			Params:                       state.Params,
			cryptoParams:                 state.cryptoParams,
			handshakeHash:                state.handshakeHash,
			masterSecret:                 state.masterSecret,
			clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
			clientTrafficSecret:          state.clientTrafficSecret,
			serverTrafficSecret:          state.serverTrafficSecret,
		}
		return nextState, nil, AlertNoAlert
	}

	logf(logTypeHandshake, "[ServerStateWaitFlight2] -> [ServerStateWaitFinished]")
	nextState := ServerStateWaitFinished{
		Params:                       state.Params,
		cryptoParams:                 state.cryptoParams,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		handshakeHash:                state.handshakeHash,
		clientTrafficSecret:          state.clientTrafficSecret,
		serverTrafficSecret:          state.serverTrafficSecret,
	}
	return nextState, nil, AlertNoAlert
}

type ServerStateWaitCert struct {
	AuthCertificate              func(chain []CertificateEntry) error
	Params                       ConnectionParameters
	cryptoParams                 cipherSuiteParams
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	handshakeHash                hash.Hash
	clientTrafficSecret          []byte
	serverTrafficSecret          []byte
}

func (state ServerStateWaitCert) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeCertificate {
		logf(logTypeHandshake, "[ServerStateWaitCert] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	cert := &CertificateBody{}
	_, err := cert.Unmarshal(hm.body)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateWaitCert] Unexpected message")
		return nil, nil, AlertDecodeError
	}

	state.handshakeHash.Write(hm.Marshal())

	if len(cert.CertificateList) == 0 {
		logf(logTypeHandshake, "[ServerStateWaitCert] WARNING client did not provide a certificate")

		logf(logTypeHandshake, "[ServerStateWaitCert] -> [ServerStateWaitFinished]")
		nextState := ServerStateWaitFinished{
			Params:                       state.Params,
			cryptoParams:                 state.cryptoParams,
			masterSecret:                 state.masterSecret,
			clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
			handshakeHash:                state.handshakeHash,
			clientTrafficSecret:          state.clientTrafficSecret,
			serverTrafficSecret:          state.serverTrafficSecret,
		}
		return nextState, nil, AlertNoAlert
	}

	logf(logTypeHandshake, "[ServerStateWaitCert] -> [ServerStateWaitCV]")
	nextState := ServerStateWaitCV{
		AuthCertificate:              state.AuthCertificate,
		Params:                       state.Params,
		cryptoParams:                 state.cryptoParams,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		handshakeHash:                state.handshakeHash,
		clientTrafficSecret:          state.clientTrafficSecret,
		serverTrafficSecret:          state.serverTrafficSecret,
		clientCertificate:            cert,
	}
	return nextState, nil, AlertNoAlert
}

type ServerStateWaitCV struct {
	AuthCertificate func(chain []CertificateEntry) error
	Params          ConnectionParameters
	cryptoParams    cipherSuiteParams

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte

	handshakeHash       hash.Hash
	clientTrafficSecret []byte
	serverTrafficSecret []byte

	clientCertificate *CertificateBody
}

func (state ServerStateWaitCV) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeCertificateVerify {
		logf(logTypeHandshake, "[ServerStateWaitCV] Unexpected message [%+v] [%s]", hm, reflect.TypeOf(hm))
		return nil, nil, AlertUnexpectedMessage
	}

	certVerify := &CertificateVerifyBody{}
	_, err := certVerify.Unmarshal(hm.body)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateWaitCert] Error decoding message %v", err)
		return nil, nil, AlertDecodeError
	}

	// Verify client signature over handshake hash
	hcv := state.handshakeHash.Sum(nil)
	logf(logTypeHandshake, "Handshake Hash to be verified: [%d] %x", len(hcv), hcv)

	clientPublicKey := state.clientCertificate.CertificateList[0].CertData.PublicKey
	if err := certVerify.Verify(clientPublicKey, hcv); err != nil {
		logf(logTypeHandshake, "[ServerStateWaitCV] Failure in client auth verification [%v]", err)
		return nil, nil, AlertHandshakeFailure
	}

	if state.AuthCertificate != nil {
		err := state.AuthCertificate(state.clientCertificate.CertificateList)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateWaitCV] Application rejected client certificate")
			return nil, nil, AlertBadCertificate
		}
	} else {
		logf(logTypeHandshake, "[ServerStateWaitCV] WARNING: No verification of client certificate")
	}

	// If it passes, record the certificateVerify in the transcript hash
	state.handshakeHash.Write(hm.Marshal())

	logf(logTypeHandshake, "[ServerStateWaitCV] -> [ServerStateWaitFinished]")
	nextState := ServerStateWaitFinished{
		Params:                       state.Params,
		cryptoParams:                 state.cryptoParams,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		handshakeHash:                state.handshakeHash,
		clientTrafficSecret:          state.clientTrafficSecret,
		serverTrafficSecret:          state.serverTrafficSecret,
	}
	return nextState, nil, AlertNoAlert
}

type ServerStateWaitFinished struct {
	Params       ConnectionParameters
	cryptoParams cipherSuiteParams

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte

	handshakeHash       hash.Hash
	clientTrafficSecret []byte
	serverTrafficSecret []byte
}

func (state ServerStateWaitFinished) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
	if hm == nil || hm.msgType != HandshakeTypeFinished {
		logf(logTypeHandshake, "[ServerStateWaitFinished] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	fin := &FinishedBody{VerifyDataLen: state.cryptoParams.hash.Size()}
	_, err := fin.Unmarshal(hm.body)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateWaitFinished] Error decoding message %v", err)
		return nil, nil, AlertDecodeError
	}

	// Verify client Finished data
	h5 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash for client Finished: [%d] %x", len(h5), h5)

	clientFinishedData := computeFinishedData(state.cryptoParams, state.clientHandshakeTrafficSecret, h5)
	logf(logTypeCrypto, "client Finished data: [%d] %x", len(clientFinishedData), clientFinishedData)

	if !bytes.Equal(fin.VerifyData, clientFinishedData) {
		logf(logTypeHandshake, "[ServerStateWaitFinished] Client's Finished failed to verify")
		return nil, nil, AlertHandshakeFailure
	}

	// Compute the resumption secret
	state.handshakeHash.Write(hm.Marshal())
	h6 := state.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 6 [%d]: %x", len(h6), h6)

	resumptionSecret := deriveSecret(state.cryptoParams, state.masterSecret, labelResumptionSecret, h6)
	logf(logTypeCrypto, "resumption secret: [%d] %x", len(resumptionSecret), resumptionSecret)

	// Compute client traffic keys
	clientTrafficKeys := makeTrafficKeys(state.cryptoParams, state.clientTrafficSecret)

	logf(logTypeHandshake, "[ServerStateWaitFinished] -> [StateConnected]")
	nextState := StateConnected{
		Params:              state.Params,
		isClient:            false,
		cryptoParams:        state.cryptoParams,
		resumptionSecret:    resumptionSecret,
		clientTrafficSecret: state.clientTrafficSecret,
		serverTrafficSecret: state.serverTrafficSecret,
	}
	toSend := []HandshakeInstruction{
		RekeyIn{Label: "application", KeySet: clientTrafficKeys},
	}
	return nextState, toSend, AlertNoAlert
}

// Connected state is symmetric between client and server (NB: Might need a
// notation as to which role is being played)
type StateConnected struct {
	Params              ConnectionParameters
	isClient            bool
	cryptoParams        cipherSuiteParams
	resumptionSecret    []byte
	clientTrafficSecret []byte
	serverTrafficSecret []byte
}

func (state *StateConnected) KeyUpdate(request KeyUpdateRequest) ([]HandshakeInstruction, Alert) {
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

	toSend := []HandshakeInstruction{
		SendHandshakeMessage{kum},
		RekeyOut{Label: "update", KeySet: trafficKeys},
	}
	return toSend, AlertNoAlert
}

func (state *StateConnected) NewSessionTicket(length int, lifetime, earlyDataLifetime uint32) ([]HandshakeInstruction, Alert) {
	tkt, err := NewSessionTicket(length)
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error generating NewSessionTicket: %v", err)
		return nil, AlertInternalError
	}

	tkt.TicketLifetime = lifetime

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
	}

	tktm, err := HandshakeMessageFromBody(tkt)
	if err != nil {
		logf(logTypeHandshake, "[StateConnected] Error marshaling NewSessionTicket: %v", err)
		return nil, AlertInternalError
	}

	toSend := []HandshakeInstruction{
		StorePSK{newPSK},
		SendHandshakeMessage{tktm},
	}
	return toSend, AlertNoAlert
}

func (state StateConnected) Next(hm *HandshakeMessage) (HandshakeState, []HandshakeInstruction, Alert) {
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

		toSend := []HandshakeInstruction{RekeyIn{Label: "update", KeySet: trafficKeys}}

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
		}

		toSend := []HandshakeInstruction{StorePSK{psk}}
		return state, toSend, AlertNoAlert
	}

	logf(logTypeHandshake, "[StateConnected] Unexpected message type %v", hm.msgType)
	return nil, nil, AlertUnexpectedMessage
}
