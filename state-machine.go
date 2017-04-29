package mint

import (
	"bytes"
)

type State interface {
	Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert)
}

// XXX: This is just a big bucket of all the previously-defined state values
// for now.  We should trim this down once the state machine version is
// functional.
type connectionState struct {
	Conn    *Conn
	Caps    Capabilities
	Opts    ConnectionOptions
	Params  ConnectionParameters
	Context cryptoContext

	// Client semi-transient state
	OfferedDH         map[NamedGroup][]byte
	OfferedPSK        PreSharedKey
	PSK               []byte
	clientHello       *HandshakeMessage
	helloRetryRequest *HandshakeMessage
	retryClientHello  *HandshakeMessage
	serverHello       *HandshakeMessage
	serverFirstFlight []*HandshakeMessage
	serverFinished    *HandshakeMessage

	// Server semi-transient state
	cookie      []byte
	cert        *Certificate
	certScheme  SignatureScheme
	transcript  []*HandshakeMessage
	dhGroup     NamedGroup
	dhPublic    []byte
	dhSecret    []byte
	selectedPSK int
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

type ClientStateStart struct {
	state *connectionState
}

func (state ClientStateStart) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm != nil {
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
	kem := PSKKeyExchangeModesExtension{KEModes: state.state.Caps.PSKModes}

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
		return nil, nil, AlertInternalError
	}
	for _, ext := range []ExtensionBody{&sv, &sni, &ks, &sg, &sa, &kem} {
		err := ch.Extensions.Add(ext)
		if err != nil {
			return nil, nil, AlertInternalError
		}
	}
	if alpn != nil {
		// XXX: This can't be folded into the above because Go interface-typed
		// values are never reported as nil
		err := ch.Extensions.Add(alpn)
		if err != nil {
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
			ed = &EarlyDataExtension{}
			ch.Extensions.Add(ed)
		}

		// Add the shim PSK extension to the ClientHello
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
			return nil, nil, AlertInternalError
		}

		truncHash := state.state.Context.params.hash.New()
		truncHash.Write(trunc)

		binder := state.state.Context.computeFinishedData(state.state.Context.binderKey, truncHash.Sum(nil))

		// Replace the PSK extension
		psk.Binders[0].Binder = binder
		ch.Extensions.Add(psk)

		// If we got here, the earlier marshal succeeded (in ch.Truncated()), so
		// this one should too.
		state.state.clientHello, _ = HandshakeMessageFromBody(ch)
		state.state.Context.earlyUpdateWithClientHello(state.state.clientHello)
	} else if len(state.state.Opts.EarlyData) > 0 {
		return nil, nil, AlertInternalError
	}

	state.state.clientHello, err = HandshakeMessageFromBody(ch)
	if err != nil {
		return nil, nil, AlertInternalError
	}

	logf(logTypeHandshake, "[ClientStateStart] -> [ClientStateWaitSH]")
	nextState := ClientStateWaitSH{state: state.state}
	toSend := []HandshakeMessageBody{ch}
	return nextState, toSend, AlertNoAlert
}

type ClientStateWaitSH struct {
	state *connectionState
}

func (state ClientStateWaitSH) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil {
		return nil, nil, AlertUnexpectedMessage
	}

	switch hm.Type() {
	case HandshakeTypeHelloRetryRequest:
		// TODO: Process HRR
		// XXX: Go via ClientStateStart or just directly back to ClientStateWaitSH?
		// return ClientStateStart{state: state.state}.Next(nil)
		logf(logTypeHandshake, "[ClientStateWaitSH] -> [ClientStateWaitSH]")
		nextState := ClientStateWaitSH{state: state.state}
		toSend := []HandshakeMessageBody{&ClientHelloBody{}}
		return nextState, toSend, AlertNoAlert

	case HandshakeTypeServerHello:
		sh := hm.(*ServerHelloBody)

		// Check that the version sent by the server is the one we support
		if sh.Version != supportedVersion {
			return nil, nil, AlertProtocolVersion
		}

		// Do PSK or key agreement depending on extensions
		serverPSK := PreSharedKeyExtension{HandshakeType: HandshakeTypeServerHello}
		serverKeyShare := KeyShareExtension{HandshakeType: HandshakeTypeServerHello}
		serverEarlyData := EarlyDataExtension{}

		foundPSK := sh.Extensions.Find(&serverPSK)
		foundKeyShare := sh.Extensions.Find(&serverKeyShare)
		state.state.Params.UsingEarlyData = sh.Extensions.Find(&serverEarlyData)

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
				return nil, nil, AlertIllegalParameter
			}

			state.state.Params.UsingDH = true
			dhSecret, _ = keyAgreement(sks.Group, sks.KeyExchange, priv)
			logf(logTypeHandshake, "[client] got key share extension")
		}

		// We just unmarshaled this, so it should re-marshal
		state.state.serverHello, _ = HandshakeMessageFromBody(sh)

		err := state.state.Context.init(sh.CipherSuite,
			state.state.clientHello,
			state.state.helloRetryRequest,
			state.state.retryClientHello)
		if err != nil {
			return nil, nil, AlertInternalError
		}

		state.state.Context.updateWithServerHello(state.state.serverHello, dhSecret)

		logf(logTypeHandshake, "[ClientStateWaitSH] -> [ClientStateWaitEE]")
		nextState := ClientStateWaitEE{state: state.state}
		return nextState, nil, AlertNoAlert
	}

	return nil, nil, AlertUnexpectedMessage
}

type ClientStateWaitEE struct {
	state *connectionState
}

func (state ClientStateWaitEE) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeEncryptedExtensions {
		return nil, nil, AlertUnexpectedMessage
	}

	ee := hm.(*EncryptedExtensionsBody)
	serverALPN := ALPNExtension{}
	serverEarlyData := EarlyDataExtension{}

	gotALPN := ee.Extensions.Find(&serverALPN)
	state.state.Params.UsingEarlyData = ee.Extensions.Find(&serverEarlyData)

	if gotALPN && len(serverALPN.Protocols) > 0 {
		state.state.Params.NextProto = serverALPN.Protocols[0]
	}

	if state.state.Params.UsingPSK {
		nextState := ClientStateWaitFinished{state: state.state}
		return nextState, nil, AlertNoAlert
	}

	logf(logTypeHandshake, "[ClientStateWaitSH] -> [ClientStateWaitCertCR]")
	nextState := ClientStateWaitCertCR{state: state.state}
	return nextState, nil, AlertNoAlert
}

type ClientStateWaitCertCR struct {
	state *connectionState
}

func (state ClientStateWaitCertCR) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil {
		return nil, nil, AlertUnexpectedMessage
	}

	switch hm.Type() {
	case HandshakeTypeCertificate:
		// TODO: Process Certificate
		nextState := ClientStateWaitCV{state: state.state}
		return nextState, nil, AlertNoAlert

	case HandshakeTypeCertificateRequest:
		// TODO: Process CertificateRequest
		nextState := ClientStateWaitCert{state: state.state}
		return nextState, nil, AlertNoAlert
	}

	return nil, nil, AlertUnexpectedMessage
}

type ClientStateWaitCert struct {
	state *connectionState
}

func (state ClientStateWaitCert) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeCertificate {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Process Certificate

	nextState := ClientStateWaitCV{state: state.state}
	return nextState, nil, AlertNoAlert
}

type ClientStateWaitCV struct {
	state *connectionState
}

func (state ClientStateWaitCV) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeCertificateVerify {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Process CertificateVerify

	nextState := ClientStateWaitFinished{state: state.state}
	return nextState, nil, AlertNoAlert
}

type ClientStateWaitFinished struct {
	state *connectionState
}

func (state ClientStateWaitFinished) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeFinished {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Verify Finished

	nextState := StateConnected{state: state.state}
	toSend := []HandshakeMessageBody{
		&EndOfEarlyDataBody{},
		&CertificateBody{},
		&CertificateVerifyBody{},
		&ClientHelloBody{},
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
//                                v
//                             NEGOTIATED
//                                | Send ServerHello
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

type ServerStateStart struct {
	SendHRR bool
	state   *connectionState
}

func (state ServerStateStart) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeClientHello {
		logf(logTypeHandshake, "[ServerStateStart] unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	// This message was presumably just unmarshaled, so it should re-marshal
	ch := hm.(*ClientHelloBody)
	state.state.clientHello, _ = HandshakeMessageFromBody(ch)

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

	// Send a cookie if required
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
			Version: supportedVersion,
		}
		hrr.Extensions.Add(cookie)
		state.state.helloRetryRequest, _ = HandshakeMessageFromBody(hrr)

		nextState := ServerStateStart{state: state.state}
		toSend := []HandshakeMessageBody{hrr}
		logf(logTypeHandshake, "[ServerStateStart] Returning HelloRetryRequest")
		return nextState, toSend, AlertNoAlert
	}

	if state.state.Caps.RequireCookie && state.state.cookie != nil && !bytes.Equal(state.state.cookie, clientCookie.Cookie) {
		logf(logTypeHandshake, "[ServerStateStart] Cookie mismatch [%x] != [%x]", state.state.cookie, clientCookie.Cookie)
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
		chBytes := state.state.clientHello.Marshal()
		hrrBytes := state.state.helloRetryRequest.Marshal()

		chTrunc, err := ch.Truncated()
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error computing truncated ClientHello [%v]", err)
			return nil, nil, AlertDecodeError
		}

		context := append(chBytes, append(hrrBytes, chTrunc...)...)
		canDoPSK, state.state.selectedPSK, psk, ctx, err = PSKNegotiation(clientPSK.Identities, clientPSK.Binders, context, state.state.Caps.PSKs)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error in PSK negotiation [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	state.state.Context = ctx

	// Figure out if we actually should do DH / PSK
	state.state.Params.UsingDH, state.state.Params.UsingPSK = PSKModeNegotiation(canDoDH, canDoPSK, clientPSKModes.KEModes)

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
	state.state.Params.UsingEarlyData = EarlyDataNegotiation(state.state.Params.UsingPSK, gotEarlyData, state.state.Caps.AllowEarlyData)
	if state.state.Params.UsingEarlyData {
		state.state.Context.earlyUpdateWithClientHello(state.state.clientHello)
	}

	// Select a ciphersuite
	var err error
	state.state.Params.CipherSuite, err = CipherSuiteNegotiation(psk, ch.CipherSuites, state.state.Caps.CipherSuites)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateStart] No common ciphersuite found [%v]", err)
		return nil, nil, AlertHandshakeFailure
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

func (state ServerStateNegotiated) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	toSend := []HandshakeMessageBody{}

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

	toSend = append(toSend, sh)
	shm, err := HandshakeMessageFromBody(sh)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling ServerHello [%v]", err)
		return nil, nil, AlertInternalError
	}

	// Crank up the crypto context
	err = state.state.Context.init(sh.CipherSuite, state.state.clientHello, state.state.helloRetryRequest, state.state.clientHello)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error initializing crypto context [%v]", err)
		return nil, nil, AlertInternalError
	}

	err = state.state.Context.updateWithServerHello(shm, state.state.dhSecret)
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

	toSend = append(toSend, ee)
	transcript := []*HandshakeMessage{eem}

	// Send a CertificateRequest message if we want client auth
	var crm *HandshakeMessage
	if state.state.Caps.RequireClientAuth {
		state.state.Params.UsingClientAuth = true

		// XXX: We don't support sending any constraints besides a list of
		// supported signature algorithms
		cr := &CertificateRequestBody{SupportedSignatureAlgorithms: state.state.Caps.SignatureSchemes}
		crm, err = HandshakeMessageFromBody(cr)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling CertificateRequest [%v]", err)
			return nil, nil, AlertInternalError
		}

		toSend = append(toSend, cr)
		transcript = append(transcript, crm)
	}

	// Authenticate with a certificate if required
	if !state.state.Params.UsingPSK {
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

		certificateVerify := &CertificateVerifyBody{Algorithm: state.state.certScheme}
		logf(logTypeHandshake, "Creating CertVerify: %04x %v", state.state.certScheme, state.state.Context.params.hash)
		// XXX: This will fail with client auth
		cvTranscript := []*HandshakeMessage{state.state.clientHello, state.state.helloRetryRequest, state.state.clientHello, shm, eem, crm, certm}
		err = certificateVerify.Sign(state.state.cert.PrivateKey, cvTranscript, state.state.Context)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error signing CertificateVerify [%v]", err)
			return nil, nil, AlertInternalError
		}
		certvm, err := HandshakeMessageFromBody(certificateVerify)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling CertificateVerify [%v]", err)
			return nil, nil, AlertInternalError
		}

		toSend = append(toSend, []HandshakeMessageBody{certificate, certificateVerify}...)
		transcript = append(transcript, []*HandshakeMessage{certm, certvm}...)
	}

	// Crank the crypto context
	err = state.state.Context.updateWithServerFirstFlight(transcript)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error updating crypto context with server's first flight [%v]", err)
		return nil, nil, AlertInternalError
	}
	fm, err := HandshakeMessageFromBody(state.state.Context.serverFinished)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling Finished message [%v]", err)
		return nil, nil, AlertInternalError
	}

	toSend = append(toSend, state.state.Context.serverFinished)
	transcript = append(transcript, fm)
	state.state.transcript = []*HandshakeMessage{state.state.clientHello, state.state.helloRetryRequest, state.state.retryClientHello, shm}
	state.state.transcript = append(state.state.transcript, transcript...)

	if state.state.Params.UsingEarlyData {
		logf(logTypeHandshake, "[ServerStateNegotiated] -> [ServerStateWaitEOED]")
		nextState := ServerStateWaitEOED{state: state.state}
		return nextState, toSend, AlertNoAlert
	}

	// TODO: Rekey to handshake keys
	logf(logTypeHandshake, "[ServerStateNegotiated] -> [ServerStateWaitFlight2]")
	nextState, moreToSend, alert := ServerStateWaitFlight2{state: state.state}.Next(nil)
	toSend = append(toSend, moreToSend...)
	return nextState, toSend, alert
}

type ServerStateWaitEOED struct {
	state *connectionState
}

func (state ServerStateWaitEOED) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeEndOfEarlyData {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Rekey to handshake keys

	logf(logTypeHandshake, "[ServerStateWaitEOED] -> [ServerStateWaitFlight2]")
	return ServerStateWaitFlight2{state: state.state}.Next(nil)
}

type ServerStateWaitFlight2 struct {
	state *connectionState
}

func (state ServerStateWaitFlight2) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm != nil {
		return nil, nil, AlertUnexpectedMessage
	}

	if state.state.Params.UsingClientAuth {
		logf(logTypeHandshake, "[ServerStateWaitEOED] -> [ServerStateWaitCert]")
		nextState := ServerStateWaitCert{state: state.state}
		return nextState, nil, AlertNoAlert
	}

	logf(logTypeHandshake, "[ServerStateWaitFlight2] -> [ServerStateWaitFinished]")
	nextState := ServerStateWaitFinished{state: state.state}
	return nextState, nil, AlertNoAlert
}

type ServerStateWaitCert struct {
	CertificateEmpty bool
	state            *connectionState
}

func (state ServerStateWaitCert) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeCertificate {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO

	if state.CertificateEmpty {
		logf(logTypeHandshake, "[ServerStateWaitCert] -> [ServerStateWaitFinished]")
		nextState := ServerStateWaitFinished{state: state.state}
		return nextState, nil, AlertNoAlert
	}

	logf(logTypeHandshake, "[ServerStateWaitCert] -> [ServerStateWaitCV]")
	nextState := ServerStateWaitCV{state: state.state}
	return nextState, nil, AlertNoAlert
}

type ServerStateWaitCV struct {
	state *connectionState
}

func (state ServerStateWaitCV) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeCertificateVerify {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO

	logf(logTypeHandshake, "[ServerStateWaitCV] -> [ServerStateWaitFinished]")
	nextState := ServerStateWaitFinished{state: state.state}
	return nextState, nil, AlertNoAlert
}

type ServerStateWaitFinished struct {
	state *connectionState
}

func (state ServerStateWaitFinished) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil || hm.Type() != HandshakeTypeFinished {
		return nil, nil, AlertUnexpectedMessage
	}

	// TODO: Verify Finished

	logf(logTypeHandshake, "[ServerStateWaitFinished] -> [StateConnected]")
	nextState := StateConnected{state: state.state}
	return nextState, nil, AlertNoAlert
}

// Connected state is symmetric between client and server (NB: Might need a
// notation as to which role is being played)
type StateConnected struct {
	state *connectionState
}

func (state StateConnected) Next(hm HandshakeMessageBody) (State, []HandshakeMessageBody, Alert) {
	if hm == nil {
		return nil, nil, AlertUnexpectedMessage
	}

	switch hm.Type() {
	case HandshakeTypeKeyUpdate:
		// TODO: Handle KeyUpdate
		return state, nil, AlertNoAlert
	case HandshakeTypeNewSessionTicket:
		// TODO: Handle KeyUpdate
		return state, nil, AlertNoAlert
	}

	return nil, nil, AlertUnexpectedMessage
}
