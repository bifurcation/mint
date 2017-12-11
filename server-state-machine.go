package mint

import (
	"bytes"
	"fmt"
	"hash"
	"reflect"

	"github.com/bifurcation/mint/syntax"
)

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

// A cookie can be sent to the client in a HRR.
type cookie struct {
	// The CipherSuite that was selected when the client sent the first ClientHello
	CipherSuite     CipherSuite
	ClientHelloHash []byte `tls:"head=2"`

	// The ApplicationCookie can be provided by the application (by setting a Config.CookieHandler)
	ApplicationCookie []byte `tls:"head=2"`
}

type ServerStateStart struct {
	Caps  Capabilities
	conn  *Conn
	hsCtx HandshakeContext
}

var _ HandshakeState = &ServerStateStart{}

func (state ServerStateStart) State() State {
	return StateServerStart
}

func (state ServerStateStart) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeClientHello {
		logf(logTypeHandshake, "[ServerStateStart] unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	ch := &ClientHelloBody{}
	if _, err := ch.Unmarshal(hm.body); err != nil {
		logf(logTypeHandshake, "[ServerStateStart] Error decoding message: %v", err)
		return nil, nil, AlertDecodeError
	}

	clientHello := hm
	connParams := ConnectionParameters{}

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

	// Handle external extensions.
	if state.Caps.ExtensionHandler != nil {
		err := state.Caps.ExtensionHandler.Receive(HandshakeTypeClientHello, &ch.Extensions)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error running external extension handler [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

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

	clientSentCookie := len(clientCookie.Cookie) > 0

	if gotServerName {
		connParams.ServerName = string(*serverName)
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

	// The client sent a cookie. So this is probably the second ClientHello (sent as a response to a HRR)
	var firstClientHello *HandshakeMessage
	var initialCipherSuite CipherSuiteParams // the cipher suite that was negotiated when sending the HelloRetryRequest
	if clientSentCookie {
		plainCookie, err := state.Caps.CookieProtector.DecodeToken(clientCookie.Cookie)
		if err != nil {
			logf(logTypeHandshake, fmt.Sprintf("[ServerStateStart] Error decoding token [%v]", err))
			return nil, nil, AlertDecryptError
		}
		cookie := &cookie{}
		if _, err := syntax.Unmarshal(plainCookie, cookie); err != nil { // this should never happen
			logf(logTypeHandshake, fmt.Sprintf("[ServerStateStart] Error unmarshaling cookie [%v]", err))
			return nil, nil, AlertInternalError
		}
		// restore the hash of initial ClientHello from the cookie
		firstClientHello = &HandshakeMessage{
			msgType: HandshakeTypeMessageHash,
			body:    cookie.ClientHelloHash,
		}
		// have the application validate its part of the cookie
		if state.Caps.CookieHandler != nil && !state.Caps.CookieHandler.Validate(state.conn, cookie.ApplicationCookie) {
			logf(logTypeHandshake, "[ServerStateStart] Cookie mismatch")
			return nil, nil, AlertAccessDenied
		}
		var ok bool
		initialCipherSuite, ok = cipherSuiteMap[cookie.CipherSuite]
		if !ok {
			logf(logTypeHandshake, fmt.Sprintf("[ServerStateStart] Cookie contained invalid cipher suite: %#x", cookie.CipherSuite))
			return nil, nil, AlertInternalError
		}
	}

	// Figure out if we can do DH
	canDoDH, dhGroup, dhPublic, dhSecret := DHNegotiation(clientKeyShares.Shares, state.Caps.Groups)

	// Figure out if we can do PSK
	var canDoPSK bool
	var selectedPSK int
	var params CipherSuiteParams
	var psk *PreSharedKey
	if len(clientPSK.Identities) > 0 {
		contextBase := []byte{}
		if clientSentCookie {
			contextBase = append(contextBase, firstClientHello.Marshal()...)
			// fill in the cookie sent by the client. Needed to calculate the correct hash
			cookieExt := &CookieExtension{Cookie: clientCookie.Cookie}
			hrr, err := state.generateHRR(params.Suite, cookieExt)
			if err != nil {
				return nil, nil, AlertInternalError
			}
			contextBase = append(contextBase, hrr.Marshal()...)
		}
		chTrunc, err := ch.Truncated()
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error computing truncated ClientHello [%v]", err)
			return nil, nil, AlertDecodeError
		}
		context := append(contextBase, chTrunc...)

		canDoPSK, selectedPSK, psk, params, err = PSKNegotiation(clientPSK.Identities, clientPSK.Binders, context, state.Caps.PSKs)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error in PSK negotiation [%v]", err)
			return nil, nil, AlertInternalError
		}
		if clientSentCookie && initialCipherSuite.Suite != params.Suite {
			logf(logTypeHandshake, "[ServerStateStart] Would have selected a different CipherSuite after receiving the client's Cookie")
			return nil, nil, AlertInternalError
		}
	}

	// Figure out if we actually should do DH / PSK
	connParams.UsingDH, connParams.UsingPSK = PSKModeNegotiation(canDoDH, canDoPSK, clientPSKModes.KEModes)

	// Select a ciphersuite
	var err error
	connParams.CipherSuite, err = CipherSuiteNegotiation(psk, ch.CipherSuites, state.Caps.CipherSuites)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateStart] No common ciphersuite found [%v]", err)
		return nil, nil, AlertHandshakeFailure
	}
	if clientSentCookie && initialCipherSuite.Suite != connParams.CipherSuite {
		logf(logTypeHandshake, "[ServerStateStart] Would have selected a different CipherSuite after receiving the client's Cookie")
		return nil, nil, AlertInternalError
	}

	var helloRetryRequest *HandshakeMessage
	if state.Caps.RequireCookie {
		// Send a cookie if required
		// NB: Need to do this here because it's after ciphersuite selection, which
		// has to be after PSK selection.
		var shouldSendHRR bool
		var cookieExt *CookieExtension
		if !clientSentCookie { // this is the first ClientHello that we receive
			var appCookie []byte
			if state.Caps.CookieHandler == nil { // if Config.RequireCookie is set, but no CookieHandler was provided, we definitely need to send a cookie
				shouldSendHRR = true
			} else { // if the CookieHandler was set, we just send a cookie when the application provides one
				var err error
				appCookie, err = state.Caps.CookieHandler.Generate(state.conn)
				if err != nil {
					logf(logTypeHandshake, "[ServerStateStart] Error generating cookie [%v]", err)
					return nil, nil, AlertInternalError
				}
				shouldSendHRR = appCookie != nil
			}
			if shouldSendHRR {
				params := cipherSuiteMap[connParams.CipherSuite]
				h := params.Hash.New()
				h.Write(clientHello.Marshal())
				plainCookie, err := syntax.Marshal(cookie{
					CipherSuite:       connParams.CipherSuite,
					ClientHelloHash:   h.Sum(nil),
					ApplicationCookie: appCookie,
				})
				if err != nil {
					logf(logTypeHandshake, "[ServerStateStart] Error marshalling cookie [%v]", err)
					return nil, nil, AlertInternalError
				}
				cookieData, err := state.Caps.CookieProtector.NewToken(plainCookie)
				if err != nil {
					logf(logTypeHandshake, "[ServerStateStart] Error encoding cookie [%v]", err)
					return nil, nil, AlertInternalError
				}
				cookieExt = &CookieExtension{Cookie: cookieData}
			}
		} else {
			cookieExt = &CookieExtension{Cookie: clientCookie.Cookie}
		}

		// Generate a HRR. We will need it in both of the two cases:
		// 1. We need to send a Cookie. Then this HRR will be sent on the wire
		// 2. We need to validate a cookie. Then we need its hash
		// Ignoring errors because everything here is newly constructed, so there
		// shouldn't be marshal errors
		if shouldSendHRR || clientSentCookie {
			helloRetryRequest, err = state.generateHRR(connParams.CipherSuite, cookieExt)
			if err != nil {
				return nil, nil, AlertInternalError
			}
		}

		if shouldSendHRR {
			toSend := []HandshakeAction{
				QueueHandshakeMessage{helloRetryRequest},
				SendQueuedHandshake{},
			}
			logf(logTypeHandshake, "[ServerStateStart] -> [ServerStateStart]")
			return state, toSend, AlertStatelessRetry
		}
	}

	// If we've got no entropy to make keys from, fail
	if !connParams.UsingDH && !connParams.UsingPSK {
		logf(logTypeHandshake, "[ServerStateStart] Neither DH nor PSK negotiated")
		return nil, nil, AlertHandshakeFailure
	}

	var pskSecret []byte
	var cert *Certificate
	var certScheme SignatureScheme
	if connParams.UsingPSK {
		pskSecret = psk.Key
	} else {
		psk = nil

		// If we're not using a PSK mode, then we need to have certain extensions
		if !gotServerName || !gotSupportedGroups || !gotSignatureAlgorithms {
			logf(logTypeHandshake, "[ServerStateStart] Insufficient extensions (%v %v %v)",
				gotServerName, gotSupportedGroups, gotSignatureAlgorithms)
			return nil, nil, AlertMissingExtension
		}

		// Select a certificate
		name := string(*serverName)
		var err error
		cert, certScheme, err = CertificateSelection(&name, signatureAlgorithms.Algorithms, state.Caps.Certificates)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] No appropriate certificate found [%v]", err)
			return nil, nil, AlertAccessDenied
		}
	}

	if !connParams.UsingDH {
		dhSecret = nil
	}

	// Figure out if we're going to do early data
	var clientEarlyTrafficSecret []byte
	connParams.ClientSendingEarlyData = gotEarlyData
	connParams.UsingEarlyData = EarlyDataNegotiation(connParams.UsingPSK, gotEarlyData, state.Caps.AllowEarlyData)
	if connParams.UsingEarlyData {
		h := params.Hash.New()
		h.Write(clientHello.Marshal())
		chHash := h.Sum(nil)

		zero := bytes.Repeat([]byte{0}, params.Hash.Size())
		earlySecret := HkdfExtract(params.Hash, zero, pskSecret)
		clientEarlyTrafficSecret = deriveSecret(params, earlySecret, labelEarlyTrafficSecret, chHash)
	}

	// Select a next protocol
	connParams.NextProto, err = ALPNNegotiation(psk, clientALPN.Protocols, state.Caps.NextProtos)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateStart] No common application-layer protocol found [%v]", err)
		return nil, nil, AlertNoApplicationProtocol
	}

	logf(logTypeHandshake, "[ServerStateStart] -> [ServerStateNegotiated]")
	return ServerStateNegotiated{
		Caps:                     state.Caps,
		Params:                   connParams,
		hsCtx:                    state.hsCtx,
		dhGroup:                  dhGroup,
		dhPublic:                 dhPublic,
		dhSecret:                 dhSecret,
		pskSecret:                pskSecret,
		selectedPSK:              selectedPSK,
		cert:                     cert,
		certScheme:               certScheme,
		clientEarlyTrafficSecret: clientEarlyTrafficSecret,

		firstClientHello:  firstClientHello,
		helloRetryRequest: helloRetryRequest,
		clientHello:       clientHello,
	}, nil, AlertNoAlert
}

func (state *ServerStateStart) generateHRR(cs CipherSuite, cookieExt *CookieExtension) (*HandshakeMessage, error) {
	var helloRetryRequest *HandshakeMessage
	hrr := &HelloRetryRequestBody{
		Version:     supportedVersion,
		CipherSuite: cs,
	}
	if err := hrr.Extensions.Add(cookieExt); err != nil {
		logf(logTypeHandshake, "[ServerStateStart] Error adding CookieExtension [%v]", err)
		return nil, err
	}
	// Run the external extension handler.
	if state.Caps.ExtensionHandler != nil {
		err := state.Caps.ExtensionHandler.Send(HandshakeTypeHelloRetryRequest, &hrr.Extensions)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateStart] Error running external extension sender [%v]", err)
			return nil, err
		}
	}
	helloRetryRequest, err := state.hsCtx.hOut.HandshakeMessageFromBody(hrr)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateStart] Error marshaling HRR [%v]", err)
		return nil, err
	}
	return helloRetryRequest, nil
}

type ServerStateNegotiated struct {
	Caps                     Capabilities
	Params                   ConnectionParameters
	hsCtx                    HandshakeContext
	dhGroup                  NamedGroup
	dhPublic                 []byte
	dhSecret                 []byte
	pskSecret                []byte
	clientEarlyTrafficSecret []byte
	selectedPSK              int
	cert                     *Certificate
	certScheme               SignatureScheme

	firstClientHello  *HandshakeMessage
	helloRetryRequest *HandshakeMessage
	clientHello       *HandshakeMessage
}

var _ HandshakeState = &ServerStateNegotiated{}

func (state ServerStateNegotiated) State() State {
	return StateServerNegotiated
}

func (state ServerStateNegotiated) Next(_ handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	// Create the ServerHello
	sh := &ServerHelloBody{
		Version:     supportedVersion,
		CipherSuite: state.Params.CipherSuite,
	}
	if _, err := prng.Read(sh.Random[:]); err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error creating server random [%v]", err)
		return nil, nil, AlertInternalError
	}
	if state.Params.UsingDH {
		logf(logTypeHandshake, "[ServerStateNegotiated] sending DH extension")
		err := sh.Extensions.Add(&KeyShareExtension{
			HandshakeType: HandshakeTypeServerHello,
			Shares:        []KeyShareEntry{{Group: state.dhGroup, KeyExchange: state.dhPublic}},
		})
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error adding key_shares extension [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	if state.Params.UsingPSK {
		logf(logTypeHandshake, "[ServerStateNegotiated] sending PSK extension")
		err := sh.Extensions.Add(&PreSharedKeyExtension{
			HandshakeType:    HandshakeTypeServerHello,
			SelectedIdentity: uint16(state.selectedPSK),
		})
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error adding PSK extension [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	// Run the external extension handler.
	if state.Caps.ExtensionHandler != nil {
		err := state.Caps.ExtensionHandler.Send(HandshakeTypeServerHello, &sh.Extensions)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error running external extension sender [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	serverHello, err := state.hsCtx.hOut.HandshakeMessageFromBody(sh)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling ServerHello [%v]", err)
		return nil, nil, AlertInternalError
	}

	// Look up crypto params
	params, ok := cipherSuiteMap[sh.CipherSuite]
	if !ok {
		logf(logTypeCrypto, "Unsupported ciphersuite [%04x]", sh.CipherSuite)
		return nil, nil, AlertHandshakeFailure
	}

	// Start up the handshake hash
	handshakeHash := params.Hash.New()
	handshakeHash.Write(state.firstClientHello.Marshal())
	handshakeHash.Write(state.helloRetryRequest.Marshal())
	handshakeHash.Write(state.clientHello.Marshal())
	handshakeHash.Write(serverHello.Marshal())

	// Compute handshake secrets
	zero := bytes.Repeat([]byte{0}, params.Hash.Size())

	var earlySecret []byte
	if state.Params.UsingPSK {
		earlySecret = HkdfExtract(params.Hash, zero, state.pskSecret)
	} else {
		earlySecret = HkdfExtract(params.Hash, zero, zero)
	}

	if state.dhSecret == nil {
		state.dhSecret = zero
	}

	h0 := params.Hash.New().Sum(nil)
	h2 := handshakeHash.Sum(nil)
	preHandshakeSecret := deriveSecret(params, earlySecret, labelDerived, h0)
	handshakeSecret := HkdfExtract(params.Hash, preHandshakeSecret, state.dhSecret)
	clientHandshakeTrafficSecret := deriveSecret(params, handshakeSecret, labelClientHandshakeTrafficSecret, h2)
	serverHandshakeTrafficSecret := deriveSecret(params, handshakeSecret, labelServerHandshakeTrafficSecret, h2)
	preMasterSecret := deriveSecret(params, handshakeSecret, labelDerived, h0)
	masterSecret := HkdfExtract(params.Hash, preMasterSecret, zero)

	logf(logTypeCrypto, "early secret (init!): [%d] %x", len(earlySecret), earlySecret)
	logf(logTypeCrypto, "handshake secret: [%d] %x", len(handshakeSecret), handshakeSecret)
	logf(logTypeCrypto, "client handshake traffic secret: [%d] %x", len(clientHandshakeTrafficSecret), clientHandshakeTrafficSecret)
	logf(logTypeCrypto, "server handshake traffic secret: [%d] %x", len(serverHandshakeTrafficSecret), serverHandshakeTrafficSecret)
	logf(logTypeCrypto, "master secret: [%d] %x", len(masterSecret), masterSecret)

	clientHandshakeKeys := makeTrafficKeys(params, clientHandshakeTrafficSecret)
	serverHandshakeKeys := makeTrafficKeys(params, serverHandshakeTrafficSecret)

	// Send an EncryptedExtensions message (even if it's empty)
	eeList := ExtensionList{}
	if state.Params.NextProto != "" {
		logf(logTypeHandshake, "[server] sending ALPN extension")
		err = eeList.Add(&ALPNExtension{Protocols: []string{state.Params.NextProto}})
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error adding ALPN to EncryptedExtensions [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	if state.Params.UsingEarlyData {
		logf(logTypeHandshake, "[server] sending EDI extension")
		err = eeList.Add(&EarlyDataExtension{})
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error adding EDI to EncryptedExtensions [%v]", err)
			return nil, nil, AlertInternalError
		}
	}
	ee := &EncryptedExtensionsBody{eeList}

	// Run the external extension handler.
	if state.Caps.ExtensionHandler != nil {
		err := state.Caps.ExtensionHandler.Send(HandshakeTypeEncryptedExtensions, &ee.Extensions)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error running external extension sender [%v]", err)
			return nil, nil, AlertInternalError
		}
	}

	eem, err := state.hsCtx.hOut.HandshakeMessageFromBody(ee)
	if err != nil {
		logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling EncryptedExtensions [%v]", err)
		return nil, nil, AlertInternalError
	}

	handshakeHash.Write(eem.Marshal())

	toSend := []HandshakeAction{
		QueueHandshakeMessage{serverHello},
		RekeyOut{epoch: EpochHandshakeData, KeySet: serverHandshakeKeys},
		QueueHandshakeMessage{eem},
	}

	// Authenticate with a certificate if required
	if !state.Params.UsingPSK {
		// Send a CertificateRequest message if we want client auth
		if state.Caps.RequireClientAuth {
			state.Params.UsingClientAuth = true

			// XXX: We don't support sending any constraints besides a list of
			// supported signature algorithms
			cr := &CertificateRequestBody{}
			schemes := &SignatureAlgorithmsExtension{Algorithms: state.Caps.SignatureSchemes}
			err := cr.Extensions.Add(schemes)
			if err != nil {
				logf(logTypeHandshake, "[ServerStateNegotiated] Error adding supported schemes to CertificateRequest [%v]", err)
				return nil, nil, AlertInternalError
			}

			crm, err := state.hsCtx.hOut.HandshakeMessageFromBody(cr)
			if err != nil {
				logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling CertificateRequest [%v]", err)
				return nil, nil, AlertInternalError
			}
			//TODO state.state.serverCertificateRequest = cr

			toSend = append(toSend, QueueHandshakeMessage{crm})
			handshakeHash.Write(crm.Marshal())
		}

		// Create and send Certificate, CertificateVerify
		certificate := &CertificateBody{
			CertificateList: make([]CertificateEntry, len(state.cert.Chain)),
		}
		for i, entry := range state.cert.Chain {
			certificate.CertificateList[i] = CertificateEntry{CertData: entry}
		}
		certm, err := state.hsCtx.hOut.HandshakeMessageFromBody(certificate)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling Certificate [%v]", err)
			return nil, nil, AlertInternalError
		}

		toSend = append(toSend, QueueHandshakeMessage{certm})
		handshakeHash.Write(certm.Marshal())

		certificateVerify := &CertificateVerifyBody{Algorithm: state.certScheme}
		logf(logTypeHandshake, "Creating CertVerify: %04x %v", state.certScheme, params.Hash)

		hcv := handshakeHash.Sum(nil)
		logf(logTypeHandshake, "Handshake Hash to be verified: [%d] %x", len(hcv), hcv)

		err = certificateVerify.Sign(state.cert.PrivateKey, hcv)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error signing CertificateVerify [%v]", err)
			return nil, nil, AlertInternalError
		}
		certvm, err := state.hsCtx.hOut.HandshakeMessageFromBody(certificateVerify)
		if err != nil {
			logf(logTypeHandshake, "[ServerStateNegotiated] Error marshaling CertificateVerify [%v]", err)
			return nil, nil, AlertInternalError
		}

		toSend = append(toSend, QueueHandshakeMessage{certvm})
		handshakeHash.Write(certvm.Marshal())
	}

	// Compute secrets resulting from the server's first flight
	h3 := handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 3 [%d] %x", len(h3), h3)
	logf(logTypeCrypto, "handshake hash for server Finished: [%d] %x", len(h3), h3)

	serverFinishedData := computeFinishedData(params, serverHandshakeTrafficSecret, h3)
	logf(logTypeCrypto, "server finished data: [%d] %x", len(serverFinishedData), serverFinishedData)

	// Assemble the Finished message
	fin := &FinishedBody{
		VerifyDataLen: len(serverFinishedData),
		VerifyData:    serverFinishedData,
	}
	finm, _ := state.hsCtx.hOut.HandshakeMessageFromBody(fin)

	toSend = append(toSend, QueueHandshakeMessage{finm})
	handshakeHash.Write(finm.Marshal())
	toSend = append(toSend, SendQueuedHandshake{})

	// Compute traffic secrets
	h4 := handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 4 [%d] %x", len(h4), h4)
	logf(logTypeCrypto, "handshake hash for server Finished: [%d] %x", len(h4), h4)

	clientTrafficSecret := deriveSecret(params, masterSecret, labelClientApplicationTrafficSecret, h4)
	serverTrafficSecret := deriveSecret(params, masterSecret, labelServerApplicationTrafficSecret, h4)
	logf(logTypeCrypto, "client traffic secret: [%d] %x", len(clientTrafficSecret), clientTrafficSecret)
	logf(logTypeCrypto, "server traffic secret: [%d] %x", len(serverTrafficSecret), serverTrafficSecret)

	serverTrafficKeys := makeTrafficKeys(params, serverTrafficSecret)
	toSend = append(toSend, RekeyOut{epoch: EpochApplicationData, KeySet: serverTrafficKeys})

	exporterSecret := deriveSecret(params, masterSecret, labelExporterSecret, h4)
	logf(logTypeCrypto, "server exporter secret: [%d] %x", len(exporterSecret), exporterSecret)

	if state.Params.UsingEarlyData {
		clientEarlyTrafficKeys := makeTrafficKeys(params, state.clientEarlyTrafficSecret)

		logf(logTypeHandshake, "[ServerStateNegotiated] -> [ServerStateWaitEOED]")
		nextState := ServerStateWaitEOED{
			AuthCertificate:              state.Caps.AuthCertificate,
			Params:                       state.Params,
			hsCtx:                        state.hsCtx,
			cryptoParams:                 params,
			handshakeHash:                handshakeHash,
			masterSecret:                 masterSecret,
			clientHandshakeTrafficSecret: clientHandshakeTrafficSecret,
			clientTrafficSecret:          clientTrafficSecret,
			serverTrafficSecret:          serverTrafficSecret,
			exporterSecret:               exporterSecret,
		}
		toSend = append(toSend, []HandshakeAction{
			RekeyIn{epoch: EpochEarlyData, KeySet: clientEarlyTrafficKeys},
			ReadEarlyData{},
		}...)
		return nextState, toSend, AlertNoAlert
	}

	logf(logTypeHandshake, "[ServerStateNegotiated] -> [ServerStateWaitFlight2]")
	toSend = append(toSend, []HandshakeAction{
		RekeyIn{epoch: EpochHandshakeData, KeySet: clientHandshakeKeys},
		ReadPastEarlyData{},
	}...)
	waitFlight2 := ServerStateWaitFlight2{
		AuthCertificate:              state.Caps.AuthCertificate,
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 params,
		handshakeHash:                handshakeHash,
		masterSecret:                 masterSecret,
		clientHandshakeTrafficSecret: clientHandshakeTrafficSecret,
		clientTrafficSecret:          clientTrafficSecret,
		serverTrafficSecret:          serverTrafficSecret,
		exporterSecret:               exporterSecret,
	}
	return waitFlight2, toSend, AlertNoAlert
}

type ServerStateWaitEOED struct {
	AuthCertificate              func(chain []CertificateEntry) error
	Params                       ConnectionParameters
	hsCtx                        HandshakeContext
	cryptoParams                 CipherSuiteParams
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	handshakeHash                hash.Hash
	clientTrafficSecret          []byte
	serverTrafficSecret          []byte
	exporterSecret               []byte
}

var _ HandshakeState = &ServerStateWaitEOED{}

func (state ServerStateWaitEOED) State() State {
	return StateServerWaitEOED
}

func (state ServerStateWaitEOED) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
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
	toSend := []HandshakeAction{
		RekeyIn{epoch: EpochHandshakeData, KeySet: clientHandshakeKeys},
	}
	waitFlight2 := ServerStateWaitFlight2{
		AuthCertificate:              state.AuthCertificate,
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 state.cryptoParams,
		handshakeHash:                state.handshakeHash,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		clientTrafficSecret:          state.clientTrafficSecret,
		serverTrafficSecret:          state.serverTrafficSecret,
		exporterSecret:               state.exporterSecret,
	}
	return waitFlight2, toSend, AlertNoAlert
}

type ServerStateWaitFlight2 struct {
	AuthCertificate              func(chain []CertificateEntry) error
	Params                       ConnectionParameters
	hsCtx                        HandshakeContext
	cryptoParams                 CipherSuiteParams
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	handshakeHash                hash.Hash
	clientTrafficSecret          []byte
	serverTrafficSecret          []byte
	exporterSecret               []byte
}

var _ HandshakeState = &ServerStateWaitFlight2{}

func (state ServerStateWaitFlight2) State() State {
	return StateServerWaitFlight2
}

func (state ServerStateWaitFlight2) Next(_ handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	if state.Params.UsingClientAuth {
		logf(logTypeHandshake, "[ServerStateWaitFlight2] -> [ServerStateWaitCert]")
		nextState := ServerStateWaitCert{
			AuthCertificate:              state.AuthCertificate,
			Params:                       state.Params,
			hsCtx:                        state.hsCtx,
			cryptoParams:                 state.cryptoParams,
			handshakeHash:                state.handshakeHash,
			masterSecret:                 state.masterSecret,
			clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
			clientTrafficSecret:          state.clientTrafficSecret,
			serverTrafficSecret:          state.serverTrafficSecret,
			exporterSecret:               state.exporterSecret,
		}
		return nextState, nil, AlertNoAlert
	}

	logf(logTypeHandshake, "[ServerStateWaitFlight2] -> [ServerStateWaitFinished]")
	nextState := ServerStateWaitFinished{
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 state.cryptoParams,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		handshakeHash:                state.handshakeHash,
		clientTrafficSecret:          state.clientTrafficSecret,
		serverTrafficSecret:          state.serverTrafficSecret,
		exporterSecret:               state.exporterSecret,
	}
	return nextState, nil, AlertNoAlert
}

type ServerStateWaitCert struct {
	AuthCertificate              func(chain []CertificateEntry) error
	Params                       ConnectionParameters
	hsCtx                        HandshakeContext
	cryptoParams                 CipherSuiteParams
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
	handshakeHash                hash.Hash
	clientTrafficSecret          []byte
	serverTrafficSecret          []byte
	exporterSecret               []byte
}

var _ HandshakeState = &ServerStateWaitCert{}

func (state ServerStateWaitCert) State() State {
	return StateServerWaitCert
}

func (state ServerStateWaitCert) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeCertificate {
		logf(logTypeHandshake, "[ServerStateWaitCert] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	cert := &CertificateBody{}
	if _, err := cert.Unmarshal(hm.body); err != nil {
		logf(logTypeHandshake, "[ServerStateWaitCert] Unexpected message")
		return nil, nil, AlertDecodeError
	}

	state.handshakeHash.Write(hm.Marshal())

	if len(cert.CertificateList) == 0 {
		logf(logTypeHandshake, "[ServerStateWaitCert] WARNING client did not provide a certificate")

		logf(logTypeHandshake, "[ServerStateWaitCert] -> [ServerStateWaitFinished]")
		nextState := ServerStateWaitFinished{
			Params:                       state.Params,
			hsCtx:                        state.hsCtx,
			cryptoParams:                 state.cryptoParams,
			masterSecret:                 state.masterSecret,
			clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
			handshakeHash:                state.handshakeHash,
			clientTrafficSecret:          state.clientTrafficSecret,
			serverTrafficSecret:          state.serverTrafficSecret,
			exporterSecret:               state.exporterSecret,
		}
		return nextState, nil, AlertNoAlert
	}

	logf(logTypeHandshake, "[ServerStateWaitCert] -> [ServerStateWaitCV]")
	nextState := ServerStateWaitCV{
		AuthCertificate:              state.AuthCertificate,
		Params:                       state.Params,
		hsCtx:                        state.hsCtx,
		cryptoParams:                 state.cryptoParams,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		handshakeHash:                state.handshakeHash,
		clientTrafficSecret:          state.clientTrafficSecret,
		serverTrafficSecret:          state.serverTrafficSecret,
		clientCertificate:            cert,
		exporterSecret:               state.exporterSecret,
	}
	return nextState, nil, AlertNoAlert
}

type ServerStateWaitCV struct {
	AuthCertificate func(chain []CertificateEntry) error
	Params          ConnectionParameters
	hsCtx           HandshakeContext
	cryptoParams    CipherSuiteParams

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte

	handshakeHash       hash.Hash
	clientTrafficSecret []byte
	serverTrafficSecret []byte
	exporterSecret      []byte

	clientCertificate *CertificateBody
}

var _ HandshakeState = &ServerStateWaitCV{}

func (state ServerStateWaitCV) State() State {
	return StateServerWaitCV
}

func (state ServerStateWaitCV) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeCertificateVerify {
		logf(logTypeHandshake, "[ServerStateWaitCV] Unexpected message [%+v] [%s]", hm, reflect.TypeOf(hm))
		return nil, nil, AlertUnexpectedMessage
	}

	certVerify := &CertificateVerifyBody{}
	if _, err := certVerify.Unmarshal(hm.body); err != nil {
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
		hsCtx:                        state.hsCtx,
		cryptoParams:                 state.cryptoParams,
		masterSecret:                 state.masterSecret,
		clientHandshakeTrafficSecret: state.clientHandshakeTrafficSecret,
		handshakeHash:                state.handshakeHash,
		clientTrafficSecret:          state.clientTrafficSecret,
		serverTrafficSecret:          state.serverTrafficSecret,
		exporterSecret:               state.exporterSecret,
	}
	return nextState, nil, AlertNoAlert
}

type ServerStateWaitFinished struct {
	Params       ConnectionParameters
	hsCtx        HandshakeContext
	cryptoParams CipherSuiteParams

	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte

	handshakeHash       hash.Hash
	clientTrafficSecret []byte
	serverTrafficSecret []byte
	exporterSecret      []byte
}

var _ HandshakeState = &ServerStateWaitFinished{}

func (state ServerStateWaitFinished) State() State {
	return StateServerWaitFinished
}

func (state ServerStateWaitFinished) Next(hr handshakeMessageReader) (HandshakeState, []HandshakeAction, Alert) {
	hm, alert := hr.ReadMessage()
	if alert != AlertNoAlert {
		return nil, nil, alert
	}
	if hm == nil || hm.msgType != HandshakeTypeFinished {
		logf(logTypeHandshake, "[ServerStateWaitFinished] Unexpected message")
		return nil, nil, AlertUnexpectedMessage
	}

	fin := &FinishedBody{VerifyDataLen: state.cryptoParams.Hash.Size()}
	if _, err := fin.Unmarshal(hm.body); err != nil {
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
		hsCtx:               state.hsCtx,
		isClient:            false,
		cryptoParams:        state.cryptoParams,
		resumptionSecret:    resumptionSecret,
		clientTrafficSecret: state.clientTrafficSecret,
		serverTrafficSecret: state.serverTrafficSecret,
		exporterSecret:      state.exporterSecret,
	}
	toSend := []HandshakeAction{
		RekeyIn{epoch: EpochApplicationData, KeySet: clientTrafficKeys},
	}
	return nextState, toSend, AlertNoAlert
}
