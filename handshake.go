package mint

import (
	"bytes"
	"fmt"
)

type capabilities struct {
	// For both client and server
	CipherSuites     []CipherSuite
	Groups           []NamedGroup
	SignatureSchemes []SignatureScheme
	PSKs             map[string]PreSharedKey

	// For client
	PSKModes []PSKKeyExchangeMode

	// For server
	NextProtos     []string
	Certificates   []*Certificate
	AllowEarlyData bool
}

type connectionOptions struct {
	ServerName string
	NextProtos []string
	EarlyData  []byte
}

type connectionParameters struct {
	UsingPSK       bool
	UsingDH        bool
	UsingEarlyData bool

	CipherSuite CipherSuite
	ServerName  string
	NextProto   string
}

type handshake interface {
	IsClient() bool
	ConnectionParams() connectionParameters
	CryptoContext() *cryptoContext
	InboundKeys() (aeadFactory, keySet)
	OutboundKeys() (aeadFactory, keySet)
	CreateKeyUpdate(KeyUpdateRequest) (*handshakeMessage, error)
	HandleKeyUpdate(*handshakeMessage) (*handshakeMessage, error)
	HandleNewSessionTicket(*handshakeMessage) (PreSharedKey, error)
}

///// Common methods

func createKeyUpdate(client bool, ctx *cryptoContext, requestUpdate KeyUpdateRequest) (*handshakeMessage, error) {
	// Roll the outbound keys
	err := ctx.updateKeys(client)
	if err != nil {
		return nil, err
	}

	// Return a KeyUpdate message
	return handshakeMessageFromBody(&keyUpdateBody{
		KeyUpdateRequest: requestUpdate,
	})
}

func handleKeyUpdate(client bool, ctx *cryptoContext, hm *handshakeMessage) (*handshakeMessage, error) {
	var ku keyUpdateBody
	_, err := ku.Unmarshal(hm.body)
	if err != nil {
		return nil, err
	}

	// Roll the inbound keys
	err = ctx.updateKeys(!client)
	if err != nil {
		return nil, err
	}

	// If requested, roll outbound keys and send a KeyUpdate
	var outboundMessage *handshakeMessage
	if ku.KeyUpdateRequest == KeyUpdateRequested {
		err = ctx.updateKeys(client)
		if err != nil {
			return nil, err
		}

		return handshakeMessageFromBody(&keyUpdateBody{
			KeyUpdateRequest: KeyUpdateNotRequested,
		})
	}

	return outboundMessage, nil
}

///// Client-side Handshake methods

type clientHandshake struct {
	OfferedDH  map[NamedGroup][]byte
	OfferedPSK PreSharedKey

	PSK     []byte
	Context cryptoContext
	Params  connectionParameters

	AuthCertificate func(chain []certificateEntry) error

	clientHello *handshakeMessage
	serverHello *handshakeMessage
}

func (h *clientHandshake) IsClient() bool {
	return true
}

func (h *clientHandshake) CryptoContext() *cryptoContext {
	return &h.Context
}

func (h clientHandshake) ConnectionParams() connectionParameters {
	return h.Params
}

func (h *clientHandshake) InboundKeys() (aeadFactory, keySet) {
	return h.Context.params.cipher, h.Context.serverTrafficKeys
}

func (h *clientHandshake) OutboundKeys() (aeadFactory, keySet) {
	return h.Context.params.cipher, h.Context.clientTrafficKeys
}

func (h *clientHandshake) CreateKeyUpdate(requestUpdate KeyUpdateRequest) (*handshakeMessage, error) {
	return createKeyUpdate(true, &h.Context, requestUpdate)
}

func (h *clientHandshake) HandleKeyUpdate(hm *handshakeMessage) (*handshakeMessage, error) {
	return handleKeyUpdate(true, &h.Context, hm)
}

func (h *clientHandshake) HandleNewSessionTicket(hm *handshakeMessage) (PreSharedKey, error) {
	var tkt newSessionTicketBody
	_, err := tkt.Unmarshal(hm.body)
	if err != nil {
		return PreSharedKey{}, err
	}

	psk := PreSharedKey{
		CipherSuite:  h.Context.suite,
		IsResumption: true,
		Identity:     tkt.Ticket,
		Key:          h.Context.resumptionSecret,
	}

	return psk, nil
}

func (h *clientHandshake) CreateClientHello(opts connectionOptions, caps capabilities) (*handshakeMessage, error) {
	// key_shares
	h.OfferedDH = map[NamedGroup][]byte{}
	ks := KeyShareExtension{
		HandshakeType: HandshakeTypeClientHello,
		Shares:        make([]KeyShareEntry, len(caps.Groups)),
	}
	for i, group := range caps.Groups {
		pub, priv, err := newKeyShare(group)
		if err != nil {
			return nil, err
		}

		ks.Shares[i].Group = group
		ks.Shares[i].KeyExchange = pub
		h.OfferedDH[group] = priv
	}

	// supported_versions, supported_groups, signature_algorithms, server_name
	sv := SupportedVersionsExtension{Versions: []uint16{supportedVersion}}
	sni := ServerNameExtension(opts.ServerName)
	sg := SupportedGroupsExtension{Groups: caps.Groups}
	sa := SignatureAlgorithmsExtension{Algorithms: caps.SignatureSchemes}
	kem := PSKKeyExchangeModesExtension{KEModes: caps.PSKModes}

	h.Params.ServerName = opts.ServerName

	// Application Layer Protocol Negotiation
	var alpn *ALPNExtension
	if (opts.NextProtos != nil) && (len(opts.NextProtos) > 0) {
		alpn = &ALPNExtension{Protocols: opts.NextProtos}
	}

	// Construct base ClientHello
	ch := &clientHelloBody{
		cipherSuites: caps.CipherSuites,
	}
	_, err := prng.Read(ch.random[:])
	if err != nil {
		return nil, err
	}
	for _, ext := range []ExtensionBody{&sv, &sni, &ks, &sg, &sa, &kem} {
		err := ch.extensions.Add(ext)
		if err != nil {
			return nil, err
		}
	}
	if alpn != nil {
		// XXX: This can't be folded into the above because Go interface-typed
		// values are never reported as nil
		err := ch.extensions.Add(alpn)
		if err != nil {
			return nil, err
		}
	}

	// Handle PSK and EarlyData just before transmitting, so that we can
	// calculate the PSK binder value
	var psk *PreSharedKeyExtension
	var ed *EarlyDataExtension
	if key, ok := caps.PSKs[opts.ServerName]; ok {
		h.OfferedPSK = key

		// Narrow ciphersuites to ones that match PSK hash
		keyParams, ok := cipherSuiteMap[key.CipherSuite]
		if !ok {
			return nil, fmt.Errorf("Unsupported ciphersuite from PSK")
		}

		compatibleSuites := []CipherSuite{}
		for _, suite := range ch.cipherSuites {
			if cipherSuiteMap[suite].hash == keyParams.hash {
				compatibleSuites = append(compatibleSuites, suite)
			}
		}
		ch.cipherSuites = compatibleSuites

		// Signal early data if we're going to do it
		if opts.EarlyData != nil {
			ed = &EarlyDataExtension{}
			ch.extensions.Add(ed)
		}

		// Add the shim PSK extension to the ClientHello
		psk = &PreSharedKeyExtension{
			HandshakeType: HandshakeTypeClientHello,
			Identities: []PSKIdentity{
				PSKIdentity{Identity: key.Identity},
			},
			Binders: []PSKBinderEntry{
				// Note: Stub to get the length fields right
				PSKBinderEntry{Binder: bytes.Repeat([]byte{0x00}, keyParams.hash.Size())},
			},
		}
		ch.extensions.Add(psk)

		// Pre-Initialize the crypto context and compute the binder value
		h.Context.preInit(key)

		// Compute the binder value
		trunc, err := ch.Truncated()
		if err != nil {
			return nil, err
		}

		truncHash := h.Context.params.hash.New()
		truncHash.Write(trunc)

		binder := h.Context.computeFinishedData(h.Context.binderKey, truncHash.Sum(nil))

		// Replace the PSK extension
		psk.Binders[0].Binder = binder
		ch.extensions.Add(psk)

		h.clientHello, err = handshakeMessageFromBody(ch)
		if err != nil {
			return nil, err
		}

		h.Context.earlyUpdateWithClientHello(h.clientHello)
	}

	h.clientHello, err = handshakeMessageFromBody(ch)
	if err != nil {
		return nil, err
	}

	return h.clientHello, nil
}

func (h *clientHandshake) HandleServerHello(shm *handshakeMessage) error {
	// Unmarshal the ServerHello
	sh := &serverHelloBody{}
	_, err := sh.Unmarshal(shm.body)
	if err != nil {
		return err
	}

	// Check that the version sent by the server is the one we support
	if sh.Version != supportedVersion {
		return fmt.Errorf("tls.client: Server sent unsupported version %x", sh.Version)
	}

	// Do PSK or key agreement depending on extensions
	serverPSK := PreSharedKeyExtension{HandshakeType: HandshakeTypeServerHello}
	serverKeyShare := KeyShareExtension{HandshakeType: HandshakeTypeServerHello}
	serverEarlyData := EarlyDataExtension{}

	foundPSK := sh.Extensions.Find(&serverPSK)
	foundKeyShare := sh.Extensions.Find(&serverKeyShare)
	h.Params.UsingEarlyData = sh.Extensions.Find(&serverEarlyData)

	if foundPSK && (serverPSK.SelectedIdentity == 0) {
		h.PSK = h.OfferedPSK.Key
		h.Params.UsingPSK = true
		logf(logTypeHandshake, "[client] got PSK extension")
	} else {
		// If the server rejected our PSK, then we have to re-start without it
		h.Context = cryptoContext{}
	}

	var dhSecret []byte
	if foundKeyShare {
		sks := serverKeyShare.Shares[0]
		priv, ok := h.OfferedDH[sks.Group]
		if !ok {
			return fmt.Errorf("Server key share for unknown group")
		}

		h.Params.UsingDH = true
		dhSecret, _ = keyAgreement(sks.Group, sks.KeyExchange, priv)
		logf(logTypeHandshake, "[client] got key share extension")
	}

	h.serverHello = shm

	err = h.Context.init(sh.CipherSuite, h.clientHello)
	if err != nil {
		return err
	}

	h.Context.updateWithServerHello(h.serverHello, dhSecret)
	return nil
}

func (h *clientHandshake) HandleServerFirstFlight(transcript []*handshakeMessage, finishedMessage *handshakeMessage) error {
	// Extract messages from sequence
	var err error
	var ee *encryptedExtensionsBody
	var cert *certificateBody
	var certVerify *certificateVerifyBody
	var certVerifyIndex int
	for i, msg := range transcript {
		switch msg.msgType {
		case HandshakeTypeEncryptedExtensions:
			ee = new(encryptedExtensionsBody)
			_, err = ee.Unmarshal(msg.body)
		case HandshakeTypeCertificate:
			cert = new(certificateBody)
			_, err = cert.Unmarshal(msg.body)
		case HandshakeTypeCertificateVerify:
			certVerifyIndex = i
			certVerify = new(certificateVerifyBody)
			_, err = certVerify.Unmarshal(msg.body)
		}

		if err != nil {
			return err
		}
	}

	// Read data from EncryptedExtensions
	serverALPN := ALPNExtension{}
	serverEarlyData := EarlyDataExtension{}

	gotALPN := ee.Extensions.Find(&serverALPN)
	h.Params.UsingEarlyData = ee.Extensions.Find(&serverEarlyData)

	if gotALPN && len(serverALPN.Protocols) > 0 {
		h.Params.NextProto = serverALPN.Protocols[0]
	}

	// Verify the server's certificate if we're not using a PSK for authentication
	if h.PSK == nil {

		if cert == nil || certVerify == nil {
			return fmt.Errorf("tls.client: No server auth data provided")
		}

		transcriptForCertVerify := []*handshakeMessage{h.clientHello, h.serverHello}
		transcriptForCertVerify = append(transcriptForCertVerify, transcript[:certVerifyIndex]...)
		logf(logTypeHandshake, "[client] Transcript for certVerify")
		for _, hm := range transcriptForCertVerify {
			logf(logTypeHandshake, "  [%d] %x", hm.msgType, hm.body)
		}
		logf(logTypeHandshake, "===")

		serverPublicKey := cert.certificateList[0].certData.PublicKey
		if err = certVerify.Verify(serverPublicKey, transcriptForCertVerify, h.Context); err != nil {
			return err
		}

		if h.AuthCertificate != nil {
			err = h.AuthCertificate(cert.certificateList)
			if err != nil {
				return err
			}
		}
	}

	h.Context.updateWithServerFirstFlight(transcript)

	// Verify server finished
	sfin := new(finishedBody)
	sfin.verifyDataLen = h.Context.serverFinished.verifyDataLen
	_, err = sfin.Unmarshal(finishedMessage.body)
	if err != nil {
		return err
	}
	if !bytes.Equal(sfin.verifyData, h.Context.serverFinished.verifyData) {
		return fmt.Errorf("tls.client: Server's Finished failed to verify")
	}

	return nil
}

///// Server-side handshake logic

type serverHandshake struct {
	Context cryptoContext
	Params  connectionParameters
}

func (h *serverHandshake) IsClient() bool {
	return true
}

func (h *serverHandshake) CryptoContext() *cryptoContext {
	return &h.Context
}

func (h serverHandshake) ConnectionParams() connectionParameters {
	return h.Params
}

func (h *serverHandshake) CreateKeyUpdate(requestUpdate KeyUpdateRequest) (*handshakeMessage, error) {
	return createKeyUpdate(false, &h.Context, requestUpdate)
}

func (h *serverHandshake) HandleKeyUpdate(hm *handshakeMessage) (*handshakeMessage, error) {
	return handleKeyUpdate(false, &h.Context, hm)
}

func (h *serverHandshake) HandleNewSessionTicket(hm *handshakeMessage) (PreSharedKey, error) {
	return PreSharedKey{}, fmt.Errorf("tls.server: Client sent NewSessionTicket")
}

func (h *serverHandshake) InboundKeys() (aeadFactory, keySet) {
	return h.Context.params.cipher, h.Context.clientTrafficKeys
}

func (h *serverHandshake) OutboundKeys() (aeadFactory, keySet) {
	return h.Context.params.cipher, h.Context.serverTrafficKeys
}

func (h *serverHandshake) HandleClientHello(chm *handshakeMessage, caps capabilities) (*handshakeMessage, []*handshakeMessage, error) {
	ch := &clientHelloBody{}
	_, err := ch.Unmarshal(chm.body)
	if err != nil {
		return nil, nil, err
	}

	supportedVersions := new(SupportedVersionsExtension)
	serverName := new(ServerNameExtension)
	supportedGroups := new(SupportedGroupsExtension)
	signatureAlgorithms := new(SignatureAlgorithmsExtension)
	clientKeyShares := &KeyShareExtension{HandshakeType: HandshakeTypeClientHello}
	clientPSK := &PreSharedKeyExtension{HandshakeType: HandshakeTypeClientHello}
	clientEarlyData := &EarlyDataExtension{}
	clientALPN := new(ALPNExtension)
	clientPSKModes := new(PSKKeyExchangeModesExtension)

	gotSupportedVersions := ch.extensions.Find(supportedVersions)
	gotServerName := ch.extensions.Find(serverName)
	gotSupportedGroups := ch.extensions.Find(supportedGroups)
	gotSignatureAlgorithms := ch.extensions.Find(signatureAlgorithms)
	gotEarlyData := ch.extensions.Find(clientEarlyData)
	ch.extensions.Find(clientKeyShares)
	ch.extensions.Find(clientPSK)
	ch.extensions.Find(clientALPN)
	ch.extensions.Find(clientPSKModes)

	if gotServerName {
		h.Params.ServerName = string(*serverName)
	}

	// If the client didn't send supportedVersions or doesn't support 1.3,
	// then we're done here.
	if !gotSupportedVersions {
		logf(logTypeHandshake, "[server] Client did not send supported_versions")
		return nil, nil, fmt.Errorf("tls.server: Client did not send supported_versions")
	}
	versionOK, _ := versionNegotiation(supportedVersions.Versions, []uint16{supportedVersion})
	if !versionOK {
		logf(logTypeHandshake, "[server] Client does not support the same version")
		return nil, nil, fmt.Errorf("tls.server: Client does not support the same version")
	}

	// Figure out if we can do DH
	canDoDH, dhGroup, dhPub, dhSecret := dhNegotiation(clientKeyShares.Shares, caps.Groups)

	// Figure out if we can do PSK
	canDoPSK := false
	var selectedPSK int
	var psk *PreSharedKey
	var ctx cryptoContext
	if len(clientPSK.Identities) > 0 {
		chTrunc, err := ch.Truncated()
		if err != nil {
			return nil, nil, err
		}
		canDoPSK, selectedPSK, psk, ctx, err = pskNegotiation(clientPSK.Identities, clientPSK.Binders, chTrunc, caps.PSKs)
		if err != nil {
			return nil, nil, err
		}
	}
	h.Context = ctx

	// Figure out if we actually should do DH / PSK
	h.Params.UsingDH, h.Params.UsingPSK = pskModeNegotiation(canDoDH, canDoPSK, clientPSKModes.KEModes)

	// If we've got no entropy to make keys from, fail
	if !h.Params.UsingDH && !h.Params.UsingPSK {
		logf(logTypeHandshake, "[server] Neither DH nor PSK negotiated")
		return nil, nil, fmt.Errorf("Neither DH nor PSK negotiated")
	}

	var cert *Certificate
	var certScheme SignatureScheme
	if !h.Params.UsingPSK {
		psk = nil
		h.Context = cryptoContext{}

		// If we're not using a PSK mode, then we need to have certain extensions
		if !gotServerName || !gotSupportedGroups || !gotSignatureAlgorithms {
			logf(logTypeHandshake, "[server] Insufficient extensions (%v %v %v)",
				gotServerName, gotSupportedGroups, gotSignatureAlgorithms)
			return nil, nil, fmt.Errorf("tls.server: Missing extension in ClientHello")
		}

		// Select a certificate
		cert, certScheme, err = certificateSelection(string(*serverName), signatureAlgorithms.Algorithms, caps.Certificates)
	}

	if !h.Params.UsingDH {
		dhSecret = nil
	}

	// Figure out if we're going to do early data
	h.Params.UsingEarlyData = earlyDataNegotiation(h.Params.UsingPSK, gotEarlyData, caps.AllowEarlyData)

	if h.Params.UsingEarlyData {
		h.Context.earlyUpdateWithClientHello(chm)
	}

	// Select a ciphersuite
	chosenSuite, err := cipherSuiteNegotiation(psk, ch.cipherSuites, caps.CipherSuites)
	if err != nil {
		return nil, nil, err
	}

	// Select a next protocol
	h.Params.NextProto, err = alpnNegotiation(psk, clientALPN.Protocols, caps.NextProtos)
	if err != nil {
		return nil, nil, err
	}

	// Create the ServerHello
	sh := &serverHelloBody{
		Version:     supportedVersion,
		CipherSuite: chosenSuite,
	}
	_, err = prng.Read(sh.Random[:])
	if err != nil {
		return nil, nil, err
	}
	if h.Params.UsingDH {
		logf(logTypeHandshake, "[server] sending DH extension")
		err = sh.Extensions.Add(&KeyShareExtension{
			HandshakeType: HandshakeTypeServerHello,
			Shares:        []KeyShareEntry{KeyShareEntry{Group: dhGroup, KeyExchange: dhPub}},
		})
		if err != nil {
			return nil, nil, err
		}
	}
	if h.Params.UsingPSK {
		logf(logTypeHandshake, "[server] sending PSK extension")
		err = sh.Extensions.Add(&PreSharedKeyExtension{
			HandshakeType:    HandshakeTypeServerHello,
			SelectedIdentity: uint16(selectedPSK),
		})
		if err != nil {
			return nil, nil, err
		}
	}
	logf(logTypeHandshake, "[server] Done creating ServerHello")

	shm, err := handshakeMessageFromBody(sh)
	if err != nil {
		return nil, nil, err
	}

	// Crank up the crypto context
	err = h.Context.init(sh.CipherSuite, chm)
	if err != nil {
		return nil, nil, err
	}

	err = h.Context.updateWithServerHello(shm, dhSecret)
	if err != nil {
		return nil, nil, err
	}

	// Send an EncryptedExtensions message (even if it's empty)
	eeList := ExtensionList{}
	if h.Params.NextProto != "" {
		logf(logTypeHandshake, "[server] sending ALPN extension")
		err = eeList.Add(&ALPNExtension{Protocols: []string{h.Params.NextProto}})
		if err != nil {
			return nil, nil, err
		}
	}
	if h.Params.UsingEarlyData {
		logf(logTypeHandshake, "[server] sending EDI extension")
		err = eeList.Add(&EarlyDataExtension{})
		if err != nil {
			return nil, nil, err
		}
	}
	ee := &encryptedExtensionsBody{eeList}
	eem, err := handshakeMessageFromBody(ee)
	if err != nil {
		return nil, nil, err
	}

	transcript := []*handshakeMessage{eem}

	// Authenticate with a certificate if required
	if !h.Params.UsingPSK {
		// Create and send Certificate, CertificateVerify
		certificate := &certificateBody{
			certificateList: make([]certificateEntry, len(cert.Chain)),
		}
		for i, entry := range cert.Chain {
			certificate.certificateList[i] = certificateEntry{certData: entry}
		}
		certm, err := handshakeMessageFromBody(certificate)
		if err != nil {
			return nil, nil, err
		}

		certificateVerify := &certificateVerifyBody{Algorithm: certScheme}
		logf(logTypeHandshake, "Creating CertVerify: %04x %v", certScheme, h.Context.params.hash)
		err = certificateVerify.Sign(cert.PrivateKey, []*handshakeMessage{chm, shm, eem, certm}, h.Context)
		if err != nil {
			return nil, nil, err
		}
		certvm, err := handshakeMessageFromBody(certificateVerify)
		if err != nil {
			return nil, nil, err
		}

		transcript = append(transcript, []*handshakeMessage{certm, certvm}...)
	}

	// Crank the crypto context
	err = h.Context.updateWithServerFirstFlight(transcript)
	if err != nil {
		return nil, nil, err
	}
	fm, err := handshakeMessageFromBody(h.Context.serverFinished)
	if err != nil {
		return nil, nil, err
	}

	transcript = append(transcript, fm)

	return shm, transcript, nil
}

func (h *serverHandshake) HandleClientSecondFlight(transcript []*handshakeMessage, finishedMessage *handshakeMessage) error {
	// XXX Currently, we don't process anything besides the Finished

	err := h.Context.updateWithClientSecondFlight(transcript)
	if err != nil {
		return err
	}

	// Read and verify client Finished
	cfin := new(finishedBody)
	cfin.verifyDataLen = h.Context.clientFinished.verifyDataLen
	_, err = cfin.Unmarshal(finishedMessage.body)
	if err != nil {
		return err
	}
	if !bytes.Equal(cfin.verifyData, h.Context.clientFinished.verifyData) {
		return fmt.Errorf("tls.server: Client's Finished failed to verify")
	}

	return nil
}

func (h *serverHandshake) CreateNewSessionTicket(length int, lifetime uint32) (PreSharedKey, *handshakeMessage, error) {
	// TODO: Check that we're in the right state for this

	tkt, err := newSessionTicket(length)
	if err != nil {
		return PreSharedKey{}, nil, err
	}

	tkt.TicketLifetime = lifetime

	err = tkt.Extensions.Add(&TicketEarlyDataInfoExtension{1 << 24})
	if err != nil {
		return PreSharedKey{}, nil, err
	}

	newPSK := PreSharedKey{
		CipherSuite:  h.Context.suite,
		IsResumption: true,
		Identity:     tkt.Ticket,
		Key:          h.Context.resumptionSecret,
	}

	tktm, err := handshakeMessageFromBody(tkt)
	return newPSK, tktm, err
}
