package mint

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
)

type capabilities struct {
	// For both client and server
	CipherSuites     []CipherSuite
	Groups           []namedGroup
	SignatureSchemes []signatureScheme
	PSKs             map[string]PreSharedKey

	// For server
	NextProtos   []string
	Certificates []*Certificate
}

type connectionOptions struct {
	ServerName string
	NextProtos []string
	EarlyData  []byte
}

///// Client-side Handshake methods

type clientHandshake struct {
	OfferedDH  map[namedGroup][]byte
	OfferedPSK PreSharedKey

	PSK     []byte
	Context cryptoContext

	AuthCertificate func(chain []certificateEntry) error

	clientHello *handshakeMessage
	serverHello *handshakeMessage
}

func (h *clientHandshake) CreateClientHello(opts connectionOptions, caps capabilities) (*handshakeMessage, error) {
	// key_shares
	h.OfferedDH = map[namedGroup][]byte{}
	ks := keyShareExtension{
		handshakeType: handshakeTypeClientHello,
		shares:        make([]keyShareEntry, len(caps.Groups)),
	}
	for i, group := range caps.Groups {
		pub, priv, err := newKeyShare(group)
		if err != nil {
			return nil, err
		}

		ks.shares[i].Group = group
		ks.shares[i].KeyExchange = pub
		h.OfferedDH[group] = priv
	}

	// supported_versions, supported_groups, signature_algorithms, server_name
	sv := supportedVersionsExtension{Versions: []uint16{supportedVersion}}
	sni := serverNameExtension(opts.ServerName)
	sg := supportedGroupsExtension{Groups: caps.Groups}
	sa := signatureAlgorithmsExtension{Algorithms: caps.SignatureSchemes}

	// Application Layer Protocol Negotiation
	var alpn *alpnExtension
	if (opts.NextProtos != nil) && (len(opts.NextProtos) > 0) {
		alpn = &alpnExtension{protocols: opts.NextProtos}
	}

	// Construct base ClientHello
	ch := &clientHelloBody{
		cipherSuites: caps.CipherSuites,
	}
	_, err := prng.Read(ch.random[:])
	if err != nil {
		return nil, err
	}
	for _, ext := range []extensionBody{&sv, &sni, &ks, &sg, &sa} {
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
	var psk *preSharedKeyExtension
	var ed *earlyDataExtension
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
			ed = &earlyDataExtension{}
			ch.extensions.Add(ed)
		}

		// Add the shim PSK extension to the ClientHello
		psk = &preSharedKeyExtension{
			handshakeType: handshakeTypeClientHello,
			identities: []pskIdentity{
				pskIdentity{Identity: key.Identity},
			},
			binders: []pskBinderEntry{
				// Note: Stub to get the length fields right
				pskBinderEntry{Binder: bytes.Repeat([]byte{0x00}, keyParams.hash.Size())},
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
		psk.binders[0].Binder = binder
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
	serverPSK := preSharedKeyExtension{handshakeType: handshakeTypeServerHello}
	foundPSK := sh.Extensions.Find(&serverPSK)
	serverKeyShare := keyShareExtension{handshakeType: handshakeTypeServerHello}
	foundKeyShare := sh.Extensions.Find(&serverKeyShare)

	if foundPSK && (serverPSK.selectedIdentity == 0) {
		h.PSK = h.OfferedPSK.Key
		logf(logTypeHandshake, "[client] got PSK extension")
	}

	var dhSecret []byte
	if foundKeyShare {
		sks := serverKeyShare.shares[0]
		priv, ok := h.OfferedDH[sks.Group]
		if !ok {
			return fmt.Errorf("Server key share for unknown group")
		}

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
	// Verify the server's certificate if we're not using a PSK for authentication
	var err error
	if h.PSK == nil {
		var cert *certificateBody
		var certVerify *certificateVerifyBody
		var certVerifyIndex int
		for i, msg := range transcript {
			switch msg.msgType {
			case handshakeTypeCertificate:
				cert = new(certificateBody)
				_, err = cert.Unmarshal(msg.body)
			case handshakeTypeCertificateVerify:
				certVerifyIndex = i
				certVerify = new(certificateVerifyBody)
				_, err = certVerify.Unmarshal(msg.body)
			}

			if err != nil {
				return err
			}
		}

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
}

func (h *serverHandshake) HandleClientHello(chm *handshakeMessage, caps capabilities) (*handshakeMessage, []*handshakeMessage, bool, error) {
	ch := &clientHelloBody{}
	_, err := ch.Unmarshal(chm.body)
	if err != nil {
		return nil, nil, false, err
	}

	supportedVersions := new(supportedVersionsExtension)
	serverName := new(serverNameExtension)
	supportedGroups := new(supportedGroupsExtension)
	signatureAlgorithms := new(signatureAlgorithmsExtension)
	clientKeyShares := &keyShareExtension{handshakeType: handshakeTypeClientHello}
	clientPSK := &preSharedKeyExtension{handshakeType: handshakeTypeClientHello}
	clientEarlyData := &earlyDataExtension{}
	clientALPN := new(alpnExtension)

	gotSupportedVersions := ch.extensions.Find(supportedVersions)
	gotServerName := ch.extensions.Find(serverName)
	gotSupportedGroups := ch.extensions.Find(supportedGroups)
	gotSignatureAlgorithms := ch.extensions.Find(signatureAlgorithms)
	gotKeyShares := ch.extensions.Find(clientKeyShares)
	gotPSK := ch.extensions.Find(clientPSK)
	gotEarlyData := ch.extensions.Find(clientEarlyData)
	gotALPN := ch.extensions.Find(clientALPN)

	// TODO: Factor out these negotiation blocks into functions that can get tested individually
	// TODO: Maybe make a "session parameters" struct that we can store alongside PSKs

	// If the client didn't send supportedVersions or doesn't support 1.3,
	// then we're done here.
	if !gotSupportedVersions {
		logf(logTypeHandshake, "[server] Client did not send supported_versions")
		return nil, nil, false, fmt.Errorf("tls.server: Client did not send supported_versions")
	}
	clientSupportsSameVersion := false
	for _, version := range supportedVersions.Versions {
		logf(logTypeHandshake, "[server] version offered by client [%04x] <> [%04x]", version, supportedVersion)
		clientSupportsSameVersion = (version == supportedVersion)
		if clientSupportsSameVersion {
			break
		}
	}
	if !clientSupportsSameVersion {
		logf(logTypeHandshake, "[server] Client does not support the same version")
		return nil, nil, false, fmt.Errorf("tls.server: Client does not support the same version")
	}

	// Find the ALPN extension and select a protocol
	var serverALPN *alpnExtension
	if gotALPN {
		logf(logTypeHandshake, "[server] Got ALPN offer: %v", clientALPN.protocols)
		for _, proto := range clientALPN.protocols {
			for _, serverProto := range caps.NextProtos {
				if proto != serverProto {
					continue
				}

				logf(logTypeHandshake, "[server] Sending ALPN value %v", proto)
				serverALPN = &alpnExtension{protocols: []string{proto}}
				break
			}

			if serverALPN != nil {
				break
			}
		}
	}

	// Find pre_shared_key extension and look it up
	var serverPSK *preSharedKeyExtension
	var pskSuite CipherSuite
	usingPSK := false
	if gotPSK {
		logf(logTypeHandshake, "[server] Got PSK extension; processing")
		for _, id := range clientPSK.identities {
			logf(logTypeHandshake, "[server] Client provided PSK identity %x", id)
		}

		for i, id := range clientPSK.identities {
			for _, key := range caps.PSKs {
				if !bytes.Equal(id.Identity, key.Identity) {
					continue
				}

				// Verify the binder
				h.Context.preInit(key)
				trunc, err := ch.Truncated()
				if err != nil {
					return nil, nil, false, err
				}

				truncHash := h.Context.params.hash.New()
				truncHash.Write(trunc)

				binder := h.Context.computeFinishedData(h.Context.binderKey, truncHash.Sum(nil))
				if !bytes.Equal(binder, clientPSK.binders[i].Binder) {
					logf(logTypeHandshake, "Binder check failed identity %x", key.Identity)
					return nil, nil, false, fmt.Errorf("PSK binder check failed")
				}

				logf(logTypeHandshake, "Using PSK identity %x", key.Identity)
				usingPSK = true
				pskSuite = key.CipherSuite

				serverPSK = &preSharedKeyExtension{
					handshakeType:    handshakeTypeServerHello,
					selectedIdentity: uint16(i),
				}

				// If we're going to need to receive early data, prepare the relevant keys
				if gotEarlyData {
					h.Context.earlyUpdateWithClientHello(chm)
				}

				break
			}

			if usingPSK {
				break
			}
		}
	}

	// If we're not using a PSK mode, then we need to have certain extensions
	if usingPSK && (!gotServerName || !gotSupportedGroups || !gotSignatureAlgorithms) {
		logf(logTypeHandshake, "[server] Insufficient extensions (%v %v %v %v)",
			gotServerName, gotSupportedGroups, gotSignatureAlgorithms, gotKeyShares)
		return nil, nil, false, fmt.Errorf("tls.server: Missing extension in ClientHello")
	}

	// If we're not using a PSK mode, then we can't do early data
	if !usingPSK && gotEarlyData {
		return nil, nil, false, fmt.Errorf("tls.server: EarlyData with no PSK")
	}

	// Find key_share extension and do key agreement
	var serverKeyShare *keyShareExtension
	var dhSecret []byte
	if gotKeyShares {
		logf(logTypeHandshake, "[server] Got KeyShare extension; processing")
		for _, share := range clientKeyShares.shares {
			for _, group := range caps.Groups {
				if group != share.Group {
					continue
				}

				pub, priv, err := newKeyShare(share.Group)
				if err != nil {
					return nil, nil, false, err
				}

				dhSecret, err = keyAgreement(share.Group, share.KeyExchange, priv)
				serverKeyShare = &keyShareExtension{
					handshakeType: handshakeTypeServerHello,
					shares:        []keyShareEntry{keyShareEntry{Group: share.Group, KeyExchange: pub}},
				}
				if err != nil {
					return nil, nil, false, err
				}
				break
			}

			if dhSecret != nil {
				break
			}
		}
	}

	// Pick a ciphersuite.  If we're using a PSK, we just need to verify that the
	// preset suite is offered
	var chosenSuite CipherSuite
	foundCipherSuite := false
	for _, suite := range ch.cipherSuites {
		if usingPSK && (suite == pskSuite) {
			chosenSuite = suite
			foundCipherSuite = true
			break
		} else if usingPSK {
			continue
		}

		for _, serverSuite := range caps.CipherSuites {
			if suite == serverSuite {
				chosenSuite = suite
				foundCipherSuite = true
				break
			}
		}

		if foundCipherSuite {
			break
		}
	}

	logf(logTypeCrypto, "Supported Client suites [%v]", ch.cipherSuites)
	if !foundCipherSuite {
		logf(logTypeHandshake, "No acceptable ciphersuites")
		return nil, nil, false, fmt.Errorf("tls.server: No acceptable ciphersuites")
	}
	logf(logTypeHandshake, "[server] Chose CipherSuite %x", chosenSuite)

	// Create the ServerHello
	sh := &serverHelloBody{
		Version:     supportedVersion,
		CipherSuite: chosenSuite,
	}
	_, err = prng.Read(sh.Random[:])
	if err != nil {
		return nil, nil, false, err
	}
	if dhSecret != nil {
		logf(logTypeHandshake, "[server] sending key share extension")
		err = sh.Extensions.Add(serverKeyShare)
		if err != nil {
			return nil, nil, false, err
		}
	} else {
		logf(logTypeHandshake, "[server] not sending key share extension; deleting DH secret")
		dhSecret = nil
	}
	if usingPSK {
		logf(logTypeHandshake, "[server] sending PSK extension")
		err = sh.Extensions.Add(serverPSK)
		if err != nil {
			return nil, nil, false, err
		}
	}
	logf(logTypeHandshake, "[server] Done creating ServerHello")

	shm, err := handshakeMessageFromBody(sh)
	if err != nil {
		return nil, nil, false, err
	}

	// Crank up the crypto context
	err = h.Context.init(sh.CipherSuite, chm)
	if err != nil {
		return nil, nil, false, err
	}

	err = h.Context.updateWithServerHello(shm, dhSecret)
	if err != nil {
		return nil, nil, false, err
	}

	// Send an EncryptedExtensions message (even if it's empty)
	eeList := extensionList{}
	if serverALPN != nil {
		logf(logTypeHandshake, "[server] sending ALPN extension")
		err = eeList.Add(serverALPN)
		if err != nil {
			return nil, nil, false, err
		}
	}
	if usingPSK && gotEarlyData {
		logf(logTypeHandshake, "[server] sending EDI extension")
		err = eeList.Add(&earlyDataExtension{})
		if err != nil {
			return nil, nil, false, err
		}
	}
	ee := &encryptedExtensionsBody{eeList}
	eem, err := handshakeMessageFromBody(ee)
	if err != nil {
		return nil, nil, false, err
	}

	transcript := []*handshakeMessage{eem}

	// Authenticate with a certificate if required
	if !usingPSK {
		// Select a certificate
		var privateKey crypto.Signer
		var chain []*x509.Certificate
		foundCert := false
		for _, cert := range caps.Certificates {
			for _, name := range cert.Chain[0].DNSNames {
				if name == string(*serverName) {
					foundCert = true
					chain = cert.Chain
					privateKey = cert.PrivateKey
				}
			}
		}

		// If there's no match, take the first certificate provided
		if !foundCert && len(caps.Certificates) > 0 {
			chain = caps.Certificates[0].Chain
			privateKey = caps.Certificates[0].PrivateKey
		} else if len(caps.Certificates) == 0 {
			return nil, nil, false, fmt.Errorf("No certificate available for the requested name [%s]", *serverName)
		}

		// Select a signature scheme from among those offered by the client
		var sigAlg signatureScheme
		foundSigAlg := false
		for _, alg := range signatureAlgorithms.Algorithms {

			valid := schemeValidForKey(alg, privateKey)
			if !valid {
				continue
			}

			enabled := false
			for _, scheme := range caps.SignatureSchemes {
				if alg == scheme {
					enabled = true
					break
				}
			}
			if !enabled {
				continue
			}

			sigAlg = alg
			foundSigAlg = true
			break
		}
		if !foundSigAlg {
			return nil, nil, false, fmt.Errorf("No signature schemes available for this client and certificate")
		}
		logf(logTypeHandshake, "Computing CertificateVerify with scheme %04x", sigAlg)

		// If there's no name match, use the first in the list or fail
		if chain == nil {
			if len(caps.Certificates) > 0 {
				chain = caps.Certificates[0].Chain
				privateKey = caps.Certificates[0].PrivateKey
			} else {
				return nil, nil, false, fmt.Errorf("No certificate found for %s", string(*serverName))
			}
		}

		// Create and send Certificate, CertificateVerify
		// TODO Certificate selection based on ClientHello
		certificate := &certificateBody{
			certificateList: make([]certificateEntry, len(chain)),
		}
		for i, cert := range chain {
			certificate.certificateList[i] = certificateEntry{certData: cert}
		}
		certm, err := handshakeMessageFromBody(certificate)
		if err != nil {
			return nil, nil, false, err
		}

		certificateVerify := &certificateVerifyBody{Algorithm: sigAlg}
		logf(logTypeHandshake, "%04x %v", sigAlg, h.Context.params.hash)
		err = certificateVerify.Sign(privateKey, []*handshakeMessage{chm, shm, eem, certm}, h.Context)
		if err != nil {
			return nil, nil, false, err
		}
		certvm, err := handshakeMessageFromBody(certificateVerify)
		if err != nil {
			return nil, nil, false, err
		}

		transcript = append(transcript, []*handshakeMessage{certm, certvm}...)
	}

	// Crank the crypto context
	err = h.Context.updateWithServerFirstFlight(transcript)
	if err != nil {
		return nil, nil, false, err
	}
	fm, err := handshakeMessageFromBody(h.Context.serverFinished)
	if err != nil {
		return nil, nil, false, err
	}

	transcript = append(transcript, fm)

	return shm, transcript, gotEarlyData, nil
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

	err = tkt.Extensions.Add(&ticketEarlyDataInfoExtension{1 << 24})
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
