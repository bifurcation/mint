package mint

import (
	"bytes"
	"fmt"
)

type handshake struct {
	OfferedDH  map[namedGroup][]byte
	OfferedPSK PreSharedKey

	PSK     []byte
	Context cryptoContext

	AuthCertificate func(chain []certificateEntry) error

	clientHello *handshakeMessage
	serverHello *handshakeMessage
}

type capabilities struct {
	CipherSuites     []cipherSuite
	Groups           []namedGroup
	SignatureSchemes []signatureScheme
	PSKs             map[string]PreSharedKey
}

type connectionOptions struct {
	ServerName string
	NextProtos []string
	EarlyData  []byte
}

func (h *handshake) CreateClientHello(opts connectionOptions, caps capabilities) (*clientHelloBody, error) {
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
		// TODO: Just store the hash on the key
		keyParams, ok := cipherSuiteMap[key.CipherSuite]
		if !ok {
			return nil, fmt.Errorf("Unsupported ciphersuite from PSK")
		}

		compatibleSuites := []cipherSuite{}
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
		binder := h.Context.computeFinishedData(h.Context.binderKey, trunc)

		// Replace the PSK extension
		psk.binders[0].Binder = binder
		ch.extensions.Add(psk)

		// Compute the early traffic and exporter keys
		chm, err := handshakeMessageFromBody(ch)
		if err != nil {
			return nil, err
		}

		h.Context.earlyUpdateWithClientHello(chm)
	}

	h.clientHello, err = handshakeMessageFromBody(ch)
	if err != nil {
		return nil, err
	}

	return ch, nil
}

func (h *handshake) HandleServerHello(sh *serverHelloBody) error {
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

	var err error
	h.serverHello, err = handshakeMessageFromBody(sh)
	if err != nil {
		return err
	}

	h.Context.init(sh.CipherSuite, h.clientHello)
	h.Context.updateWithServerHello(h.serverHello, dhSecret)
	return nil
}

func (h *handshake) HandleServerFirstFlight(transcript []*handshakeMessage, finishedMessage *handshakeMessage) error {
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
