package mint

import (
	"bytes"
	"fmt"

	"github.com/bifurcation/mint/syntax"
)

// Assumptions:
//
//  * Certificate request context is never provided
//
//	* The only extension in CertificateRequest is signature_algorithms, which has the contents specified
//
//	* Only one certificate, selected from the provided array
//
//	* The following extensions are pre-negotiated:
//		* supported_versions
//		* supported_groups
//		* signature_algorithms
//
//	* Extensions are serialized in order by extension type
type ctlsCompression struct {
	SupportedVersion uint16
	SupportedGroup   NamedGroup
	SignatureScheme  SignatureScheme
	Certificates     []*Certificate
}

func replaceBody(hm *HandshakeMessage, body []byte) *HandshakeMessage {
	return &HandshakeMessage{
		msgType:  hm.msgType,
		seq:      hm.seq,
		body:     body,
		datagram: hm.datagram,
		offset:   0,
		length:   uint32(len(body)),
		cipher:   hm.cipher,
	}
}

func (c ctlsCompression) Compress(hmIn *HandshakeMessage) (*HandshakeMessage, error) {
	var bodyOut []byte
	switch hmIn.msgType {
	case HandshakeTypeClientHello:
		body, err := hmIn.ToBody()
		if err != nil {
			return nil, err
		}
		ch := body.(*ClientHelloBody)

		header := struct {
			Random       [32]byte
			CipherSuites []CipherSuite `tls:"head=2,min=2"`
		}{
			Random:       ch.Random,
			CipherSuites: make([]CipherSuite, len(ch.CipherSuites)),
		}
		copy(header.CipherSuites, ch.CipherSuites)

		headerBytes, err := syntax.Marshal(header)
		if err != nil {
			return nil, err
		}

		// Strip unnecessary extensions
		extStrip := []ExtensionType{
			ExtensionTypeSignatureAlgorithms,
			ExtensionTypeSupportedGroups,
			ExtensionTypeSupportedVersions,
		}
		for _, extType := range extStrip {
			err = ch.Extensions.Remove(extType)
			if err != nil {
				return nil, err
			}
		}

		// Marshal the extensions without their length octets
		extStr := struct {
			Extensions []Extension `tls:"head=none"`
		}{ch.Extensions}
		extBytes, err := syntax.Marshal(extStr)
		if err != nil {
			return nil, err
		}

		bodyOut = make([]byte, len(headerBytes))
		copy(bodyOut, headerBytes)
		bodyOut = append(bodyOut, extBytes...)

	case HandshakeTypeServerHello:
		body, err := hmIn.ToBody()
		if err != nil {
			return nil, err
		}
		sh := body.(*ServerHelloBody)

		header := struct {
			Random       [32]byte
			CipherSuites CipherSuite
		}{
			Random:       sh.Random,
			CipherSuites: sh.CipherSuite,
		}

		headerBytes, err := syntax.Marshal(header)
		if err != nil {
			return nil, err
		}

		// Strip any unnecessary extensions
		extStrip := []ExtensionType{
			ExtensionTypeSupportedVersions,
		}
		for _, extType := range extStrip {
			err = sh.Extensions.Remove(extType)
			if err != nil {
				return nil, err
			}
		}

		// Marshal the extensions without their length octets
		extStr := struct {
			Extensions []Extension `tls:"head=none"`
		}{sh.Extensions}
		extBytes, err := syntax.Marshal(extStr)
		if err != nil {
			return nil, err
		}

		bodyOut = make([]byte, len(headerBytes))
		copy(bodyOut, headerBytes)
		bodyOut = append(bodyOut, extBytes...)

	case HandshakeTypeEncryptedExtensions:
		// Omit the two length octets
		bodyOut = make([]byte, len(hmIn.body)-2)
		copy(bodyOut[0:], hmIn.body[2:])

	case HandshakeTypeCertificateRequest:
		// TODO(rlb@ipv.sx) Verify that message is compressible
		// * Context is empty
		// * Signature algorithms extension matches
		// * No other extensions
		bodyOut = []byte{}

	case HandshakeTypeCertificate:
		body, err := hmIn.ToBody()
		if err != nil {
			return nil, err
		}
		cert := body.(*CertificateBody)

		if len(cert.CertificateRequestContext) != 0 {
			return nil, fmt.Errorf("Certificate message with context cannot be compressed")
		}

		index := -1
		certData := cert.CertificateList[0].CertData.Raw
		for i, cert := range c.Certificates {
			if bytes.Equal(certData, cert.Chain[0].Raw) {
				index = i
				break
			}
		}
		if index == -1 {
			return nil, fmt.Errorf("Unrecognized certificate")
		}

		bodyOut, err = syntax.Marshal(uint32(index))
		if err != nil {
			return nil, err
		}

	case HandshakeTypeCertificateVerify:
		// Omit the two length octets
		// XXX: Could save another 2 bytes here by fixing algorithm
		bodyOut = make([]byte, len(hmIn.body)-2)
		copy(bodyOut[0:], hmIn.body[0:2])
		copy(bodyOut[2:], hmIn.body[4:])

	default:
		bodyOut = make([]byte, len(hmIn.body))
		copy(bodyOut, hmIn.body)
	}

	hmOut := replaceBody(hmIn, bodyOut)

	lenIn := len(hmIn.body)
	lenOut := len(hmOut.body)
	diff := lenIn - lenOut
	logf(logTypeCompression, "[+%02x] %d = %d - %d", hmIn.msgType, diff, lenIn, lenOut)
	if diff != 0 {
		logf(logTypeCompression, "[%x] ->> [%x]", hmIn.body, hmOut.body)
	}

	return hmOut, nil
}

func (c ctlsCompression) Decompress(hmIn *HandshakeMessage) (*HandshakeMessage, error) {
	var bodyOut []byte
	switch hmIn.msgType {
	case HandshakeTypeClientHello:
		logf(logTypeCompression, "ch: %x", hmIn.body)

		header := struct {
			Random       [32]byte
			CipherSuites []CipherSuite `tls:"head=2,min=2"`
		}{}
		read, err := syntax.Unmarshal(hmIn.body, &header)
		if err != nil {
			return nil, err
		}

		extLen := len(hmIn.body) - read
		extBytes := []byte{byte(extLen >> 8), byte(extLen)}
		extBytes = append(extBytes, hmIn.body[read:]...)
		extList := struct {
			Extensions ExtensionList `tls:"head=2"`
		}{}
		_, err = syntax.Unmarshal(extBytes, &extList)
		if err != nil {
			return nil, err
		}

		// Re-populate any stripped extensions
		sv := &SupportedVersionsExtension{HandshakeType: HandshakeTypeClientHello, Versions: []uint16{tls13Version}}
		sg := &SupportedGroupsExtension{Groups: []NamedGroup{c.SupportedGroup}}
		sa := &SignatureAlgorithmsExtension{Algorithms: []SignatureScheme{c.SignatureScheme}}
		for _, ext := range []ExtensionBody{sv, sg, sa} {
			err = extList.Extensions.Add(ext)
			if err != nil {
				return nil, err
			}
		}

		// Re-form the ClientHello body
		chOut := ClientHelloBody{
			LegacyVersion: tls12Version,
			Random:        header.Random,
			CipherSuites:  header.CipherSuites,
			Extensions:    extList.Extensions,
		}
		bodyOut, err = chOut.Marshal()
		if err != nil {
			return nil, err
		}

	case HandshakeTypeServerHello:
		header := struct {
			Random      [32]byte
			CipherSuite CipherSuite
		}{}
		read, err := syntax.Unmarshal(hmIn.body, &header)
		if err != nil {
			return nil, err
		}

		extLen := len(hmIn.body) - read
		extBytes := []byte{byte(extLen >> 8), byte(extLen)}
		extBytes = append(extBytes, hmIn.body[read:]...)
		extList := struct {
			Extensions ExtensionList `tls:"head=2"`
		}{}
		_, err = syntax.Unmarshal(extBytes, &extList)
		if err != nil {
			return nil, err
		}

		// Re-populate any stripped extensions
		sv := &SupportedVersionsExtension{HandshakeType: HandshakeTypeServerHello, Versions: []uint16{tls13Version}}
		for _, ext := range []ExtensionBody{sv} {
			err = extList.Extensions.Add(ext)
			if err != nil {
				return nil, err
			}
		}

		shOut := ServerHelloBody{
			Version:                 tls12Version,
			Random:                  header.Random,
			LegacySessionID:         []byte{},
			CipherSuite:             header.CipherSuite,
			LegacyCompressionMethod: 0,
			Extensions:              extList.Extensions,
		}
		bodyOut, err = shOut.Marshal()
		if err != nil {
			return nil, err
		}

	case HandshakeTypeEncryptedExtensions:
		// Re-add the two length octets
		bodyOut = make([]byte, len(hmIn.body)+2)
		extLen := len(hmIn.body)
		bodyOut = []byte{byte(extLen >> 8), byte(extLen)}
		bodyOut = append(bodyOut, hmIn.body...)

	case HandshakeTypeCertificateRequest:
		cr := CertificateRequestBody{}
		schemes := &SignatureAlgorithmsExtension{
			Algorithms: []SignatureScheme{c.SignatureScheme},
		}
		err := cr.Extensions.Add(schemes)
		if err != nil {
			return nil, err
		}

		bodyOut, err = syntax.Marshal(cr)
		if err != nil {
			return nil, err
		}

	case HandshakeTypeCertificate:
		var index32 uint32
		_, err := syntax.Unmarshal(hmIn.body, &index32)
		if err != nil {
			return nil, err
		}
		index := int(index32)

		if index > len(c.Certificates) {
			return nil, fmt.Errorf("Certificate index out of bounds")
		}

		chain := c.Certificates[index].Chain
		cert := CertificateBody{
			CertificateList: make([]CertificateEntry, len(chain)),
		}
		for i, entry := range chain {
			cert.CertificateList[i] = CertificateEntry{CertData: entry}
		}

		bodyOut, err = cert.Marshal()
		if err != nil {
			return nil, err
		}

	case HandshakeTypeCertificateVerify:
		// Re-add the two length octets
		bodyOut = make([]byte, len(hmIn.body)+2)
		sigLen := len(hmIn.body) - 2
		encSigLen := []byte{byte(sigLen >> 8), byte(sigLen)}

		copy(bodyOut[0:], hmIn.body[0:2])
		copy(bodyOut[2:], encSigLen)
		copy(bodyOut[4:], hmIn.body[2:])

	default:
		bodyOut = make([]byte, len(hmIn.body))
		copy(bodyOut, hmIn.body)
	}

	hmOut := replaceBody(hmIn, bodyOut)

	lenIn := len(hmIn.body)
	lenOut := len(bodyOut)
	diff := lenOut - lenIn
	logf(logTypeCompression, "[-%02x] %d = %d - %d", hmIn.msgType, diff, lenOut, lenIn)
	if diff != 0 {
		//logf(logTypeCompression, "[%x] -<< [%x]", hmIn.body, hmOut.body)
	}

	return hmOut, nil
}
