package mint

import (
	"github.com/bifurcation/mint/syntax"
)

type ctlsCompression struct{}

// Lossless compression
// * ClientHello						7		Legacy fields; extension length
// * ServerHello						6		Legacy fields; extension length
// * EncryptedExtensions		2		Unnecessary length
// * CertificateRequest			2		Unnecessary length
// * Certificate						3		Unnecessary length
// * CertificateVerify			2		Unnecessary length
// * Finished								0
//
// M1:  7
// M2: 15 = 6 + 2 + 2 + 3 + 2 + 0
// M3:  5 = 3 + 2 + 0

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
		context := struct {
			Value []byte `tls:"head=1"`
		}{}
		read, err := syntax.Unmarshal(hmIn.body, &context)
		if err != nil {
			return nil, err
		}

		bodyOut = make([]byte, read)
		copy(bodyOut, hmIn.body[:read])
		bodyOut = append(bodyOut, hmIn.body[read+2:]...)

	case HandshakeTypeCertificate:
		context := struct {
			Value []byte `tls:"head=1"`
		}{}
		read, err := syntax.Unmarshal(hmIn.body, &context)
		if err != nil {
			return nil, err
		}

		bodyOut = make([]byte, read)
		copy(bodyOut, hmIn.body[:read])
		bodyOut = append(bodyOut, hmIn.body[read+3:]...)

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
		//logf(logTypeCompression, "[%x] ->> [%x]", hmIn.body, hmOut.body)
	}

	return hmOut, nil
}

func (c ctlsCompression) Decompress(hmIn *HandshakeMessage) (*HandshakeMessage, error) {
	var bodyOut []byte
	switch hmIn.msgType {
	case HandshakeTypeClientHello:
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
			Extensions []Extension `tls:"head=2"`
		}{}
		_, err = syntax.Unmarshal(extBytes, &extList)
		if err != nil {
			return nil, err
		}

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
			Extensions []Extension `tls:"head=2"`
		}{}
		_, err = syntax.Unmarshal(extBytes, &extList)
		if err != nil {
			return nil, err
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
		context := struct {
			Value []byte `tls:"head=1"`
		}{}
		read, err := syntax.Unmarshal(hmIn.body, &context)
		if err != nil {
			return nil, err
		}

		extLen := len(hmIn.body) - read
		extBytes := []byte{byte(extLen >> 8), byte(extLen)}

		bodyOut = make([]byte, read)
		copy(bodyOut, hmIn.body[:read])
		bodyOut = append(bodyOut, extBytes...)
		bodyOut = append(bodyOut, hmIn.body[read:]...)

	case HandshakeTypeCertificate:
		context := struct {
			Value []byte `tls:"head=1"`
		}{}
		read, err := syntax.Unmarshal(hmIn.body, &context)
		if err != nil {
			return nil, err
		}

		extLen := len(hmIn.body) - read
		extBytes := []byte{byte(extLen >> 16), byte(extLen >> 8), byte(extLen)}

		bodyOut = make([]byte, read)
		copy(bodyOut, hmIn.body[:read])
		bodyOut = append(bodyOut, extBytes...)
		bodyOut = append(bodyOut, hmIn.body[read:]...)

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
