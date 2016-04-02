package mint

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

const (
	fixedClientHelloBodyLen  = 39
	fixedServerHelloBodyLen  = 36
	maxCipherSuites          = 1 << 15
	extensionHeaderLen       = 4
	maxExtensionDataLen      = (1 << 16) - 1
	maxExtensionsLen         = (1 << 16) - 1
	maxCertRequestContextLen = 255
	maxTicketLen             = (1 << 16) - 1
)

type handshakeMessageBody interface {
	Type() handshakeType
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (int, error)
}

// struct {
//     ProtocolVersion client_version = { 3, 4 };    /* TLS v1.3 */
//     Random random;
//     opaque legacy_session_id<0..32>;              /* MUST be [] */
//     CipherSuite cipher_suites<2..2^16-2>;
//     opaque legacy_compression_methods<1..2^8-1>;  /* MUST be [0] */
//     Extension extensions<0..2^16-1>;
// } ClientHello;
type clientHelloBody struct {
	// Omitted: clientVersion
	// Omitted: legacySessionID
	// Omitted: legacyCompressionMethods
	random       [32]byte
	cipherSuites []cipherSuite
	extensions   extensionList
}

func (ch clientHelloBody) Type() handshakeType {
	return handshakeTypeClientHello
}

func (ch clientHelloBody) Marshal() ([]byte, error) {
	baseBodyLen := fixedClientHelloBodyLen + 2*len(ch.cipherSuites)
	body := make([]byte, baseBodyLen)
	for i := range body {
		body[i] = 0
	}

	// Write base fields that are non-zero
	body[0] = 0x03
	body[1] = 0x04
	copy(body[2:34], ch.random[:])

	if len(ch.cipherSuites) == 0 {
		return nil, fmt.Errorf("tls.clienthello: No ciphersuites provided")
	}
	if len(ch.cipherSuites) > maxCipherSuites {
		return nil, fmt.Errorf("tls.clienthello: Too many ciphersuites")
	}
	cipherSuitesLen := 2 * len(ch.cipherSuites)
	body[35] = byte(cipherSuitesLen >> 8)
	body[36] = byte(cipherSuitesLen)
	for i, suite := range ch.cipherSuites {
		body[2*i+37] = byte(suite >> 8)
		body[2*i+38] = byte(suite)
	}
	body[37+cipherSuitesLen] = 0x01

	extensions, err := ch.extensions.Marshal()
	if err != nil {
		return nil, err
	}

	return append(body, extensions...), nil
}

func (ch *clientHelloBody) Unmarshal(data []byte) (int, error) {
	if len(data) < fixedClientHelloBodyLen {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; too short")
	}

	if data[0] != 0x03 || data[1] != 0x04 {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; unsupported version %02x%02x", data[0], data[1])
	}

	copy(ch.random[:], data[2:34])

	// Since we only do 1.3, we can enforce that the session ID MUST be empty
	if data[34] != 0x00 {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; non-empty session ID")
	}

	cipherSuitesLen := (int(data[35]) << 8) + int(data[36])
	if len(data) < 37+cipherSuitesLen {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; too many ciphersuites")
	}
	if cipherSuitesLen%2 != 0 {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; odd ciphersuites size")
	}
	ch.cipherSuites = make([]cipherSuite, cipherSuitesLen/2)
	for i := 0; i < cipherSuitesLen/2; i++ {
		ch.cipherSuites[i] = (cipherSuite(data[2*i+37]) << 8) + cipherSuite(data[2*i+38])
	}

	// Since we only do 1.3, we can enforce that the compression methods
	if len(data) < 37+cipherSuitesLen+2 {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; no compression methods")
	}
	if data[37+cipherSuitesLen] != 0x01 || data[37+cipherSuitesLen+1] != 0x00 {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; incorrect compression methods")
	}

	extLen, err := ch.extensions.Unmarshal(data[37+cipherSuitesLen+2:])
	if err != nil {
		return 0, err
	}

	return 37 + cipherSuitesLen + 2 + extLen, nil
}

// struct {
//     ProtocolVersion server_version;
//     Random random;
//     CipherSuite cipher_suite;
//     select (extensions_present) {
//         case false:
//             struct {};
//         case true:
//             Extension extensions<0..2^16-1>;
//     };
// } ServerHello;
type serverHelloBody struct {
	// Omitted: server_version
	random      [32]byte
	cipherSuite cipherSuite
	extensions  extensionList
}

func (sh serverHelloBody) Type() handshakeType {
	return handshakeTypeServerHello
}

func (sh serverHelloBody) Marshal() ([]byte, error) {
	body := make([]byte, fixedServerHelloBodyLen)

	body[0] = 0x03
	body[1] = 0x04

	copy(body[2:34], sh.random[:])

	body[34] = byte(sh.cipherSuite >> 8)
	body[35] = byte(sh.cipherSuite)

	if len(sh.extensions) > 0 {
		extensions, err := sh.extensions.Marshal()
		if err != nil {
			return nil, err
		}
		body = append(body, extensions...)
	}

	return body, nil
}

func (sh *serverHelloBody) Unmarshal(data []byte) (int, error) {
	if len(data) < fixedServerHelloBodyLen {
		return 0, fmt.Errorf("tls.serverhello: Malformed ServerHello; too short")
	}

	if data[0] != 0x03 || data[1] != 0x04 {
		return 0, fmt.Errorf("tls.serverhello: Malformed ServerHello; unsupported version %02x%02x", data[0], data[1])
	}

	copy(sh.random[:], data[2:34])
	sh.cipherSuite = (cipherSuite(data[34]) << 8) + cipherSuite(data[35])

	read := fixedServerHelloBodyLen
	if len(data) > fixedServerHelloBodyLen {
		extLen, err := sh.extensions.Unmarshal(data[fixedServerHelloBodyLen:])
		if err != nil {
			return 0, err
		}

		read += extLen
	} else {
		sh.extensions = extensionList{}
	}

	return read, nil
}

// struct {
//     opaque verify_data[verify_data_length];
// } Finished;
//
// verifyDataLen is not a field in the TLS struct, but we add it here so
// that calling code can tell us how much data to expect when we marshal /
// unmarshal.  (We could add this to the marshal/unmarshal methods, but let's
// try to keep the signature consistent for now.)
type finishedBody struct {
	verifyDataLen int
	verifyData    []byte
}

func (fin finishedBody) Type() handshakeType {
	return handshakeTypeFinished
}

func (fin finishedBody) Marshal() ([]byte, error) {
	if len(fin.verifyData) != fin.verifyDataLen {
		return nil, fmt.Errorf("tls.finished: data length mismatch")
	}

	body := make([]byte, len(fin.verifyData))
	copy(body, fin.verifyData)
	return body, nil
}

func (fin *finishedBody) Unmarshal(data []byte) (int, error) {
	if len(data) < fin.verifyDataLen {
		return 0, fmt.Errorf("tls.finished: Malformed finished; too short")
	}

	fin.verifyData = make([]byte, fin.verifyDataLen)
	copy(fin.verifyData, data[:fin.verifyDataLen])
	return fin.verifyDataLen, nil
}

// struct {
//     Extension extensions<0..2^16-1>;
// } EncryptedExtensions;
//
// Marshal() and Unmarshal() are handled by extensionList
type encryptedExtensionsBody extensionList

func (ee encryptedExtensionsBody) Type() handshakeType {
	return handshakeTypeEncryptedExtensions
}

func (ee encryptedExtensionsBody) Marshal() ([]byte, error) {
	if allowEmptyEncryptedExtensions && len(ee) == 0 {
		return []byte{}, nil
	}

	return extensionList(ee).Marshal()
}

func (ee *encryptedExtensionsBody) Unmarshal(data []byte) (int, error) {
	var el extensionList

	if allowEmptyEncryptedExtensions && len(data) == 0 {
		*ee = encryptedExtensionsBody(el)
		return 0, nil
	}

	read, err := el.Unmarshal(data)
	if err == nil {
		*ee = encryptedExtensionsBody(el)
	}
	return read, err
}

// opaque ASN1Cert<1..2^24-1>;
//
// struct {
//     opaque certificate_request_context<0..255>;
//     ASN1Cert certificate_list<0..2^24-1>;
// } Certificate;
type certificateBody struct {
	certificateRequestContext []byte
	certificateList           []*x509.Certificate
}

func (c certificateBody) Type() handshakeType {
	return handshakeTypeCertificate
}

func (c certificateBody) Marshal() ([]byte, error) {
	if len(c.certificateRequestContext) > maxCertRequestContextLen {
		return nil, fmt.Errorf("tls.certificate: Request context too long")
	}

	contextLen := len(c.certificateRequestContext)
	certsLen := 0
	for _, cert := range c.certificateList {
		if cert == nil || len(cert.Raw) == 0 {
			return nil, fmt.Errorf("tls:certificate: Unmarshaled certificate")
		}
		certsLen += 3 + len(cert.Raw)
	}

	data := make([]byte, 1+contextLen+3+certsLen)
	data[0] = byte(contextLen)
	copy(data[1:1+contextLen], c.certificateRequestContext)
	start := 1 + contextLen
	data[start] = byte(certsLen >> 16)
	data[start+1] = byte(certsLen >> 8)
	data[start+2] = byte(certsLen)
	start += 3
	for _, cert := range c.certificateList {
		certLen := len(cert.Raw)
		data[start] = byte(certLen >> 16)
		data[start+1] = byte(certLen >> 8)
		data[start+2] = byte(certLen)
		copy(data[start+3:], cert.Raw)
		start += 3 + len(cert.Raw)
	}
	return data, nil
}

func (c *certificateBody) Unmarshal(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("tls:certificate: Message too short for context length")
	}

	contextLen := int(data[0])
	if len(data) < 1+contextLen+3 {
		return 0, fmt.Errorf("tls:certificate: Message too short for context")
	}
	c.certificateRequestContext = make([]byte, contextLen)
	copy(c.certificateRequestContext, data[1:1+contextLen])

	certsLen := (int(data[1+contextLen]) << 16) + (int(data[1+contextLen+1]) << 8) + int(data[1+contextLen+2])
	if len(data) < 1+contextLen+3+certsLen {
		return 0, fmt.Errorf("tls:certificate: Message too short for certificates")
	}

	start := 1 + contextLen + 3
	end := 1 + contextLen + 3 + certsLen
	c.certificateList = []*x509.Certificate{}
	for start < end {
		if len(data[start:]) < 3 {
			return 0, fmt.Errorf("tls:certificate: Message too short for certificate length")
		}

		certLen := (int(data[start]) << 16) + (int(data[start+1]) << 8) + int(data[start+2])
		if len(data[start+3:]) < certLen {
			return 0, fmt.Errorf("tls:certificate: Message too short for certificate")
		}

		cert, err := x509.ParseCertificate(data[start+3 : start+3+certLen])
		if err != nil {
			return 0, fmt.Errorf("tls:certificate: Certificate failed to parse: %v", err)
		}

		c.certificateList = append(c.certificateList, cert)
		start += 3 + certLen
	}
	return start, nil
}

// CertificateVerify
//
// enum {... (255)} HashAlgorithm
// enum {... (255)} SignatureAlgorithm
//
// struct {
//     HashAlgorithm hash;
//     SignatureAlgorithm signature;
// } SignatureAndHashAlgorithm;
//
// struct {
//    SignatureAndHashAlgorithm algorithm;
//    opaque signature<0..2^16-1>;
// } DigitallySigned;
//
// struct {
//      digitally-signed struct {
//         opaque hashed_data[hash_length];
//      };
// } CertificateVerify;
type certificateVerifyBody struct {
	alg       signatureAndHashAlgorithm
	signature []byte
}

func (cv certificateVerifyBody) Type() handshakeType {
	return handshakeTypeCertificateVerify
}

func (cv certificateVerifyBody) Marshal() ([]byte, error) {
	sigLen := len(cv.signature)
	data := make([]byte, 2+2+sigLen)

	data[0] = byte(cv.alg.hash)
	data[1] = byte(cv.alg.signature)
	data[2] = byte(sigLen >> 8)
	data[3] = byte(sigLen)
	copy(data[4:], cv.signature)

	return data, nil
}

func (cv *certificateVerifyBody) Unmarshal(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("tls:certificateverify: Message too short for header")
	}

	sigLen := (int(data[2]) << 8) + int(data[3])
	if len(data) < 4+sigLen {
		return 0, fmt.Errorf("tls:certificateverify: Message too short for signature")
	}

	cv.alg.hash = hashAlgorithm(data[0])
	cv.alg.signature = signatureAlgorithm(data[1])
	cv.signature = make([]byte, sigLen)
	copy(cv.signature, data[4:])

	return 4 + sigLen, nil
}

func (cv *certificateVerifyBody) computeContext(transcript []*handshakeMessage) (hash crypto.Hash, hashed []byte, err error) {
	handshakeContext := []byte{}
	for _, msg := range transcript {
		if msg == nil {
			err = fmt.Errorf("tls.certverify: Nil message")
			return
		}
		data := msg.Marshal()
		logf(logTypeHandshake, "Added Message to Handshake Context to be verified: [%d] %x", len(data), data)
		handshakeContext = append(handshakeContext, data...)
	}

	hash, ok := hashMap[cv.alg.hash]
	if !ok {
		err = fmt.Errorf("tls.certverify: Unsupported hash algorithm")
		return
	}
	h := hash.New()
	h.Write(handshakeContext)

	logf(logTypeHandshake, "Handshake Context to be verified: [%d] %x", len(handshakeContext), handshakeContext)
	hashed = h.Sum(nil)
	logf(logTypeHandshake, "Handshake Hash to be verified: [%d] %x", len(hashed), hashed)
	return
}

func (cv *certificateVerifyBody) Sign(privateKey crypto.Signer, transcript []*handshakeMessage) error {
	hash, hashedData, err := cv.computeContext(transcript)
	if err != nil {
		return err
	}

	cv.alg.signature, cv.signature, err = sign(hash, privateKey, hashedData, contextCertificateVerify)
	return err
}

func (cv *certificateVerifyBody) Verify(publicKey crypto.PublicKey, transcript []*handshakeMessage) error {
	_, hashedData, err := cv.computeContext(transcript)
	if err != nil {
		return err
	}

	logf(logTypeHandshake, "Digest to be verified: [%d] %x", len(hashedData), hashedData)

	return verify(cv.alg, publicKey, hashedData, contextCertificateVerify, cv.signature)
}

//  struct {
//      uint32 ticket_lifetime_hint;
//      opaque ticket<0..2^16-1>;
//  } NewSessionTicket;
type newSessionTicketBody struct {
	lifetimeHint uint32
	ticket       []byte
}

func newSessionTicket(lifetime uint32, ticketLen int) (*newSessionTicketBody, error) {
	tkt := &newSessionTicketBody{
		lifetimeHint: lifetime,
		ticket:       make([]byte, ticketLen),
	}
	_, err := prng.Read(tkt.ticket)
	return tkt, err
}

func (tkt newSessionTicketBody) Type() handshakeType {
	return handshakeTypeNewSessionTicket
}

func (tkt newSessionTicketBody) Marshal() ([]byte, error) {
	ticketLen := len(tkt.ticket)
	if ticketLen > maxTicketLen {
		return nil, fmt.Errorf("tls.ticket: Ticket too long to marshal")
	}

	header := []byte{
		byte(tkt.lifetimeHint >> 24),
		byte(tkt.lifetimeHint >> 16),
		byte(tkt.lifetimeHint >> 8),
		byte(tkt.lifetimeHint >> 0),
		byte(ticketLen >> 8),
		byte(ticketLen >> 0),
	}
	return append(header, tkt.ticket...), nil
}

func (tkt *newSessionTicketBody) Unmarshal(data []byte) (int, error) {
	if len(data) < 6 {
		return 0, fmt.Errorf("tls.ticket: Ticket too short to unmarshal")
	}

	tkt.lifetimeHint = (uint32(data[0]) << 24) + (uint32(data[1]) << 16) +
		(uint32(data[2]) << 8) + (uint32(data[3]))

	ticketLen := (int(data[4]) << 8) + int(data[5])
	if len(data[6:]) < ticketLen {
		return 0, fmt.Errorf("tls.ticket: Data too short to read ticket")
	}
	tkt.ticket = make([]byte, ticketLen)
	copy(tkt.ticket, data[6:])

	return 6 + ticketLen, nil
}
