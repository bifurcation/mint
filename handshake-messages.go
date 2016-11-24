package mint

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/bifurcation/mint/syntax"
)

const (
	fixedClientHelloBodyLen      = 39
	fixedServerHelloBodyLen      = 36
	fixedNewSessionTicketBodyLen = 10
	maxCipherSuites              = 1 << 15
	extensionHeaderLen           = 4
	maxExtensionDataLen          = (1 << 16) - 1
	maxExtensionsLen             = (1 << 16) - 1
	maxCertRequestContextLen     = 255
	maxTicketLen                 = (1 << 16) - 1
)

type handshakeMessageBody interface {
	Type() HandshakeType
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (int, error)
}

// struct {
//     ProtocolVersion legacy_version = 0x0303; /* TLS v1.2 */
//     Random random;
//     opaque legacy_session_id<0..32>;
//     CipherSuite cipher_suites<2..2^16-2>;
//     opaque legacy_compression_methods<1..2^8-1>;
//     Extension extensions<0..2^16-1>;
// } ClientHello;
type clientHelloBody struct {
	// Omitted: clientVersion
	// Omitted: legacySessionID
	// Omitted: legacyCompressionMethods
	random       [32]byte
	cipherSuites []CipherSuite
	extensions   ExtensionList
}

type clientHelloBodyInner struct {
	LegacyVersion            uint16
	Random                   [32]byte
	LegacySessionID          []byte        `tls:"head=1,max=32"`
	CipherSuites             []CipherSuite `tls:"head=2,min=2"`
	LegacyCompressionMethods []byte        `tls:"head=1,min=1"`
	Extensions               []Extension   `tls:"head=2"`
}

func (ch clientHelloBody) Type() HandshakeType {
	return HandshakeTypeClientHello
}

func (ch clientHelloBody) Marshal() ([]byte, error) {
	return syntax.Marshal(clientHelloBodyInner{
		LegacyVersion:            0x0303,
		Random:                   ch.random,
		LegacySessionID:          []byte{},
		CipherSuites:             ch.cipherSuites,
		LegacyCompressionMethods: []byte{0},
		Extensions:               ch.extensions,
	})
}

func (ch *clientHelloBody) Unmarshal(data []byte) (int, error) {
	var inner clientHelloBodyInner
	read, err := syntax.Unmarshal(data, &inner)
	if err != nil {
		return 0, err
	}

	// We are strict about these things because we only support 1.3
	if inner.LegacyVersion != 0x0303 {
		return 0, fmt.Errorf("tls.clienthello: Incorrect version number")
	}

	if len(inner.LegacyCompressionMethods) != 1 || inner.LegacyCompressionMethods[0] != 0 {
		return 0, fmt.Errorf("tls.clienthello: Invalid compression method")
	}

	ch.random = inner.Random
	ch.cipherSuites = inner.CipherSuites
	ch.extensions = inner.Extensions
	return read, nil
}

// TODO: File a spec bug to clarify this
func (ch clientHelloBody) Truncated() ([]byte, error) {
	if len(ch.extensions) == 0 {
		return nil, fmt.Errorf("tls.clienthello.truncate: No extensions")
	}

	pskExt := ch.extensions[len(ch.extensions)-1]
	if pskExt.ExtensionType != ExtensionTypePreSharedKey {
		return nil, fmt.Errorf("tls.clienthello.truncate: Last extension is not PSK")
	}

	chm, err := handshakeMessageFromBody(&ch)
	if err != nil {
		return nil, err
	}
	chData := chm.Marshal()

	psk := PreSharedKeyExtension{
		HandshakeType: HandshakeTypeClientHello,
	}
	_, err = psk.Unmarshal(pskExt.ExtensionData)
	if err != nil {
		return nil, err
	}

	// Marshal just the binders so that we know how much to truncate
	binders := struct {
		Binders []PSKBinderEntry `tls:"head=2,min=33"`
	}{Binders: psk.Binders}
	binderData, _ := syntax.Marshal(binders)
	binderLen := len(binderData)

	chLen := len(chData)
	return chData[:chLen-binderLen], nil
}

// struct {
//     ProtocolVersion version;
//     Random random;
//     CipherSuite cipher_suite;
//     Extension extensions<0..2^16-1>;
// } ServerHello;
type serverHelloBody struct {
	Version     uint16
	Random      [32]byte
	CipherSuite CipherSuite
	Extensions  ExtensionList `tls:"head=2"`
}

func (sh serverHelloBody) Type() HandshakeType {
	return HandshakeTypeServerHello
}

func (sh serverHelloBody) Marshal() ([]byte, error) {
	return syntax.Marshal(sh)
}

func (sh *serverHelloBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, sh)
}

// struct {
//     opaque verify_data[verify_data_length];
// } Finished;
//
// verifyDataLen is not a field in the TLS struct, but we add it here so
// that calling code can tell us how much data to expect when we marshal /
// unmarshal.  (We could add this to the marshal/unmarshal methods, but let's
// try to keep the signature consistent for now.)
//
// For similar reasons, we don't use the `syntax` module here, because this
// struct doesn't map well to standard TLS presentation language concepts.
//
// TODO: File a spec bug
type finishedBody struct {
	verifyDataLen int
	verifyData    []byte
}

func (fin finishedBody) Type() HandshakeType {
	return HandshakeTypeFinished
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
// Marshal() and Unmarshal() are handled by ExtensionList
type encryptedExtensionsBody struct {
	Extensions ExtensionList `tls:"head=2"`
}

func (ee encryptedExtensionsBody) Type() HandshakeType {
	return HandshakeTypeEncryptedExtensions
}

func (ee encryptedExtensionsBody) Marshal() ([]byte, error) {
	return syntax.Marshal(ee)
}

func (ee *encryptedExtensionsBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, ee)
}

// opaque ASN1Cert<1..2^24-1>;
//
// struct {
//     ASN1Cert cert_data;
//     Extension extensions<0..2^16-1>
// } CertificateEntry;
//
// struct {
//     opaque certificate_request_context<0..2^8-1>;
//     CertificateEntry certificate_list<0..2^24-1>;
// } Certificate;
type certificateEntry struct {
	certData   *x509.Certificate
	extensions ExtensionList
}

type certificateBody struct {
	certificateRequestContext []byte
	certificateList           []certificateEntry
}

func (c certificateBody) Type() HandshakeType {
	return HandshakeTypeCertificate
}

func (c certificateBody) Marshal() ([]byte, error) {
	if len(c.certificateRequestContext) > maxCertRequestContextLen {
		return nil, fmt.Errorf("tls.certificate: Request context too long")
	}

	certsData := []byte{}
	for _, entry := range c.certificateList {
		if entry.certData == nil || len(entry.certData.Raw) == 0 {
			return nil, fmt.Errorf("tls:certificate: Unmarshaled certificate")
		}

		extData, err := entry.extensions.Marshal()
		if err != nil {
			return nil, err
		}

		certLen := len(entry.certData.Raw)
		entryData := []byte{byte(certLen >> 16), byte(certLen >> 8), byte(certLen)}
		entryData = append(entryData, entry.certData.Raw...)
		entryData = append(entryData, extData...)
		certsData = append(certsData, entryData...)
	}
	certsDataLen := len(certsData)
	certsDataLenBytes := []byte{byte(certsDataLen >> 16), byte(certsDataLen >> 8), byte(certsDataLen)}

	data := []byte{byte(len(c.certificateRequestContext))}
	data = append(data, c.certificateRequestContext...)
	data = append(data, certsDataLenBytes...)
	data = append(data, certsData...)
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
	c.certificateList = []certificateEntry{}
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

		var ext ExtensionList
		read, err := ext.Unmarshal(data[start+3+certLen:])
		if err != nil {
			return 0, err
		}

		c.certificateList = append(c.certificateList, certificateEntry{
			certData:   cert,
			extensions: ext,
		})
		start += 3 + certLen + read
	}
	return start, nil
}

// struct {
//     SignatureScheme algorithm;
//     opaque signature<0..2^16-1>;
// } CertificateVerify;
type certificateVerifyBody struct {
	Algorithm SignatureScheme
	Signature []byte `tls:"head=2"`
}

func (cv certificateVerifyBody) Type() HandshakeType {
	return HandshakeTypeCertificateVerify
}

func (cv certificateVerifyBody) Marshal() ([]byte, error) {
	return syntax.Marshal(cv)
}

func (cv *certificateVerifyBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, cv)
}

func (cv *certificateVerifyBody) computeContext(ctx cryptoContext, transcript []*handshakeMessage) (hashed []byte, err error) {
	h := ctx.params.hash.New()
	handshakeContext := []byte{}
	for _, msg := range transcript {
		if msg == nil {
			err = fmt.Errorf("tls.certverify: Nil message")
			return
		}
		data := msg.Marshal()
		logf(logTypeHandshake, "Added Message to Handshake Context to be verified: [%d] %x", len(data), data)
		handshakeContext = append(handshakeContext, data...)
		h.Write(data)
	}

	hashed = h.Sum(nil)
	logf(logTypeHandshake, "Handshake Context to be verified: [%d] %x", len(handshakeContext), handshakeContext)
	logf(logTypeHandshake, "Handshake Hash to be verified: [%d] %x", len(hashed), hashed)
	return
}

func (cv *certificateVerifyBody) encodeSignatureInput(data []byte) []byte {
	const context = "TLS 1.3, server CertificateVerify"
	sigInput := bytes.Repeat([]byte{0x20}, 64)
	sigInput = append(sigInput, []byte(context)...)
	sigInput = append(sigInput, []byte{0}...)
	sigInput = append(sigInput, data...)
	return sigInput
}

func (cv *certificateVerifyBody) Sign(privateKey crypto.Signer, transcript []*handshakeMessage, ctx cryptoContext) error {
	hashedWithContext, err := cv.computeContext(ctx, transcript)
	if err != nil {
		return err
	}

	sigInput := cv.encodeSignatureInput(hashedWithContext)
	cv.Signature, err = sign(cv.Algorithm, privateKey, sigInput)
	logf(logTypeHandshake, "Signed: alg=[%04x] sigInput=[%x], sig=[%x]", cv.Algorithm, sigInput, cv.Signature)
	return err
}

func (cv *certificateVerifyBody) Verify(publicKey crypto.PublicKey, transcript []*handshakeMessage, ctx cryptoContext) error {
	hashedWithContext, err := cv.computeContext(ctx, transcript)
	if err != nil {
		return err
	}

	sigInput := cv.encodeSignatureInput(hashedWithContext)
	logf(logTypeHandshake, "About to verify: alg=[%04x] sigInput=[%x], sig=[%x]", cv.Algorithm, sigInput, cv.Signature)
	return verify(cv.Algorithm, publicKey, sigInput, cv.Signature)
}

// struct {
//     uint32 ticket_lifetime;
//     uint32 ticket_age_add;
//     opaque ticket<1..2^16-1>;
//     Extension extensions<0..2^16-2>;
// } NewSessionTicket;
type newSessionTicketBody struct {
	TicketLifetime uint32
	TicketAgeAdd   uint32
	Ticket         []byte        `tls:"head=2,min=1"`
	Extensions     ExtensionList `tls:"head=2"`
}

func newSessionTicket(ticketLen int) (*newSessionTicketBody, error) {
	tkt := &newSessionTicketBody{
		Ticket: make([]byte, ticketLen),
	}
	_, err := prng.Read(tkt.Ticket)
	return tkt, err
}

func (tkt newSessionTicketBody) Type() HandshakeType {
	return HandshakeTypeNewSessionTicket
}

func (tkt newSessionTicketBody) Marshal() ([]byte, error) {
	return syntax.Marshal(tkt)
}

func (tkt *newSessionTicketBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, tkt)
}

// enum {
//     update_not_requested(0), update_requested(1), (255)
// } KeyUpdateRequest;
//
// struct {
//     KeyUpdateRequest request_update;
// } KeyUpdate;
type keyUpdateBody struct {
	KeyUpdateRequest KeyUpdateRequest
}

func (ku keyUpdateBody) Type() HandshakeType {
	return HandshakeTypeKeyUpdate
}

func (ku keyUpdateBody) Marshal() ([]byte, error) {
	return syntax.Marshal(ku)
}

func (ku *keyUpdateBody) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, ku)
}
