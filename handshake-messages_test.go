package mint

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

const (
	fixedClientHelloBodyLen  = 39
	fixedServerHelloBodyLen  = 36
	maxCipherSuites          = 1 << 15
	maxExtensionDataLen      = (1 << 16) - 1
	maxCertRequestContextLen = 255
	maxTicketLen             = (1 << 16) - 1
)

var (
	supportedVersionHex = hex.EncodeToString([]byte{
		byte(supportedVersion >> 8),
		byte(supportedVersion & 0xff),
	})
	tls12VersionHex = hex.EncodeToString([]byte{
		byte(tls12Version >> 8),
		byte(tls12Version & 0xff),
	})

	// ClientHello test cases
	// NB: Borrowing some values from extensions_test.go
	helloRandom = [32]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}
	chCipherSuites = []CipherSuite{0x0001, 0x0002, 0x0003}
	chValidIn      = ClientHelloBody{
		LegacyVersion:   tls12Version,
		Random:          helloRandom,
		CipherSuites:    chCipherSuites,
		Extensions:      extListValidIn,
		LegacySessionID: []byte{},
	}
	chValidHex = "0303" + hex.EncodeToString(helloRandom[:]) + "00" +
		"0006000100020003" + "0100" + extListValidHex
	chOverflowHex = "0303" + hex.EncodeToString(helloRandom[:]) + "00" +
		"0006000100020003" + "0100" + extListOverflowOuterHex

	// ClientHello truncation test cases
	chTruncPSKData = unhex(pskClientHex)
	chTruncHex     = "01000062" + "0303" + hex.EncodeToString(helloRandom[:]) +
		"00" + "0006000100020003" + "0100" + "00330029002f000a00040102030405060708"
	chTruncValid = ClientHelloBody{
		LegacyVersion: tls12Version,
		Random:        helloRandom,
		CipherSuites:  chCipherSuites,
		Extensions: []Extension{
			{
				ExtensionType: ExtensionTypePreSharedKey,
				ExtensionData: chTruncPSKData,
			},
		},
	}
	chTruncInvalid = ClientHelloBody{}
	chTruncNoExt   = ClientHelloBody{
		LegacyVersion: tls12Version,
		Random:        helloRandom,
		CipherSuites:  chCipherSuites,
		Extensions:    []Extension{},
	}
	chTruncNoPSK = ClientHelloBody{
		LegacyVersion: tls12Version,
		Random:        helloRandom,
		CipherSuites:  chCipherSuites,
		Extensions: []Extension{
			{ExtensionType: ExtensionTypeEarlyData},
		},
	}
	chTruncBadPSK = ClientHelloBody{
		LegacyVersion: tls12Version,
		Random:        helloRandom,
		CipherSuites:  chCipherSuites,
		Extensions: []Extension{
			{ExtensionType: ExtensionTypePreSharedKey},
		},
	}

	// ServerHello test cases
	shValidIn = ServerHelloBody{
		Version:         tls12Version,
		Random:          helloRandom,
		LegacySessionID: []byte{},
		CipherSuite:     CipherSuite(0x0001),
		Extensions:      extListValidIn,
	}
	shEmptyIn = ServerHelloBody{
		Version:     tls12Version,
		Random:      helloRandom,
		CipherSuite: CipherSuite(0x0001),
	}
	shValidHex    = tls12VersionHex + hex.EncodeToString(helloRandom[:]) + "00" + "0001" + "00" + extListValidHex
	shEmptyHex    = tls12VersionHex + hex.EncodeToString(helloRandom[:]) + "00" + "0001" + "00" + "0000"
	shOverflowHex = tls12VersionHex + hex.EncodeToString(helloRandom[:]) + "0001" + extListOverflowOuterHex

	// Finished test cases
	finValidIn = FinishedBody{
		VerifyDataLen: len(helloRandom),
		VerifyData:    helloRandom[:],
	}
	finValidHex = hex.EncodeToString(helloRandom[:])

	// EncryptedExtensions test cases
	encExtValidIn  = EncryptedExtensionsBody{extListValidIn}
	encExtValidHex = extListValidHex

	// Certificate test cases
	cert1Hex = "308201653082010ba003020102020500a0a0a0a0300a0608" +
		"2a8648ce3d0403023017311530130603550403130c657861" +
		"6d706c65312e636f6d3022180f3030303130313031303030" +
		"3030305a180f30303031303130313030303030305a301731" +
		"1530130603550403130c6578616d706c65312e636f6d3059" +
		"301306072a8648ce3d020106082a8648ce3d030107034200" +
		"044460e6de2a170e0c7c8d1306c82386db31980bd76647bd" +
		"e9b96055d075fc64ea7d8d3864afcf0ff16da73c68df6880" +
		"a597303243410016ef2e36f5962584d187a340303e300e06" +
		"03551d0f0101ff0404030203a830130603551d25040c300a" +
		"06082b0601050507030130170603551d110410300e820c65" +
		"78616d706c65312e636f6d300a06082a8648ce3d04030203" +
		"48003045022005937d0bf7a7cb4589715bb83dddd2505335" +
		"829e6305b75cfeae6f2dcc2230b6022100f6f0e75436cd59" +
		"b94ceedffb18bcf5bb2f161260a282f7b63d1376e5805c51" +
		"b6"
	cert2Hex = "308201643082010ba003020102020500a0a0a0a0300a0608" +
		"2a8648ce3d0403043017311530130603550403130c657861" +
		"6d706c65322e636f6d3022180f3030303130313031303030" +
		"3030305a180f30303031303130313030303030305a301731" +
		"1530130603550403130c6578616d706c65322e636f6d3059" +
		"301306072a8648ce3d020106082a8648ce3d030107034200" +
		"044460e6de2a170e0c7c8d1306c82386db31980bd76647bd" +
		"e9b96055d075fc64ea7d8d3864afcf0ff16da73c68df6880" +
		"a597303243410016ef2e36f5962584d187a340303e300e06" +
		"03551d0f0101ff0404030203a830130603551d25040c300a" +
		"06082b0601050507030130170603551d110410300e820c65" +
		"78616d706c65322e636f6d300a06082a8648ce3d04030403" +
		"470030440220718254f2b3c1cc0fa4c53bf43182f8acbc19" +
		"04e45ee1a3abdc8bc50a155712b4022010664cc29b80fae9" +
		"150027726da5b144df764a76007eee2a52b6ae0c995395fb"
	cert1Bytes = unhex(cert1Hex)
	cert2Bytes = unhex(cert2Hex)
	cert1, _   = x509.ParseCertificate(cert1Bytes)
	cert2, _   = x509.ParseCertificate(cert2Bytes)

	certValidIn = CertificateBody{
		CertificateRequestContext: []byte{0, 0, 0, 0},
		CertificateList: []CertificateEntry{
			{
				CertData:   cert1,
				Extensions: extListValidIn,
			},
			{
				CertData:   cert2,
				Extensions: extListValidIn,
			},
		},
	}
	certOverflowIn = CertificateBody{
		CertificateRequestContext: []byte{0, 0, 0, 0},
		CertificateList: []CertificateEntry{
			{
				CertData:   cert1,
				Extensions: extListSingleTooLongIn,
			},
		},
	}
	certValidHex = "0400000000" +
		"0002f5" +
		"000169" + cert1Hex + extListValidHex +
		"000168" + cert2Hex + extListValidHex
	certTooShortHex = "000000023081"

	// CertificateVerify test cases
	certVerifyValidIn = CertificateVerifyBody{
		Algorithm: ECDSA_P256_SHA256,
		Signature: []byte{0, 0, 0, 0},
	}
	certVerifyValidHex    = "0403000400000000"
	certVerifyCipherSuite = TLS_AES_128_GCM_SHA256

	// CertificateRequest test cases
	certReqValidIn = CertificateRequestBody{
		CertificateRequestContext: []byte{0, 1, 2, 3, 4, 5, 6, 7},
		Extensions: []Extension{
			{
				ExtensionType: ExtensionTypeSignatureAlgorithms,
				ExtensionData: unhex("000404030503"),
			},
		},
	}
	certReqValidHex = "080001020304050607" + // context
		"000a000d0006000404030503" // extensions

	// NewSessionTicket test cases
	ticketValidHex = "00010203" + "04050607" + "0408090a0b" + "00040c0d0e0f" + "0006eeff00021122"
	ticketValidIn  = NewSessionTicketBody{
		TicketLifetime: 0x00010203,
		TicketAgeAdd:   0x04050607,
		TicketNonce:    []byte{0x08, 0x09, 0x0a, 0x0b},
		Ticket:         []byte{0x0c, 0x0d, 0x0e, 0x0f},
		Extensions: []Extension{
			{
				ExtensionType: 0xeeff,
				ExtensionData: []byte{0x11, 0x22},
			},
		},
	}
	ticketTooBigIn = NewSessionTicketBody{
		TicketLifetime: 0x00010203,
		Ticket:         make([]byte, maxTicketLen+1),
	}
	ticketExtensionsTooBigIn = NewSessionTicketBody{
		Extensions: extListSingleTooLongIn,
	}

	// KeyUpdate test cases
	keyUpdateValidHex = "01"
	keyUpdateValidIn  = KeyUpdateBody{
		KeyUpdateRequest: KeyUpdateRequested,
	}

	// EndOfEarlyData test cases
	endOfEarlyDataValidHex = ""
	endOfEarlyDataValidIn  = EndOfEarlyDataBody{}
)

func TestHandshakeMessageTypes(t *testing.T) {
	assertEquals(t, ClientHelloBody{}.Type(), HandshakeTypeClientHello)
	assertEquals(t, ServerHelloBody{}.Type(), HandshakeTypeServerHello)
	assertEquals(t, FinishedBody{}.Type(), HandshakeTypeFinished)
	assertEquals(t, EncryptedExtensionsBody{}.Type(), HandshakeTypeEncryptedExtensions)
	assertEquals(t, CertificateBody{}.Type(), HandshakeTypeCertificate)
	assertEquals(t, CertificateVerifyBody{}.Type(), HandshakeTypeCertificateVerify)
}

func TestClientHelloMarshalUnmarshal(t *testing.T) {
	chValid := unhex(chValidHex)
	chOverflow := unhex(chOverflowHex)

	// Test correctness of handshake type
	assertEquals(t, (ClientHelloBody{}).Type(), HandshakeTypeClientHello)

	// Test successful marshal
	out, err := chValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid ClientHello")
	assertByteEquals(t, out, chValid)

	// Test marshal failure on empty ciphersuites
	chValidIn.CipherSuites = []CipherSuite{}
	out, err = chValidIn.Marshal()
	assertError(t, err, "Marshaled a ClientHello with no CipherSuites")
	chValidIn.CipherSuites = chCipherSuites

	// Test marshal failure on too many ciphersuites
	tooManyCipherSuites := make([]CipherSuite, maxCipherSuites+1)
	for i := range tooManyCipherSuites {
		tooManyCipherSuites[i] = CipherSuite(0x0001)
	}
	chValidIn.CipherSuites = tooManyCipherSuites
	out, err = chValidIn.Marshal()
	assertError(t, err, "Marshaled a ClientHello with too many CipherSuites")
	chValidIn.CipherSuites = chCipherSuites

	// Test marshal failure on extension list marshal failure
	chValidIn.Extensions = extListTooLongIn
	out, err = chValidIn.Marshal()
	assertError(t, err, "Marshaled a ClientHello with bad extensions")
	chValidIn.Extensions = extListValidIn

	// Test successful unmarshal
	var ch ClientHelloBody
	read, err := ch.Unmarshal(chValid)
	assertNotError(t, err, "Failed to unmarshal a valid ClientHello")
	assertEquals(t, read, len(chValid))
	assertDeepEquals(t, ch, chValidIn)

	// Test unmarshal failure on too-short ClientHello
	_, err = ch.Unmarshal(chValid[:fixedClientHelloBodyLen-1])
	assertError(t, err, "Unmarshaled a ClientHello below the min length")

	// Test unmarshal failure on ciphersuite size overflow
	chValid[35] = 0xFF
	_, err = ch.Unmarshal(chValid)
	assertError(t, err, "Unmarshaled a ClientHello an overflowing cipherSuite list")
	chValid[35] = 0x00

	// Test unmarshal failure on odd ciphersuite size
	chValid[36] ^= 0x01
	_, err = ch.Unmarshal(chValid)
	assertError(t, err, "Unmarshaled a ClientHello an odd cipherSuite list length")
	chValid[36] ^= 0x01

	// Test unmarshal failure on missing compression methods
	_, err = ch.Unmarshal(chValid[:37+6])
	assertError(t, err, "Unmarshaled a ClientHello truncated before the compression methods")

	// Test unmarshal failure on incorrect compression methods
	chValid[37+6] = 0x03
	_, err = ch.Unmarshal(chValid)
	assertError(t, err, "Unmarshaled a ClientHello more than one compression method")
	chValid[37+6] = 0x01
	chValid[37+7] = 0x01
	_, err = ch.Unmarshal(chValid)
	assertError(t, err, "Unmarshaled a ClientHello the wrong compression method")
	chValid[37+7] = 0x00

	// Test unmarshal failure on extension list unmarshal failure
	_, err = ch.Unmarshal(chOverflow)
	assertError(t, err, "Unmarshaled a ClientHello with invalid extensions")
}

func TestClientHelloTruncate(t *testing.T) {
	chTrunc := unhex(chTruncHex)

	// Test success
	trunc, err := chTruncValid.Truncated()
	assertNotError(t, err, "Error truncating valid ClientHello")
	assertByteEquals(t, trunc, chTrunc)

	// Test failure on marshal failure
	_, err = chTruncInvalid.Truncated()
	assertError(t, err, "Truncated a ClientHello that should not have marshaled")

	// Test failure on no extensions
	_, err = chTruncNoExt.Truncated()
	assertError(t, err, "Truncated a ClientHello with no extensions")

	// Test failure on last extension not PSK
	_, err = chTruncNoPSK.Truncated()
	assertError(t, err, "Truncated a ClientHello whose last extension was not a PSK")

	// Test failiure on last extension malformed PSK
	_, err = chTruncBadPSK.Truncated()
	assertError(t, err, "Truncated a ClientHello with a mal-formed PSK")
}

func TestServerHelloMarshalUnmarshal(t *testing.T) {
	shValid := unhex(shValidHex)
	shEmpty := unhex(shEmptyHex)
	shOverflow := unhex(shOverflowHex)

	// Test correctness of handshake type
	assertEquals(t, (ServerHelloBody{}).Type(), HandshakeTypeServerHello)

	// Test successful marshal
	out, err := shValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid ServerHello")
	assertByteEquals(t, out, shValid)

	// Test successful marshal with no extensions present
	out, err = shEmptyIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid ServerHello with no extensions")
	assertByteEquals(t, out, shEmpty)

	// Test marshal failure on extension list marshal failure
	shValidIn.Extensions = extListTooLongIn
	out, err = shValidIn.Marshal()
	assertError(t, err, "Marshaled a ServerHello with bad extensions")
	shValidIn.Extensions = extListValidIn

	// Test successful unmarshal
	var sh ServerHelloBody
	read, err := sh.Unmarshal(shValid)
	assertNotError(t, err, "Failed to unmarshal a valid ServerHello")
	assertEquals(t, read, len(shValid))
	assertDeepEquals(t, sh, shValidIn)

	// Test successful unmarshal with no extensions present
	read, err = sh.Unmarshal(shEmpty)
	assertNotError(t, err, "Failed to unmarshal a valid ServerHello")
	assertEquals(t, read, len(shEmpty))
	assertByteEquals(t, sh.Random[:], shEmptyIn.Random[:])
	assertEquals(t, sh.CipherSuite, shEmptyIn.CipherSuite)
	assertEquals(t, len(sh.Extensions), 0)

	// Test unmarshal failure on too-short ServerHello
	_, err = sh.Unmarshal(shValid[:fixedServerHelloBodyLen-1])
	assertError(t, err, "Unmarshaled a too-short ServerHello")

	// Test unmarshal failure on extension list unmarshal failure
	_, err = sh.Unmarshal(shOverflow)
	assertError(t, err, "Unmarshaled a ServerHello with invalid extensions")
}

func TestFinishedMarshalUnmarshal(t *testing.T) {
	finValid := unhex(finValidHex)

	// Test correctness of handshake type
	assertEquals(t, (FinishedBody{}).Type(), HandshakeTypeFinished)

	// Test successful marshal
	out, err := finValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid Finished")
	assertByteEquals(t, out, finValid)

	// Test marshal failure on incorrect data length
	finValidIn.VerifyDataLen--
	out, err = finValidIn.Marshal()
	assertError(t, err, "Marshaled a Finished with the wrong data length")
	finValidIn.VerifyDataLen++

	// Test successful unmarshal
	var fin FinishedBody
	fin.VerifyDataLen = len(finValid)
	read, err := fin.Unmarshal(finValid)
	assertNotError(t, err, "Failed to unmarshal a valid Finished")
	assertEquals(t, read, len(finValid))
	assertDeepEquals(t, fin, finValidIn)

	// Test unmarshal failure on insufficient data
	fin.VerifyDataLen++
	_, err = fin.Unmarshal(finValid)
	assertError(t, err, "Unmarshaled a Finished with too little data")
	fin.VerifyDataLen--
}

// This one is a little brief because it is just an extensionList
func TestEncrypteExtensionsMarshalUnmarshal(t *testing.T) {
	encExtValid := unhex(encExtValidHex)

	// Test correctness of handshake type
	assertEquals(t, (EncryptedExtensionsBody{}).Type(), HandshakeTypeEncryptedExtensions)

	// Test successful marshal
	out, err := encExtValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid EncryptedExtensions")
	assertByteEquals(t, out, encExtValid)

	// Test successful unmarshal
	var ee EncryptedExtensionsBody
	read, err := ee.Unmarshal(encExtValid)
	assertNotError(t, err, "Failed to unmarshal a valid EncryptedExtensions")
	assertEquals(t, read, len(encExtValid))
	assertDeepEquals(t, ee, encExtValidIn)
}

func TestCertificateMarshalUnmarshal(t *testing.T) {
	// Create a couple of certificates and manually encode
	certValid := unhex(certValidHex)
	certTooShort := unhex(certTooShortHex)

	// Test correctness of handshake type
	assertEquals(t, (CertificateBody{}).Type(), HandshakeTypeCertificate)

	// Test successful marshal
	out, err := certValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid Certificate")
	assertByteEquals(t, out, certValid)

	// Test marshal failure on context too long
	originalContext := certValidIn.CertificateRequestContext
	certValidIn.CertificateRequestContext = bytes.Repeat([]byte{0}, maxCertRequestContextLen+1)
	out, err = certValidIn.Marshal()
	assertError(t, err, "Marshaled a Certificate with a too-long context")
	certValidIn.CertificateRequestContext = originalContext

	// Test marshal failure on no raw certa
	originalRaw := cert1.Raw
	cert1.Raw = []byte{}
	out, err = certValidIn.Marshal()
	assertError(t, err, "Marshaled a Certificate with an empty cert")
	cert1.Raw = originalRaw

	// Test marshal failure on extension list marshal failure
	out, err = certOverflowIn.Marshal()
	assertError(t, err, "Marshaled a Certificate with an too-long extension list")

	// Test successful unmarshal
	cert := CertificateBody{}
	read, err := cert.Unmarshal(certValid)
	assertNotError(t, err, "Failed to unmarshal valid Certificate")
	assertEquals(t, read, len(certValid))
	assertDeepEquals(t, cert, certValidIn)

	// Test unmarshal failure on truncated header
	_, err = cert.Unmarshal(certValid[:0])
	assertError(t, err, "Unmarshaled a Certificate with a truncated header")

	// Test unmarshal failure on truncated context
	_, err = cert.Unmarshal(certValid[:7])
	assertError(t, err, "Unmarshaled a Certificate with a truncated context")

	// Test unmarshal failure on truncated certificates
	_, err = cert.Unmarshal(certValid[:12])
	assertError(t, err, "Unmarshaled a Certificate with truncated certificates")

	// Test unmarshal failure on a too-short certificates field
	_, err = cert.Unmarshal(certTooShort)
	assertError(t, err, "Unmarshaled a Certificate with truncated certificate length")

	// Test unmarshal failure on truncated certificate
	certValid[8] ^= 0xFF // Make length of first cert huge
	_, err = cert.Unmarshal(certValid)
	assertError(t, err, "Unmarshaled a Certificate with truncated certificates")
	certValid[8] ^= 0xFF

	// Test unmarshal failure on malformed certificate
	certValid[11] ^= 0xFF // Clobber first octet of first cert
	_, err = cert.Unmarshal(certValid)
	assertError(t, err, "Unmarshaled a Certificate with truncated certificates")
	certValid[11] ^= 0xFF
}

func TestCertificateVerifyMarshalUnmarshal(t *testing.T) {
	certVerifyValid := unhex(certVerifyValidHex)

	handshakeHash := []byte{0, 1, 2, 3}

	privRSA, err := newSigningKey(RSA_PSS_SHA256)
	assertNotError(t, err, "failed to generate RSA private key")

	// Test correctness of handshake type
	assertEquals(t, (CertificateVerifyBody{}).Type(), HandshakeTypeCertificateVerify)

	// Test successful marshal
	out, err := certVerifyValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid CertificateVerify")
	assertByteEquals(t, out, certVerifyValid)

	// Test successful unmarshal
	var cv CertificateVerifyBody
	read, err := cv.Unmarshal(certVerifyValid)
	assertNotError(t, err, "Failed to unmarshal a valid CertificateVerify")
	assertEquals(t, read, len(certVerifyValid))
	assertDeepEquals(t, cv, certVerifyValidIn)

	// Test unmarshal failure on truncated header
	_, err = cv.Unmarshal(certVerifyValid[:1])
	assertError(t, err, "Unmarshaled a CertificateVerify with no header")

	// Test unmarshal failure on truncated signature
	_, err = cv.Unmarshal(certVerifyValid[:5])
	assertError(t, err, "Unmarshaled a CertificateVerify with no header")

	// Test successful sign / verify round-trip
	certVerifyValidIn.Algorithm = RSA_PSS_SHA256
	err = certVerifyValidIn.Sign(privRSA, handshakeHash)
	assertNotError(t, err, "Failed to sign CertificateVerify")

	// Test sign failure on algorithm
	originalAlg := certVerifyValidIn.Algorithm
	certVerifyValidIn.Algorithm = SignatureScheme(0)
	err = certVerifyValidIn.Sign(privRSA, handshakeHash)
	assertError(t, err, "Signed CertificateVerify despite bad algorithm")
	certVerifyValidIn.Algorithm = originalAlg

	// Test successful verify
	certVerifyValidIn = CertificateVerifyBody{Algorithm: RSA_PSS_SHA256}
	err = certVerifyValidIn.Sign(privRSA, handshakeHash)
	assertNotError(t, err, "Failed to sign CertificateVerify")
	err = certVerifyValidIn.Verify(privRSA.Public(), handshakeHash)
	assertNotError(t, err, "Failed to verify CertificateVerify")

	// Test verify failure on bad algorithm
	originalAlg = certVerifyValidIn.Algorithm
	certVerifyValidIn.Algorithm = SignatureScheme(0)
	err = certVerifyValidIn.Verify(privRSA.Public(), handshakeHash)
	assertError(t, err, "Verified CertificateVerify despite bad hash algorithm")
	certVerifyValidIn.Algorithm = originalAlg
}

func TestCertificateRequestMarshalUnmarshal(t *testing.T) {
	certReqValid := unhex(certReqValidHex)

	// Test correctness of handshake type
	assertEquals(t, (CertificateRequestBody{}).Type(), HandshakeTypeCertificateRequest)

	// Test successful marshal
	out, err := certReqValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid CertificateRequest")
	assertByteEquals(t, out, certReqValid)

	// Test successful unmarshal
	var cv CertificateRequestBody
	read, err := cv.Unmarshal(certReqValid)
	assertNotError(t, err, "Failed to unmarshal a valid CertificateRequest")
	assertEquals(t, read, len(certReqValid))
	assertDeepEquals(t, cv, certReqValidIn)

}

func TestNewSessionTicketMarshalUnmarshal(t *testing.T) {
	ticketValid := unhex(ticketValidHex)

	// Test correctness of handshake type
	assertEquals(t, (NewSessionTicketBody{}).Type(), HandshakeTypeNewSessionTicket)

	// Test creation of a new random ticket
	tkt, err := NewSessionTicket(16, 3)
	assertNotError(t, err, "Failed to create session ticket")
	assertEquals(t, tkt.TicketLifetime, uint32(3))
	assertEquals(t, len(tkt.Ticket), 16)

	// Test successful marshal
	out, err := ticketValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid NewSessionTicket")
	assertByteEquals(t, out, ticketValid)

	// Test marshal failure on a ticket that's too large
	out, err = ticketTooBigIn.Marshal()
	assertError(t, err, "Marshaled a NewSessionTicket with an invalid data length")

	// Test marshal failure on extensions too large
	out, err = ticketExtensionsTooBigIn.Marshal()
	assertError(t, err, "Marshaled a NewSessionTicket with extensions that are too big")

	// Test successful unmarshal
	read, err := tkt.Unmarshal(ticketValid)
	assertNotError(t, err, "Failed to unmarshal a valid NewSessionTicket")
	assertEquals(t, read, len(ticketValid))
	assertDeepEquals(t, *tkt, ticketValidIn)

	// Test unmarshal failure on insufficient data
	_, err = tkt.Unmarshal(ticketValid[:4])
	assertError(t, err, "Unmarshaled a NewSessionTicket with an incomplete header")

	_, err = tkt.Unmarshal(ticketValid[:13])
	assertError(t, err, "Unmarshaled a NewSessionTicket with an incomplete ticket")

	_, err = tkt.Unmarshal(ticketValid[:20])
	assertError(t, err, "Unmarshaled a NewSessionTicket with incomplete extensions")
}

func TestKeyUpdateMarshalUnmarshal(t *testing.T) {
	keyUpdateValid := unhex(keyUpdateValidHex)

	// Test correctness of handshake type
	assertEquals(t, (KeyUpdateBody{}).Type(), HandshakeTypeKeyUpdate)

	// Test successful marshal
	out, err := keyUpdateValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid KeyUpdate")
	assertByteEquals(t, out, keyUpdateValid)

	// Test successful unmarshal
	var ku KeyUpdateBody
	read, err := ku.Unmarshal(keyUpdateValid)
	assertNotError(t, err, "Failed to unmarshal a valid KeyUpdate")
	assertEquals(t, read, len(keyUpdateValid))
	assertDeepEquals(t, ku, keyUpdateValidIn)
}

func TestEndOfEarlyDataMarshalUnmarshal(t *testing.T) {
	endOfEarlyDataValid := unhex(endOfEarlyDataValidHex)

	// Test correctness of handshake type
	assertEquals(t, (EndOfEarlyDataBody{}).Type(), HandshakeTypeEndOfEarlyData)

	// Test successful marshal
	out, err := endOfEarlyDataValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid KeyUpdate")
	assertByteEquals(t, out, endOfEarlyDataValid)

	// Test successful unmarshal
	var eoed EndOfEarlyDataBody
	read, err := eoed.Unmarshal(endOfEarlyDataValid)
	assertNotError(t, err, "Failed to unmarshal a valid KeyUpdate")
	assertEquals(t, read, len(endOfEarlyDataValid))
	assertDeepEquals(t, eoed, endOfEarlyDataValidIn)
}

func TestsafeUnmarshal(t *testing.T) {
	chValid := unhex(chValidHex)
	tooLong := append(chValid, 0)
	var ch ClientHelloBody

	// Check that safeUnmarshal works normally
	err := safeUnmarshal(&ch, chValid)
	assertNotError(t, err, "Failed to unmarshal ClientHello")

	// Test successful unmarshal
	read, err := ch.Unmarshal(tooLong)
	assertNotError(t, err, "Failed to unmarshal a too long ClientHello")
	assertEquals(t, read, len(chValid))
	assertDeepEquals(t, ch, chValidIn)

	// Now test that safeUnmarshal barfs
	err = safeUnmarshal(&ch, tooLong)
	assertError(t, err, "Unmarshalled something too long")
}
