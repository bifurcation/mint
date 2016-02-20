package mint

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

var (
	// ClientHello test cases
	// NB: Borrowing some values from extensions_test.go
	helloRandom = [32]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}
	chCipherSuites = []cipherSuite{0x0001, 0x0002, 0x0003}
	chValidIn      = clientHelloBody{
		random:       helloRandom,
		cipherSuites: chCipherSuites,
		extensions:   extListValidIn,
	}
	chValidHex = "0304" + hex.EncodeToString(helloRandom[:]) + "00" +
		"0006000100020003" + "0100" + extListValidHex
	chOverflowHex = "0304" + hex.EncodeToString(helloRandom[:]) + "00" +
		"0006000100020003" + "0100" + extListOverflowOuterHex

	// ServerHello test cases
	shValidIn = serverHelloBody{
		random:      helloRandom,
		cipherSuite: cipherSuite(0x0001),
		extensions:  extListValidIn,
	}
	shEmptyIn = serverHelloBody{
		random:      helloRandom,
		cipherSuite: cipherSuite(0x0001),
	}
	shValidHex    = "0304" + hex.EncodeToString(helloRandom[:]) + "0001" + extListValidHex
	shEmptyHex    = "0304" + hex.EncodeToString(helloRandom[:]) + "0001"
	shOverflowHex = "0304" + hex.EncodeToString(helloRandom[:]) + "0001" + extListOverflowOuterHex

	// Finished test cases
	finValidIn = finishedBody{
		verifyDataLen: len(helloRandom),
		verifyData:    helloRandom[:],
	}
	finValidHex = hex.EncodeToString(helloRandom[:])

	// EncryptedExtensions test cases
	encExtValidIn  = encryptedExtensionsBody(extListValidIn)
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
	certValidIn  = certificateBody{certificateRequestContext: []byte{0, 0, 0, 0}}
	certValidHex = "04000000000002d1308201653082010ba003020102020500" +
		"a0a0a0a0300a06082a8648ce3d0403023017311530130603" +
		"550403130c6578616d706c65312e636f6d3022180f303030" +
		"31303130313030303030305a180f30303031303130313030" +
		"303030305a3017311530130603550403130c6578616d706c" +
		"65312e636f6d3059301306072a8648ce3d020106082a8648" +
		"ce3d030107034200044460e6de2a170e0c7c8d1306c82386" +
		"db31980bd76647bde9b96055d075fc64ea7d8d3864afcf0f" +
		"f16da73c68df6880a597303243410016ef2e36f5962584d1" +
		"87a340303e300e0603551d0f0101ff0404030203a8301306" +
		"03551d25040c300a06082b0601050507030130170603551d" +
		"110410300e820c6578616d706c65312e636f6d300a06082a" +
		"8648ce3d0403020348003045022005937d0bf7a7cb458971" +
		"5bb83dddd2505335829e6305b75cfeae6f2dcc2230b60221" +
		"00f6f0e75436cd59b94ceedffb18bcf5bb2f161260a282f7" +
		"b63d1376e5805c51b6308201643082010ba0030201020205" +
		"00a0a0a0a0300a06082a8648ce3d04030430173115301306" +
		"03550403130c6578616d706c65322e636f6d3022180f3030" +
		"3031303130313030303030305a180f303030313031303130" +
		"30303030305a3017311530130603550403130c6578616d70" +
		"6c65322e636f6d3059301306072a8648ce3d020106082a86" +
		"48ce3d030107034200044460e6de2a170e0c7c8d1306c823" +
		"86db31980bd76647bde9b96055d075fc64ea7d8d3864afcf" +
		"0ff16da73c68df6880a597303243410016ef2e36f5962584" +
		"d187a340303e300e0603551d0f0101ff0404030203a83013" +
		"0603551d25040c300a06082b060105050703013017060355" +
		"1d110410300e820c6578616d706c65322e636f6d300a0608" +
		"2a8648ce3d04030403470030440220718254f2b3c1cc0fa4" +
		"c53bf43182f8acbc1904e45ee1a3abdc8bc50a155712b402" +
		"2010664cc29b80fae9150027726da5b144df764a76007eee" +
		"2a52b6ae0c995395fb"
	certEmptyHex = "00000000"

	// CertificateVerify test cases
	certVerifyValidIn = certificateVerifyBody{
		alg: signatureAndHashAlgorithm{
			hash:      hashAlgorithmSHA256,
			signature: signatureAlgorithmECDSA,
		},
		signature: []byte{0, 0, 0, 0},
	}
	certVerifyValidHex = "0403000400000000"
)

func TestHandshakeMessageTypes(t *testing.T) {
	assertEquals(t, clientHelloBody{}.Type(), handshakeTypeClientHello)
	assertEquals(t, serverHelloBody{}.Type(), handshakeTypeServerHello)
	assertEquals(t, finishedBody{}.Type(), handshakeTypeFinished)
	assertEquals(t, encryptedExtensionsBody{}.Type(), handshakeTypeEncryptedExtensions)
	assertEquals(t, certificateBody{}.Type(), handshakeTypeCertificate)
	assertEquals(t, certificateVerifyBody{}.Type(), handshakeTypeCertificateVerify)
}

func TestClientHelloMarshalUnmarshal(t *testing.T) {
	chValid, _ := hex.DecodeString(chValidHex)
	chOverflow, _ := hex.DecodeString(chOverflowHex)

	// Test correctness of handshake type
	assertEquals(t, (clientHelloBody{}).Type(), handshakeTypeClientHello)

	// Test successful marshal
	out, err := chValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid ClientHello")
	assertByteEquals(t, out, chValid)

	// Test marshal failure on empty ciphersuites
	chValidIn.cipherSuites = []cipherSuite{}
	out, err = chValidIn.Marshal()
	assertError(t, err, "Marshaled a ClientHello with no CipherSuites")
	chValidIn.cipherSuites = chCipherSuites

	// Test marshal failure on too many ciphersuites
	tooManyCipherSuites := make([]cipherSuite, maxCipherSuites+1)
	for i := range tooManyCipherSuites {
		tooManyCipherSuites[i] = cipherSuite(0x0001)
	}
	chValidIn.cipherSuites = tooManyCipherSuites
	out, err = chValidIn.Marshal()
	assertError(t, err, "Marshaled a ClientHello with too many CipherSuites")
	chValidIn.cipherSuites = chCipherSuites

	// Test marshal failure on extension list marshal failure
	chValidIn.extensions = extListTooLongIn
	out, err = chValidIn.Marshal()
	assertError(t, err, "Marshaled a ClientHello with bad extensions")
	chValidIn.extensions = extListValidIn

	// Test successful unmarshal
	var ch clientHelloBody
	read, err := ch.Unmarshal(chValid)
	assertNotError(t, err, "Failed to unmarshal a valid ClientHello")
	assertEquals(t, read, len(chValid))
	assertDeepEquals(t, ch, chValidIn)

	// Test unmarshal failure on too-short ClientHello
	_, err = ch.Unmarshal(chValid[:fixedClientHelloBodyLen-1])
	assertError(t, err, "Unmarshaled a ClientHello below the min length")

	// Test unmarshal failure on wrong version
	chValid[1] -= 1
	_, err = ch.Unmarshal(chValid)
	assertError(t, err, "Unmarshaled a ClientHello with the wrong version")
	chValid[1] += 1

	// Test unmarshal failure on non-empty session ID
	chValid[34] = 0x04
	_, err = ch.Unmarshal(chValid)
	assertError(t, err, "Unmarshaled a ClientHello with non-empty session ID")
	chValid[34] = 0x00

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
	chLen, err = ch.Unmarshal(chOverflow)
	assertError(t, err, "Unmarshaled a ClientHello with invalid extensions")
}

func TestServerHelloMarshalUnmarshal(t *testing.T) {
	shValid, _ := hex.DecodeString(shValidHex)
	shEmpty, _ := hex.DecodeString(shEmptyHex)
	shOverflow, _ := hex.DecodeString(shOverflowHex)

	// Test correctness of handshake type
	assertEquals(t, (serverHelloBody{}).Type(), handshakeTypeServerHello)

	// Test successful marshal
	out, err := shValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid ServerHello")
	assertByteEquals(t, out, shValid)

	// Test successful marshal with no extensions present
	out, err = shEmptyIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid ServerHello with no extensions")
	assertByteEquals(t, out, shEmpty)

	// Test marshal failure on extension list marshal failure
	shValidIn.extensions = extListTooLongIn
	out, err = shValidIn.Marshal()
	assertError(t, err, "Marshaled a ServerHello with bad extensions")
	shValidIn.extensions = extListValidIn

	// Test successful unmarshal
	var sh serverHelloBody
	read, err := sh.Unmarshal(shValid)
	assertNotError(t, err, "Failed to unmarshal a valid ServerHello")
	assertEquals(t, read, len(shValid))
	assertDeepEquals(t, sh, shValidIn)

	// Test successful unmarshal with no extensions present
	read, err = sh.Unmarshal(shEmpty)
	assertNotError(t, err, "Failed to unmarshal a valid ServerHello")
	assertEquals(t, read, len(shEmpty))
	assertByteEquals(t, sh.random[:], shEmptyIn.random[:])
	assertEquals(t, sh.cipherSuite, shEmptyIn.cipherSuite)
	assertEquals(t, len(sh.extensions), 0)

	// Test unmarshal failure on too-short ServerHello
	_, err = sh.Unmarshal(shValid[:fixedServerHelloBodyLen-1])
	assertError(t, err, "Unmarshaled a too-short ServerHello")

	// Test unmarshal failure on wrong version
	shValid[1] -= 1
	_, err = sh.Unmarshal(shValid)
	assertError(t, err, "Unmarshaled a ServerHello with the wrong version")
	shValid[1] += 1

	// Test unmarshal failure on extension list unmarshal failure
	_, err = sh.Unmarshal(shOverflow)
	assertError(t, err, "Unmarshaled a ServerHello with invalid extensions")
}

func TestFinishedMarshalUnmarshal(t *testing.T) {
	finValid, _ := hex.DecodeString(finValidHex)

	// Test correctness of handshake type
	assertEquals(t, (finishedBody{}).Type(), handshakeTypeFinished)

	// Test successful marshal
	out, err := finValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid Finished")
	assertByteEquals(t, out, finValid)

	// Test marshal failure on incorrect data length
	finValidIn.verifyDataLen -= 1
	out, err = finValidIn.Marshal()
	assertError(t, err, "Marshaled a Finished with the wrong data length")
	finValidIn.verifyDataLen += 1

	// Test successful unmarshal
	var fin finishedBody
	fin.verifyDataLen = len(finValid)
	read, err := fin.Unmarshal(finValid)
	assertNotError(t, err, "Failed to unmarshal a valid Finished")
	assertEquals(t, read, len(finValid))
	assertDeepEquals(t, fin, finValidIn)

	// Test unmarshal failure on insufficient data
	fin.verifyDataLen += 1
	_, err = fin.Unmarshal(finValid)
	assertError(t, err, "Unmarshaled a Finished with too little data")
	fin.verifyDataLen -= 1
}

// This one is a little brief because it is just an extensionList
func TestEncrypteExtensionsMarshalUnmarshal(t *testing.T) {
	encExtValid, _ := hex.DecodeString(encExtValidHex)

	// Test correctness of handshake type
	assertEquals(t, (encryptedExtensionsBody{}).Type(), handshakeTypeEncryptedExtensions)

	// Test successful marshal
	out, err := encExtValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid EncryptedExtensions")
	assertByteEquals(t, out, encExtValid)

	// Test successful unmarshal
	var ee encryptedExtensionsBody
	read, err := ee.Unmarshal(encExtValid)
	assertNotError(t, err, "Failed to unmarshal a valid EncryptedExtensions")
	assertEquals(t, read, len(encExtValid))
	assertDeepEquals(t, ee, encExtValidIn)
}

func TestCertificateMarshalUnmarshal(t *testing.T) {
	// Create a couple of certificates and manually encode
	certValid, _ := hex.DecodeString(certValidHex)
	certEmpty, _ := hex.DecodeString(certEmptyHex)
	cert1Bytes, _ := hex.DecodeString(cert1Hex)
	cert2Bytes, _ := hex.DecodeString(cert2Hex)
	cert1, _ := x509.ParseCertificate(cert1Bytes)
	cert2, _ := x509.ParseCertificate(cert2Bytes)
	certValidIn.certificateList = []*x509.Certificate{cert1, cert2}

	// Test correctness of handshake type
	assertEquals(t, (certificateBody{}).Type(), handshakeTypeCertificate)

	// Test successful marshal
	out, err := certValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid Certificate")
	assertByteEquals(t, out, certValid)

	// Test marshal failure on context too long
	originalContext := certValidIn.certificateRequestContext
	certValidIn.certificateRequestContext = bytes.Repeat([]byte{0}, maxCertRequestContextLen+1)
	out, err = certValidIn.Marshal()
	assertError(t, err, "Marshaled a Certificate with a too-long context")
	certValidIn.certificateRequestContext = originalContext

	// Test marshal failure on no raw certa
	originalRaw := cert1.Raw
	cert1.Raw = []byte{}
	out, err = certValidIn.Marshal()
	assertError(t, err, "Marshaled a Certificate with an empty cert")
	cert1.Raw = originalRaw

	// Test successful unmarshal
	cert := certificateBody{}
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

	// Test unmarshal failure on malformed certificate
	certValid[8] ^= 0xFF
	_, err = cert.Unmarshal(certValid)
	assertError(t, err, "Unmarshaled a Certificate with truncated certificates")
	certValid[8] ^= 0xFF

	// Test unmarshal failure on no certificates
	_, err = cert.Unmarshal(certEmpty)
	assertError(t, err, "Unmarshaled a Certificate with no certificates")
}

func TestCertificateVerifyMarshalUnmarshal(t *testing.T) {
	certVerifyValid, _ := hex.DecodeString(certVerifyValidHex)
	transcript := []handshakeMessageBody{&chValidIn, &shValidIn}
	privRSA, err := newSigningKey(signatureAlgorithmRSA)
	assertNotError(t, err, "failed to generate RSA private key")

	// Test correctness of handshake type
	assertEquals(t, (certificateVerifyBody{}).Type(), handshakeTypeCertificateVerify)

	// Test successful marshal
	out, err := certVerifyValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid CertificateVerify")
	assertByteEquals(t, out, certVerifyValid)

	// Test successful unmarshal
	var cv certificateVerifyBody
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

	// Test successful sign
	err = certVerifyValidIn.Sign(privRSA, transcript)
	assertNotError(t, err, "Failed to sign CertificateVerify")

	// Test sign failure on handshake marshal failure
	chValidIn.extensions = extListSingleTooLongIn
	err = certVerifyValidIn.Sign(privRSA, transcript)
	assertError(t, err, "Signed CertificateVerify despite unmarshal failure")
	chValidIn.extensions = extListValidIn

	// Test sign failure on bad hash algorithm
	certVerifyValidIn.alg.hash = hashAlgorithm(0)
	err = certVerifyValidIn.Sign(privRSA, transcript)
	assertError(t, err, "Signed CertificateVerify despite bad hash algorithm")
	certVerifyValidIn.alg.hash = hashAlgorithmSHA256

	// Test successful verify
	err = certVerifyValidIn.Sign(privRSA, transcript)
	assertNotError(t, err, "Failed to sign CertificateVerify")
	err = certVerifyValidIn.Verify(privRSA.Public(), transcript)
	assertNotError(t, err, "Failed to verify CertificateVerify")

	// Test verify failure on bad hash algorithm
	certVerifyValidIn.alg.hash = hashAlgorithm(0)
	err = certVerifyValidIn.Verify(privRSA.Public(), transcript)
	assertError(t, err, "Signed CertificateVerify despite bad hash algorithm")
	certVerifyValidIn.alg.hash = hashAlgorithmSHA256
}
