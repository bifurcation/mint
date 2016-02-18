package mint

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

var (
	ecGroups = []namedGroup{namedGroupP256, namedGroupP384, namedGroupP521}

	shortKeyPubHex = "04e9f6076620ddf6a24e4398162057eccd3077892f046b412" +
		"0ffcb9fa31cdfd385c8727b222f9a6091e442e48f32ba145" +
		"bd3d68c0631b0ed8faf298c40c404bf59"
	shortKeyPrivHex = "6f28e305a0975ead3b95c228082adcae852fca6af0c9385f670531657966cd6a"

	// Test vectors from RFC 5869
	hkdfSaltHex              = "000102030405060708090a0b0c"
	hkdfInputHex             = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
	hkdfInfoHex              = "f0f1f2f3f4f5f6f7f8f9"
	hkdfExtractOutputHex     = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
	hkdfExtractZeroOutputHex = "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
	hkdfExpandOutputHex      = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	hkdfExpandLen            = 42
	hkdfLabel                = "test"
	hkdfHashHex              = "f9a54250131c827542664bcad131b87c09cdd92f0d5f84db3680ee4c0c0f8ed6" // random
	hkdfEncodedLabelHex      = "002a" + "0c" + hex.EncodeToString([]byte("TLS 1.3,"+hkdfLabel)) + "20" + hkdfHashHex
	hkdfExpandLabelOutputHex = "cca90009033b529a7fd768fc49e111aacb04dd4f86f309ed4a7faf4c91ee14bda45f4f1d300c3ec01ab2"
)

func TestNewKeyShare(t *testing.T) {
	// Test success cases for elliptic curve groups
	for _, group := range ecGroups {
		// priv is opaque, so there's nothing we can do to test besides use
		pub, _, err := newKeyShare(group)
		assertNotError(t, err, "Failed to generate new key pair")

		crv := curveFromNamedGroup(group)
		x, y := elliptic.Unmarshal(crv, pub)
		assert(t, x != nil && y != nil, "Public key failed to unmarshal")
		assert(t, crv.Params().IsOnCurve(x, y), "Public key not on curve")
	}

	// Test failure case for an elliptic curve key generation failure
	originalPRNG := prng
	prng = bytes.NewReader(nil)
	_, _, err := newKeyShare(namedGroupP256)
	assertError(t, err, "Generated a key with no entropy")
	prng = originalPRNG

	// Test failure case for an unknown group
	_, _, err = newKeyShare(namedGroupUnknown)
	assertError(t, err, "Generated a key for an unsupported group")
}

func TestKeyAgreement(t *testing.T) {
	shortKeyPub, _ := hex.DecodeString(shortKeyPubHex)
	shortKeyPriv, _ := hex.DecodeString(shortKeyPrivHex)

	// Test success cases for elliptic curve groups
	for _, group := range ecGroups {
		pubA, privA, err := newKeyShare(group)
		assertNotError(t, err, "Failed to generate new key pair (A)")
		pubB, privB, err := newKeyShare(group)
		assertNotError(t, err, "Failed to generate new key pair (B)")

		x1, err1 := keyAgreement(group, pubA, privB)
		x2, err2 := keyAgreement(group, pubB, privA)
		assertNotError(t, err1, "Key agreement failed (Ab)")
		assertNotError(t, err2, "Key agreement failed (aB)")
		assertByteEquals(t, x1, x2)
	}

	// Test that a short elliptic curve point is properly padded
	// shortKey* have been chosen to produce a point with an X coordinate that
	// has a leading zero
	curveSize := len(curveFromNamedGroup(namedGroupP256).Params().P.Bytes())
	x, err := keyAgreement(namedGroupP256, shortKeyPub, shortKeyPriv)
	assertNotError(t, err, "Failed to complete short key agreement")
	assertEquals(t, len(x), curveSize)

	// Test failure case for a too-short public key
	_, err = keyAgreement(namedGroupP256, shortKeyPub[:5], shortKeyPriv)
	assertError(t, err, "Performed key agreement with a truncated public key")

	// Test failure case for an unknown group
	_, err = keyAgreement(namedGroupUnknown, shortKeyPub, shortKeyPriv)
	assertError(t, err, "Performed key agreement with an unsupported group")
}

func TestNewSigningKey(t *testing.T) {
	// Test RSA success
	privRSA, err := newSigningKey(signatureAlgorithmRSA)
	assertNotError(t, err, "failed to generate RSA private key")
	_, ok := privRSA.(*rsa.PrivateKey)
	assert(t, ok, "New RSA key was not actually an RSA key")

	// Test ECDSA success
	privECDSA, err := newSigningKey(signatureAlgorithmECDSA)
	assertNotError(t, err, "failed to generate RSA private key")
	_, ok = privECDSA.(*ecdsa.PrivateKey)
	assert(t, ok, "New RSA key was not actually an RSA key")

	// Test unsupported algorithm
	_, err = newSigningKey(signatureAlgorithmEdDSA)
	assertError(t, err, "Created a private key for an unsupported algorithm")
}

func TestSelfSigned(t *testing.T) {
	priv, err := newSigningKey(signatureAlgorithmECDSA)
	assertNotError(t, err, "Failed to create private key")

	// Test success
	alg := signatureAndHashAlgorithm{hashAlgorithmSHA256, signatureAlgorithmECDSA}
	cert, err := newSelfSigned("example.com", alg, priv)
	assertNotError(t, err, "Failed to sign certificate")
	assert(t, len(cert.Raw) > 0, "Certificate had empty raw value")
	assertEquals(t, cert.SignatureAlgorithm, x509AlgMap[alg.signature][alg.hash])

	// Test failure on unknown signature algorithm
	alg = signatureAndHashAlgorithm{hashAlgorithmSHA256, signatureAlgorithmRSAPSS}
	_, err = newSelfSigned("example.com", alg, priv)
	assertError(t, err, "Signed with an unsupported algorithm")

	// Test failure on certificate signing failure (due to algorithm mismatch)
	alg = signatureAndHashAlgorithm{hashAlgorithmSHA256, signatureAlgorithmRSA}
	_, err = newSelfSigned("example.com", alg, priv)
	assertError(t, err, "Signed with a mismatched algorithm")
}

func TestHKDF(t *testing.T) {
	hash := crypto.SHA256
	hkdfInput, _ := hex.DecodeString(hkdfInputHex)
	hkdfSalt, _ := hex.DecodeString(hkdfSaltHex)
	hkdfInfo, _ := hex.DecodeString(hkdfInfoHex)
	hkdfExtractOutput, _ := hex.DecodeString(hkdfExtractOutputHex)
	hkdfExtractZeroOutput, _ := hex.DecodeString(hkdfExtractZeroOutputHex)
	hkdfExpandOutput, _ := hex.DecodeString(hkdfExpandOutputHex)
	hkdfHash, _ := hex.DecodeString(hkdfHashHex)
	hkdfEncodedLabel, _ := hex.DecodeString(hkdfEncodedLabelHex)
	hkdfExpandLabelOutput, _ := hex.DecodeString(hkdfExpandLabelOutputHex)

	// Test hkdfExtract is correct with salt
	out := hkdfExtract(hash, hkdfSalt, hkdfInput)
	assertByteEquals(t, out, hkdfExtractOutput)

	// Test hkdfExtract is correct without salt
	out = hkdfExtract(hash, nil, hkdfInput)
	assertByteEquals(t, out, hkdfExtractZeroOutput)

	// Test hkdfExpand is correct
	out = hkdfExpand(hash, hkdfExtractOutput, hkdfInfo, hkdfExpandLen)
	assertByteEquals(t, out, hkdfExpandOutput)

	// Test hkdfEncodeLabel is correct
	out = hkdfEncodeLabel(hkdfLabel, hkdfHash, hkdfExpandLen)
	assertByteEquals(t, out, hkdfEncodedLabel)

	// This is pro-forma, just for the coverage
	out = hkdfExpandLabel(hash, hkdfSalt, hkdfLabel, hkdfHash, hkdfExpandLen)
	assertByteEquals(t, out, hkdfExpandLabelOutput)
}

func random(n int) []byte {
	data := make([]byte, n)
	rand.Reader.Read(data)
	return data
}

var (
	clientHelloContextIn = &clientHelloBody{
		cipherSuites: []cipherSuite{
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	serverHelloContextIn = &serverHelloBody{
		cipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	}

	certificateContextIn = &certificateBody{
		certificateRequestContext: []byte{},
		certificateList:           make([]*x509.Certificate, 1),
	}

	certificateVerifyContextIn = &certificateVerifyBody{
		alg:       signatureAndHashAlgorithm{hash: hashAlgorithmSHA256, signature: signatureAlgorithmRSA},
		signature: random(64),
	}

	ESContextIn = random(32)
	SSContextIn = ESContextIn
)

func TestCryptoContext(t *testing.T) {
	rand.Reader.Read(clientHelloContextIn.random[:])
	rand.Reader.Read(serverHelloContextIn.random[:])

	clientHelloContextIn.extensions.Add(extensionTypeSupportedGroups, supportedGroupsExtension{
		groups: []namedGroup{namedGroupP256, namedGroupP521},
	})
	clientHelloContextIn.extensions.Add(extensionTypeSignatureAlgorithms, signatureAlgorithmsExtension{
		algorithms: []signatureAndHashAlgorithm{
			signatureAndHashAlgorithm{hash: hashAlgorithmSHA256, signature: signatureAlgorithmRSA},
			signatureAndHashAlgorithm{hash: hashAlgorithmSHA256, signature: signatureAlgorithmECDSA},
		},
	})
	clientHelloContextIn.extensions.Add(extensionTypeKeyShare, keyShareExtension{
		roleIsServer: false,
		shares: []keyShare{
			keyShare{group: namedGroupP256, keyExchange: random(keyExchangeSizeFromNamedGroup(namedGroupP256))},
			keyShare{group: namedGroupP521, keyExchange: random(keyExchangeSizeFromNamedGroup(namedGroupP521))},
		},
	})

	serverHelloContextIn.extensions.Add(extensionTypeKeyShare, keyShareExtension{
		roleIsServer: true,
		shares: []keyShare{
			keyShare{group: namedGroupP521, keyExchange: random(keyExchangeSizeFromNamedGroup(namedGroupP521))},
		},
	})

	alg := signatureAndHashAlgorithm{hash: hashAlgorithmSHA256, signature: signatureAlgorithmECDSA}
	priv, err := newSigningKey(signatureAlgorithmECDSA)
	assertNotError(t, err, "Failed to generate key pair")
	cert, err := newSelfSigned("example.com", alg, priv)
	assertNotError(t, err, "Failed to sign certificate")
	certificateContextIn.certificateList[0] = cert

	// Test successful Init
	ctx := cryptoContext{}
	err = ctx.Init(clientHelloContextIn, serverHelloContextIn, SSContextIn, ESContextIn, serverHelloContextIn.cipherSuite)
	assertNotError(t, err, "Failed to init context")
	// TODO actually test results

	// Test Init failure on usupported ciphersuite
	ctx = cryptoContext{}
	err = ctx.Init(clientHelloContextIn, serverHelloContextIn, SSContextIn, ESContextIn, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
	assertError(t, err, "Init'ed context with an unsupported ciphersuite")

	// Test Init failure on CH addToTranscript failure (i.e., marshal failure)
	ctx = cryptoContext{}
	originalSuites := clientHelloContextIn.cipherSuites
	clientHelloContextIn.cipherSuites = []cipherSuite{}
	err = ctx.Init(clientHelloContextIn, serverHelloContextIn, SSContextIn, ESContextIn, serverHelloContextIn.cipherSuite)
	assertError(t, err, "Init'ed context despite ClientHello marshal failure")
	clientHelloContextIn.cipherSuites = originalSuites

	// Test Init failure on SH addToTranscript failure (i.e., marshal failure)
	ctx = cryptoContext{}
	originalExtensions := serverHelloContextIn.extensions
	serverHelloContextIn.extensions = extListTooLongIn
	err = ctx.Init(clientHelloContextIn, serverHelloContextIn, SSContextIn, ESContextIn, serverHelloContextIn.cipherSuite)
	assertError(t, err, "Init'ed context despite ServerHello marshal failure")
	serverHelloContextIn.extensions = originalExtensions

	// TODO Test Update on un-Init'ed context
	ctx = cryptoContext{}
	err = ctx.Update([]handshakeMessageBody{certificateContextIn, certificateVerifyContextIn})
	assertError(t, err, "Allowed Update on un-Init'ed context")

	// Test succesful Update
	ctx = cryptoContext{}
	err = ctx.Init(clientHelloContextIn, serverHelloContextIn, SSContextIn, ESContextIn, serverHelloContextIn.cipherSuite)
	assertNotError(t, err, "Failed to init context before update")
	err = ctx.Update([]handshakeMessageBody{certificateContextIn, certificateVerifyContextIn})
	assertNotError(t, err, "Failed to update context")
	// TODO actually test results

	// Test Update failure on addToTranscript failure (i.e., marshal failure)
	// TODO: Figure out why this doesn't hit
	ctx = cryptoContext{}
	err = ctx.Init(clientHelloContextIn, serverHelloContextIn, SSContextIn, ESContextIn, serverHelloContextIn.cipherSuite)
	assertNotError(t, err, "Failed to init context before update failure test")
	originalContext := certificateContextIn.certificateRequestContext
	certificateContextIn.certificateRequestContext = bytes.Repeat([]byte{0}, maxCertRequestContextLen)
	err = ctx.Update([]handshakeMessageBody{certificateContextIn, certificateVerifyContextIn})
	assertNotError(t, err, "Updated context despite marshal failure")
	certificateContextIn.certificateRequestContext = originalContext

	// Test key update
	ctx.UpdateKeys()
	// TODO actually test results
}

// To test the crypto context code, we'll want to feed it a transcript.
// Let's make it as realistic as possible!
//
// Pre-computed:
// * client random
// * server random
// * client key shares
// * server key share
// * server certificate
//
// ClientHello {
//  random: [precomputed]
//  ciphersuites: [
//    TLS_ECDHE_ECDSA_WITH_AES_128_GCM,
//    TLS_ECDHE_RSA_WITH_AES_128_GCM
//  ],
//  extensions: {
//    server_name: "example.com",
//    supported_groups: [P256, P384, P512],
//    signature_algorithms: [rsa, ecdsa, rsapss],
//    key_shares: [precomputed]
//  ]
// }
//
// ServerHello {
//  random: [precomputed],
//  ciphersuite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM,
//  extensions: [
//    key_share: [precomputed]
//  ]
// }
//
// EncryptedExtensions?
//
// Certificate {
//  context: []
//  certList: [precomputed]
// }
//
// CertificateVerify{
//  [precomputed]
// }
