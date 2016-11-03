package mint

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
)

var (
	ecGroups    = []namedGroup{namedGroupP256, namedGroupP384, namedGroupP521}
	nonECGroups = []namedGroup{namedGroupFF2048, namedGroupFF3072, namedGroupFF4096,
		namedGroupFF6144, namedGroupFF8192, namedGroupX25519}
	dhGroups = append(ecGroups, nonECGroups...)

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
	hkdfEncodedLabelHex      = "002a" + "0d" + hex.EncodeToString([]byte("TLS 1.3, "+hkdfLabel)) + "20" + hkdfHashHex
	hkdfExpandLabelOutputHex = "474de877d26b9e14ba50d91657bdf8bdb0fb7152f0ef8d908bb68eb697bb64c6bf2f2d81fa987e86bc32"
)

func TestNewKeyShare(t *testing.T) {
	// Test success cases
	for _, group := range ecGroups {
		// priv is opaque, so there's nothing we can do to test besides use
		pub, priv, err := newKeyShare(group)
		assertNotError(t, err, "Failed to generate new key pair")
		assertNotNil(t, priv, "Private key is nil")
		assertEquals(t, len(pub), keyExchangeSizeFromNamedGroup(group))

		crv := curveFromNamedGroup(group)
		x, y := elliptic.Unmarshal(crv, pub)
		assert(t, x != nil && y != nil, "Public key failed to unmarshal")
		assert(t, crv.Params().IsOnCurve(x, y), "Public key not on curve")
	}

	for _, group := range nonECGroups {
		priv, pub, err := newKeyShare(group)
		assertNotError(t, err, "Failed to generate new key pair")
		assertNotNil(t, priv, "Private key is nil")
		assertEquals(t, len(pub), keyExchangeSizeFromNamedGroup(group))
	}

	// Test failure case for an elliptic curve key generation failure
	originalPRNG := prng
	prng = bytes.NewReader(nil)
	_, _, err := newKeyShare(namedGroupP256)
	assertError(t, err, "Generated an EC key with no entropy")
	prng = originalPRNG

	// Test failure case for an finite field key generation failure
	originalPRNG = prng
	prng = bytes.NewReader(nil)
	_, _, err = newKeyShare(namedGroupFF2048)
	assertError(t, err, "Generated a FF key with no entropy")
	prng = originalPRNG

	// Test failure case for an X25519 key generation failure
	originalPRNG = prng
	prng = bytes.NewReader(nil)
	_, _, err = newKeyShare(namedGroupX25519)
	assertError(t, err, "Generated an X25519 key with no entropy")
	prng = originalPRNG

	// Test failure case for an unknown group
	_, _, err = newKeyShare(namedGroupUnknown)
	assertError(t, err, "Generated a key for an unsupported group")
}

func TestKeyAgreement(t *testing.T) {
	shortKeyPub, _ := hex.DecodeString(shortKeyPubHex)
	shortKeyPriv, _ := hex.DecodeString(shortKeyPrivHex)

	// Test success cases
	for _, group := range dhGroups {
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

	// Test failure for a too-short ffdh public key
	_, err = keyAgreement(namedGroupFF2048, shortKeyPub[:5], shortKeyPriv)
	assertError(t, err, "Performed key agreement with a truncated public key")

	// Test failure for a too-short X25519 public key
	_, err = keyAgreement(namedGroupX25519, shortKeyPub[:5], shortKeyPriv)
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

func TestSignVerify(t *testing.T) {
	data := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
		20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
		30, 31}
	context := "TLS 1.3, test"

	privRSA, err := newSigningKey(signatureAlgorithmRSA)
	assertNotError(t, err, "failed to generate RSA private key")
	privECDSA, err := newSigningKey(signatureAlgorithmECDSA)
	assertNotError(t, err, "failed to generate RSA private key")

	// Test successful signing
	sigAlgRSA, sigRSA, err := sign(crypto.SHA256, privRSA, data, context)
	assertNotError(t, err, "Failed to generate RSA signature")
	assertEquals(t, sigAlgRSA, signatureAlgorithmRSA)

	originalAllowPKCS1 := allowPKCS1
	allowPKCS1 = false
	sigAlgRSAPSS, sigRSAPSS, err := sign(crypto.SHA256, privRSA, data, context)
	assertNotError(t, err, "Failed to generate RSA-PSS signature")
	assertEquals(t, sigAlgRSAPSS, signatureAlgorithmRSAPSS)
	allowPKCS1 = originalAllowPKCS1

	sigAlgECDSA, sigECDSA, err := sign(crypto.SHA256, privECDSA, data, context)
	assertNotError(t, err, "Failed to generate ECDSA signature")
	assertEquals(t, sigAlgECDSA, signatureAlgorithmECDSA)

	// Test successful verification
	algRSA := signatureAndHashAlgorithm{hashAlgorithmSHA256, signatureAlgorithmRSA}
	err = verify(algRSA, privRSA.Public(), data, context, sigRSA)
	assertNotError(t, err, "Failed to verify a valid RSA-PSS signature")

	originalAllowPKCS1 = allowPKCS1
	allowPKCS1 = false
	algRSAPSS := signatureAndHashAlgorithm{hashAlgorithmSHA256, signatureAlgorithmRSAPSS}
	err = verify(algRSAPSS, privRSA.Public(), data, context, sigRSAPSS)
	assertNotError(t, err, "Failed to verify a valid RSA-PSS signature")
	allowPKCS1 = originalAllowPKCS1

	algECDSA := signatureAndHashAlgorithm{hashAlgorithmSHA256, signatureAlgorithmECDSA}
	err = verify(algECDSA, privECDSA.Public(), data, context, sigECDSA)
	assertNotError(t, err, "Failed to verify a valid ECDSA signature")

	// Test RSA verify failure on bad algorithm
	originalAllowPKCS1 = allowPKCS1
	allowPKCS1 = false
	err = verify(algRSA, privRSA.Public(), data, context, sigRSA)
	assertError(t, err, "Verified RSA with something other than PSS")
	allowPKCS1 = originalAllowPKCS1

	err = verify(algECDSA, privRSA.Public(), data, context, sigRSA)
	assertError(t, err, "Verified RSA with a non-RSA algorithm")

	// Test ECDSA verify failure on bad algorithm
	err = verify(algRSAPSS, privECDSA.Public(), data, context, sigECDSA)
	assertError(t, err, "Verified ECDSA with a bad algorithm")

	// Test ECDSA verify failure on ASN.1 unmarshal failure
	err = verify(algECDSA, privECDSA.Public(), data, context, sigECDSA[:8])
	assertError(t, err, "Verified ECDSA with a bad ASN.1")

	// Test ECDSA verify failure on trailing data
	err = verify(algECDSA, privECDSA.Public(), data, context, append(sigECDSA, data...))
	assertError(t, err, "Verified ECDSA with a trailing ASN.1")

	// Test ECDSA verify failure on zero / negative values
	zeroSigIn := ecdsaSignature{big.NewInt(0), big.NewInt(0)}
	zeroSig, err := asn1.Marshal(zeroSigIn)
	err = verify(algECDSA, privECDSA.Public(), data, context, zeroSig)
	assertError(t, err, "Verified ECDSA with zero signature")

	// Test ECDSA verify failure on signature validation failure
	sigECDSA[7] ^= 0xFF
	err = verify(algECDSA, privECDSA.Public(), data, context, sigECDSA)
	assertError(t, err, "Verified ECDSA with corrupted signature")
	sigECDSA[7] ^= 0xFF

	// Test verify failure on unknown public key type
	err = verify(algECDSA, struct{}{}, data, context, sigECDSA)
	assertError(t, err, "Verified with invalid public key type")
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
			TLS_AES_128_GCM_SHA256,
		},
	}

	serverHelloContextIn = &serverHelloBody{
		cipherSuite: TLS_AES_128_GCM_SHA256,
	}

	certificateContextIn = &certificateBody{
		certificateRequestContext: []byte{},
		certificateList: []certificateEntry{
			{certData: cert1},
			{certData: cert2},
		},
	}

	certificateVerifyContextIn = &certificateVerifyBody{
		alg:       signatureAndHashAlgorithm{hash: hashAlgorithmSHA256, signature: signatureAlgorithmRSA},
		signature: random(64),
	}

	dhSecretIn  = random(32)
	pskSecretIn = random(32)
)

func keySetEmpty(k keySet) bool {
	return len(k.key) == 0 && len(k.iv) == 0
}

func TestCryptoContext(t *testing.T) {
	rand.Reader.Read(clientHelloContextIn.random[:])
	rand.Reader.Read(serverHelloContextIn.random[:])

	clientHelloContextIn.extensions.Add(&supportedGroupsExtension{
		groups: []namedGroup{namedGroupP256, namedGroupP521},
	})
	clientHelloContextIn.extensions.Add(&signatureAlgorithmsExtension{
		algorithms: []signatureAndHashAlgorithm{
			signatureAndHashAlgorithm{hash: hashAlgorithmSHA256, signature: signatureAlgorithmRSA},
			signatureAndHashAlgorithm{hash: hashAlgorithmSHA256, signature: signatureAlgorithmECDSA},
		},
	})
	clientHelloContextIn.extensions.Add(&keyShareExtension{
		handshakeType: handshakeTypeClientHello,
		shares: []keyShareEntry{
			keyShareEntry{Group: namedGroupP256, KeyExchange: random(keyExchangeSizeFromNamedGroup(namedGroupP256))},
			keyShareEntry{Group: namedGroupP521, KeyExchange: random(keyExchangeSizeFromNamedGroup(namedGroupP521))},
		},
	})

	serverHelloContextIn.extensions.Add(&keyShareExtension{
		handshakeType: handshakeTypeServerHello,
		shares: []keyShareEntry{
			keyShareEntry{Group: namedGroupP521, KeyExchange: random(keyExchangeSizeFromNamedGroup(namedGroupP521))},
		},
	})

	chm, err := handshakeMessageFromBody(clientHelloContextIn)
	assertNotError(t, err, "Error in prep [0]")
	shm, err := handshakeMessageFromBody(serverHelloContextIn)
	assertNotError(t, err, "Error in prep [1]")
	cm, err := handshakeMessageFromBody(certificateContextIn)
	assertNotError(t, err, "Error in prep [2]")
	cvm, err := handshakeMessageFromBody(certificateVerifyContextIn)
	assertNotError(t, err, "Error in prep [3]")

	alg := signatureAndHashAlgorithm{hash: hashAlgorithmSHA256, signature: signatureAlgorithmECDSA}
	priv, err := newSigningKey(signatureAlgorithmECDSA)
	assertNotError(t, err, "Failed to generate key pair")
	cert, err := newSelfSigned("example.com", alg, priv)
	assertNotError(t, err, "Failed to sign certificate")
	certificateContextIn.certificateList[0].certData = cert

	// BEGIN TESTS

	// Test successful init
	ctx := cryptoContext{}
	err = ctx.init(serverHelloContextIn.cipherSuite, chm, pskSecretIn, false)
	assertNotError(t, err, "Failed to init context")
	assertEquals(t, ctx.suite, serverHelloContextIn.cipherSuite)
	assertNotNil(t, ctx.params, "Params not populated")
	assertNotNil(t, ctx.zero, "Zero not populated")
	assertByteEquals(t, ctx.pskSecret, pskSecretIn)
	assertNotNil(t, ctx.earlySecret, "Early secret not populated")
	assertNotNil(t, ctx.binderKey, "Binder key not populated")
	assertNotNil(t, ctx.handshakeHash, "Failed to init handshake hash")
	assertNotNil(t, ctx.earlyTrafficSecret, "Failed to set early traffic secret")
	assertNotNil(t, ctx.earlyExporterSecret, "Failed to set early exporter secret")
	assertNotNil(t, ctx.clientEarlyTrafficKeys, "Failed to set early traffic keys")

	// Test successful init with nil PSK secret
	ctx = cryptoContext{}
	err = ctx.init(TLS_AES_128_GCM_SHA256, chm, nil, false)
	assertNotError(t, err, "Failed to init context with nil PSK secret")
	assertByteEquals(t, ctx.pskSecret, ctx.zero)

	// Test init failure on usupported ciphersuite
	ctx = cryptoContext{}
	err = ctx.init(TLS_CHACHA20_POLY1305_SHA256, chm, nil, false)
	assertError(t, err, "Init'ed context with an unsupported ciphersuite")

	// Test successful updateWithServerHello
	ctx = cryptoContext{}
	_ = ctx.init(serverHelloContextIn.cipherSuite, chm, pskSecretIn, false)
	err = ctx.updateWithServerHello(shm, dhSecretIn)
	assertNotError(t, err, "Failed to update context")
	assertNotNil(t, ctx.h2, "Failed to set handshake hash (2)")
	assertByteEquals(t, ctx.dhSecret, dhSecretIn)
	assertNotNil(t, ctx.handshakeSecret, "Failed to set handshake secret")
	assertNotNil(t, ctx.clientHandshakeTrafficSecret, "Failed to set client handshake traffic secret")
	assertNotNil(t, ctx.serverHandshakeTrafficSecret, "Failed to set server handshake traffic secret")
	assertNotNil(t, ctx.clientHandshakeKeys, "Failed to set client handshake keys")
	assertNotNil(t, ctx.serverHandshakeKeys, "Failed to set server handshake keys")
	assertNotNil(t, ctx.masterSecret, "Failed to set master secret")
	assertNotNil(t, ctx.clientFinishedKey, "Failed to set client finished key")
	assertNotNil(t, ctx.serverFinishedKey, "Failed to set server finished key")

	// Test successful updateWithServerHello with nil dhSecret
	ctx = cryptoContext{}
	_ = ctx.init(TLS_AES_128_GCM_SHA256, chm, pskSecretIn, false)
	err = ctx.updateWithServerHello(shm, nil)
	assertNotError(t, err, "Failed to update context with nil DH secret")
	assertByteEquals(t, ctx.dhSecret, ctx.zero)

	// Test successful updateWithServerFirstFlight
	ctx = cryptoContext{}
	_ = ctx.init(TLS_AES_128_GCM_SHA256, chm, pskSecretIn, false)
	_ = ctx.updateWithServerHello(shm, nil)
	err = ctx.updateWithServerFirstFlight([]*handshakeMessage{cm, cvm})
	assertNotError(t, err, "Failed to update context")
	assertNotNil(t, ctx.h3, "Failed to set handshake hash (3)")
	assertNotNil(t, ctx.h4, "Failed to set handshake hash (4)")
	assertNotNil(t, ctx.serverFinishedData, "Failed to set server finished data")
	assertNotNil(t, ctx.serverFinished, "Failed to set server finished message")
	assertNotNil(t, ctx.clientTrafficSecret, "Failed to set client traffic secret")
	assertNotNil(t, ctx.serverTrafficSecret, "Failed to set server traffic secret")
	assertNotNil(t, ctx.clientTrafficKeys, "Failed to set client traffic keys")
	assertNotNil(t, ctx.serverTrafficKeys, "Failed to set server traffic keys")
	assertNotNil(t, ctx.exporterSecret, "Failed to set exporter secret")

	// Test successful updateWithClientSecondFlight
	// TODO: Use a more realistic second flight
	ctx = cryptoContext{}
	_ = ctx.init(TLS_AES_128_GCM_SHA256, chm, pskSecretIn, false)
	_ = ctx.updateWithServerHello(shm, dhSecretIn)
	_ = ctx.updateWithServerFirstFlight([]*handshakeMessage{cm, cvm})
	err = ctx.updateWithClientSecondFlight([]*handshakeMessage{cm})
	assertNotError(t, err, "Failed to update context")
	assertNotNil(t, ctx.h5, "Failed to set handshake hash (5)")
	assertNotNil(t, ctx.h6, "Failed to set handshake hash (6)")
	assertNotNil(t, ctx.clientFinishedData, "Failed to set client finished data")
	assertNotNil(t, ctx.clientFinished, "Failed to set client finished message")
	assertNotNil(t, ctx.resumptionSecret, "Failed to set resumption secret")

	// Test key update
	oldClientKeys := ctx.clientTrafficKeys
	oldServerKeys := ctx.serverTrafficKeys
	err = ctx.updateKeys()
	newClientKeys := ctx.clientTrafficKeys
	newServerKeys := ctx.serverTrafficKeys
	assertNotError(t, err, "UpdateKeys failed")
	assert(t, !bytes.Equal(oldClientKeys.key, newClientKeys.key), "Client write key didn't change")
	assert(t, !bytes.Equal(oldServerKeys.key, newServerKeys.key), "Server write key didn't change")
	assert(t, !bytes.Equal(oldClientKeys.iv, newClientKeys.iv), "Client write IV didn't change")
	assert(t, !bytes.Equal(oldServerKeys.iv, newServerKeys.iv), "Server write IV didn't change")

	// Test that the order of operations is enforced
	ctx = cryptoContext{}
	_ = ctx.init(TLS_AES_128_GCM_SHA256, chm, pskSecretIn, false)

	ctx.state = ctxStateUnknown
	err = ctx.updateWithServerHello(shm, dhSecretIn)
	assertError(t, err, "Allowed updateWithServerHello in wrong state")
	ctx.state = ctxStateClientHello
	err = ctx.updateWithServerHello(shm, dhSecretIn)
	assertNotError(t, err, "Rejected updateWithServerHello in proper state")

	ctx.state = ctxStateUnknown
	err = ctx.updateWithServerFirstFlight([]*handshakeMessage{cm, cvm})
	assertError(t, err, "Allowed updateWithServerFirstFlight in wrong state")
	ctx.state = ctxStateServerHello
	err = ctx.updateWithServerFirstFlight([]*handshakeMessage{cm, cvm})
	assertNotError(t, err, "Rejected updateWithServerFirstFlight in proper state")

	ctx.state = ctxStateUnknown
	err = ctx.updateWithClientSecondFlight([]*handshakeMessage{cm})
	assertError(t, err, "Allowed updateWithServerFirstFlight in wrong state")
	ctx.state = ctxStateServerFirstFlight
	err = ctx.updateWithClientSecondFlight([]*handshakeMessage{cm})
	assertNotError(t, err, "Rejected updateWithServerFirstFlight in proper state")

	ctx.state = ctxStateUnknown
	err = ctx.updateKeys()
	assertError(t, err, "Allowed UpdateKeys in wrong state")

}
