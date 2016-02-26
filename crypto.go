package mint

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"

	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

var prng = rand.Reader

type cipherSuiteParams struct {
	hash   crypto.Hash // Hash function
	keyLen int         // Key length in octets
	ivLen  int         // IV length in octets
}

var (
	hashMap = map[hashAlgorithm]crypto.Hash{
		hashAlgorithmSHA1:   crypto.SHA1,
		hashAlgorithmSHA256: crypto.SHA256,
		hashAlgorithmSHA384: crypto.SHA384,
		hashAlgorithmSHA512: crypto.SHA512,
	}

	cipherSuiteMap = map[cipherSuite]cipherSuiteParams{
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: cipherSuiteParams{
			hash:   crypto.SHA256,
			keyLen: 16,
			ivLen:  12,
		},
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: cipherSuiteParams{
			hash:   crypto.SHA256,
			keyLen: 16,
			ivLen:  12,
		},
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: cipherSuiteParams{
			hash:   crypto.SHA256,
			keyLen: 32,
			ivLen:  12,
		},
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: cipherSuiteParams{
			hash:   crypto.SHA256,
			keyLen: 32,
			ivLen:  12,
		},
	}

	x509AlgMap = map[signatureAlgorithm]map[hashAlgorithm]x509.SignatureAlgorithm{
		signatureAlgorithmRSA: map[hashAlgorithm]x509.SignatureAlgorithm{
			hashAlgorithmSHA1:   x509.SHA1WithRSA,
			hashAlgorithmSHA256: x509.SHA256WithRSA,
			hashAlgorithmSHA384: x509.SHA384WithRSA,
			hashAlgorithmSHA512: x509.SHA512WithRSA,
		},
		signatureAlgorithmECDSA: map[hashAlgorithm]x509.SignatureAlgorithm{
			hashAlgorithmSHA1:   x509.ECDSAWithSHA1,
			hashAlgorithmSHA256: x509.ECDSAWithSHA256,
			hashAlgorithmSHA384: x509.ECDSAWithSHA384,
			hashAlgorithmSHA512: x509.ECDSAWithSHA512,
		},
	}

	defaultRSAKeySize = 2048
	defaultECDSACurve = elliptic.P256()
)

func curveFromNamedGroup(group namedGroup) (crv elliptic.Curve) {
	switch group {
	case namedGroupP256:
		crv = elliptic.P256()
	case namedGroupP384:
		crv = elliptic.P384()
	case namedGroupP521:
		crv = elliptic.P521()
	}
	return
}

func keyExchangeSizeFromNamedGroup(group namedGroup) (size int) {
	size = 0
	switch group {
	case namedGroupP256:
		size = 66
	case namedGroupP384:
		size = 98
	case namedGroupP521:
		size = 134
	}
	return
}

func newKeyShare(group namedGroup) (pub []byte, priv []byte, err error) {
	switch group {
	case namedGroupP256, namedGroupP384, namedGroupP521:
		var x, y *big.Int
		crv := curveFromNamedGroup(group)
		priv, x, y, err = elliptic.GenerateKey(crv, prng)
		if err != nil {
			return
		}

		pub = elliptic.Marshal(crv, x, y)
		pub = append([]byte{byte(len(pub))}, pub...)
		return

	default:
		return nil, nil, fmt.Errorf("tls.newkeyshare: Unsupported group %v", group)
	}
}

func keyAgreement(group namedGroup, pub []byte, priv []byte) ([]byte, error) {
	switch group {
	case namedGroupP256, namedGroupP384, namedGroupP521:
		pubLen := int(pub[0])
		if len(pub) != keyExchangeSizeFromNamedGroup(group) || len(pub) != pubLen+1 {
			return nil, fmt.Errorf("tls.keyagreement: Wrong public key size")
		}

		crv := curveFromNamedGroup(group)
		pubX, pubY := elliptic.Unmarshal(crv, pub[1:])
		x, _ := crv.Params().ScalarMult(pubX, pubY, priv)

		curveSize := len(crv.Params().P.Bytes())
		xBytes := x.Bytes()
		if len(xBytes) < curveSize {
			xBytes = append(bytes.Repeat([]byte{0}, curveSize-len(xBytes)), xBytes...)
		}
		return xBytes, nil

	default:
		return nil, fmt.Errorf("tls.keyagreement: Unsupported group %v", group)
	}
}

func newSigningKey(sig signatureAlgorithm) (crypto.Signer, error) {
	switch sig {
	case signatureAlgorithmRSA:
		return rsa.GenerateKey(prng, defaultRSAKeySize)
	case signatureAlgorithmECDSA:
		return ecdsa.GenerateKey(defaultECDSACurve, prng)
	default:
		return nil, fmt.Errorf("tls.newsigningkey: Unsupported signature algorithm")
	}
}

func newSelfSigned(name string, alg signatureAndHashAlgorithm, priv crypto.Signer) (*x509.Certificate, error) {
	sigAlg, ok := x509AlgMap[alg.signature][alg.hash]
	if !ok {
		return nil, fmt.Errorf("tls.selfsigned: Unknown signature algorithm")
	}

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(0xA0A0A0A0),
		SignatureAlgorithm: sigAlg,
		Subject:            pkix.Name{CommonName: name},
		DNSNames:           []string{name},
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(prng, template, template, priv.Public(), priv)
	if err != nil {
		return nil, err
	}

	// It is safe to ignore the error here because we're parsing known-good data
	cert, _ := x509.ParseCertificate(der)
	return cert, nil
}

// XXX(rlb): Copied from crypto/x509
type ecdsaSignature struct {
	R, S *big.Int
}

const (
	contextCertificateVerify = "TLS 1.3, server CertificateVerify"
)

func encodeSignatureInput(hash crypto.Hash, data []byte, context string) []byte {
	h := hash.New()
	h.Write(bytes.Repeat([]byte{0x20}, 64))
	h.Write([]byte(context))
	h.Write([]byte{0})
	h.Write(data)
	return h.Sum(nil)
}

type pkcs1Opts struct {
	hash crypto.Hash
}

func (opts pkcs1Opts) HashFunc() crypto.Hash {
	return opts.hash
}

func sign(hash crypto.Hash, privateKey crypto.Signer, data []byte, context string) (signatureAlgorithm, []byte, error) {
	var opts crypto.SignerOpts
	var sigAlg signatureAlgorithm

	log.Printf("digest to be verified: %x", data)
	digest := encodeSignatureInput(hash, data, context)
	log.Printf("digest with context: %x", digest)

	switch privateKey.(type) {
	case *rsa.PrivateKey:
		if allowPKCS1 {
			sigAlg = signatureAlgorithmRSA
			opts = &pkcs1Opts{hash: hash}
		} else {
			sigAlg = signatureAlgorithmRSAPSS
			opts = &rsa.PSSOptions{SaltLength: hash.Size(), Hash: hash}
		}
	case *ecdsa.PrivateKey:
		sigAlg = signatureAlgorithmECDSA
	}

	sig, err := privateKey.Sign(prng, digest, opts)
	return sigAlg, sig, err
}

func verify(alg signatureAndHashAlgorithm, publicKey crypto.PublicKey, data []byte, context string, sig []byte) error {
	hash := hashMap[alg.hash]

	digest := encodeSignatureInput(hash, data, context)

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if allowPKCS1 && alg.signature == signatureAlgorithmRSA {
			return rsa.VerifyPKCS1v15(pub, hash, digest, sig)
		}

		if alg.signature != signatureAlgorithmRSA && alg.signature != signatureAlgorithmRSAPSS {
			return fmt.Errorf("tls.verify: Unsupported algorithm for RSA key")
		}

		opts := &rsa.PSSOptions{SaltLength: hash.Size(), Hash: hash}
		return rsa.VerifyPSS(pub, hash, digest, sig, opts)
	case *ecdsa.PublicKey:
		if alg.signature != signatureAlgorithmECDSA {
			return fmt.Errorf("tls.verify: Unsupported algorithm for ECDSA key")
		}

		ecdsaSig := new(ecdsaSignature)
		if rest, err := asn1.Unmarshal(sig, ecdsaSig); err != nil {
			return err
		} else if len(rest) != 0 {
			return fmt.Errorf("tls.verify: trailing data after ECDSA signature")
		}
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			return fmt.Errorf("tls.verify: ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pub, digest, ecdsaSig.R, ecdsaSig.S) {
			return fmt.Errorf("tls.verify: ECDSA verification failure")
		}
		return nil
	default:
		return fmt.Errorf("tls.verify: Unsupported key type")
	}
}

// From RFC 5869
// PRK = HMAC-Hash(salt, IKM)
func hkdfExtract(hash crypto.Hash, saltIn, input []byte) []byte {
	salt := saltIn

	// if [salt is] not provided, it is set to a string of HashLen zeros
	if salt == nil {
		salt = bytes.Repeat([]byte{0}, hash.Size())
	}

	h := hmac.New(hash.New, salt)
	h.Write(input)
	return h.Sum(nil)
}

// struct HkdfLabel {
//    uint16 length;
//    opaque label<9..255>;
//    opaque hash_value<0..255>;
// };
func hkdfEncodeLabel(labelIn string, hashValue []byte, outLen int) []byte {
	label := "TLS 1.3, " + labelIn

	labelLen := len(label)
	hashLen := len(hashValue)
	hkdfLabel := make([]byte, 2+1+labelLen+1+hashLen)
	hkdfLabel[0] = byte(outLen >> 8)
	hkdfLabel[1] = byte(outLen)
	hkdfLabel[2] = byte(labelLen)
	copy(hkdfLabel[3:3+labelLen], []byte(label))
	hkdfLabel[3+labelLen] = byte(hashLen)
	copy(hkdfLabel[3+labelLen+1:], hashValue)

	return hkdfLabel
}

func hkdfExpand(hash crypto.Hash, prk, info []byte, outLen int) []byte {
	out := []byte{}
	T := []byte{}
	i := byte(1)
	for len(out) < outLen {
		block := append(T, info...)
		block = append(block, i)

		h := hmac.New(hash.New, prk)
		h.Write(block)

		T = h.Sum(nil)
		out = append(out, T...)
		i += 1
	}
	return out[:outLen]
}

func hkdfExpandLabel(hash crypto.Hash, secret []byte, label string, hashValue []byte, outLen int) []byte {
	info := hkdfEncodeLabel(label, hashValue, outLen)
	derived := hkdfExpand(hash, secret, info, outLen)

	log.Printf("HKDF Expand: label=[TLS 1.3, ] + '%s',requested length=%d\n", label, outLen)
	log.Printf("PRK [%d]: %x\n", len(secret), secret)
	log.Printf("Hash [%d]: %x\n", len(hashValue), hashValue)
	log.Printf("Info [%d]: %x\n", len(info), info)
	log.Printf("Derived key [%d]: %x\n", len(derived), derived)

	return derived
}

const (
	labelMSS            = "expanded static secret"
	labelMES            = "expanded ephemeral secret"
	labelTrafficSecret  = "traffic secret"
	labelServerFinished = "server finished"
	labelClientFinished = "client finished"

	phaseEarlyHandshake = "early handshake key expansion"
	phaseEarlyData      = "early application data key expansion"
	phaseHandshake      = "handshake key expansion"
	phaseApplication    = "application data key expansion"

	purposeClientWriteKey = "client write key"
	purposeServerWriteKey = "server write key"
	purposeClientWriteIV  = "client write iv"
	purposeServerWriteIV  = "server write iv"
)

type keySet struct {
	clientWriteKey []byte
	serverWriteKey []byte
	clientWriteIV  []byte
	serverWriteIV  []byte
}

// XXX: This might be specific to 1xRTT; we'll figure out how to adapt later
type cryptoContext struct {
	initialized bool

	suite  cipherSuite
	params cipherSuiteParams

	transcript []*handshakeMessage

	ES, SS        []byte
	xES, xSS      []byte
	handshakeKeys keySet

	mES, mSS           []byte
	masterSecret       []byte
	serverFinishedKey  []byte
	serverFinishedData []byte
	serverFinished     *finishedBody

	clientFinishedKey  []byte
	clientFinishedData []byte
	clientFinished     *finishedBody

	trafficSecret   []byte
	applicationKeys keySet
}

func (c *cryptoContext) marshalTranscript() []byte {
	data := []byte{}
	for _, msg := range c.transcript {
		data = append(data, msg.Marshal()...)
	}
	return data
}

func (c *cryptoContext) makeTrafficKeys(secret []byte, phase string, handshakeHash []byte) keySet {
	return keySet{
		clientWriteKey: hkdfExpandLabel(c.params.hash, secret, phase+", "+purposeClientWriteKey, handshakeHash, c.params.keyLen),
		serverWriteKey: hkdfExpandLabel(c.params.hash, secret, phase+", "+purposeServerWriteKey, handshakeHash, c.params.keyLen),
		clientWriteIV:  hkdfExpandLabel(c.params.hash, secret, phase+", "+purposeClientWriteIV, handshakeHash, c.params.ivLen),
		serverWriteIV:  hkdfExpandLabel(c.params.hash, secret, phase+", "+purposeServerWriteIV, handshakeHash, c.params.ivLen),
	}
}

func (c *cryptoContext) Init(ch, sh *handshakeMessage, SS, ES []byte, suite cipherSuite) error {
	// Configure based on cipherSuite
	params, ok := cipherSuiteMap[suite]
	if !ok {
		return fmt.Errorf("tls.cryptoinit: Unsupported ciphersuite")
	}
	c.suite = suite
	c.params = params

	// Set up transcript and initialize transcript hash
	c.transcript = []*handshakeMessage{}

	// Add ClientHello, ServerHello to transcript
	if ch == nil || sh == nil {
		return fmt.Errorf("tls.cryptoinit: Nil message provided")
	}
	c.transcript = append(c.transcript, []*handshakeMessage{ch, sh}...)

	// Compute xSS, xES = HKDF-Extract(0, ES)
	c.SS = make([]byte, len(SS))
	c.ES = make([]byte, len(ES))
	copy(c.ES, ES)
	copy(c.SS, ES)
	c.xSS = hkdfExtract(c.params.hash, nil, c.SS)
	c.xES = hkdfExtract(c.params.hash, nil, c.ES)

	// Compute handshakeKeys
	context := c.marshalTranscript()
	h := c.params.hash.New()
	h.Write(context)
	handshakeHash := h.Sum(nil)
	c.handshakeKeys = c.makeTrafficKeys(c.xES, phaseHandshake, handshakeHash)

	c.initialized = true
	return nil
}

func (c *cryptoContext) Update(messages []*handshakeMessage) error {
	if !c.initialized {
		return fmt.Errorf("tls.updatecontext: Called on uninitialized context")
	}

	// Add messages to transcript
	for _, msg := range messages {
		if msg == nil {
			return fmt.Errorf("tls.updatecontext: Nil message")
		}
	}
	c.transcript = append(c.transcript, messages...)
	handshakeSoFar := c.marshalTranscript()

	// Compute handshake hash
	h := c.params.hash.New()
	h.Write(handshakeSoFar)
	handshakeHash := h.Sum(nil)

	// Compute mSS, mES = HKDF-Expand-Label(xSS, label, handshake_hash, L)
	L := c.params.hash.Size()
	c.mSS = hkdfExpandLabel(c.params.hash, c.xSS, labelMSS, handshakeHash, L)
	c.mES = hkdfExpandLabel(c.params.hash, c.xSS, labelMES, handshakeHash, L)

	// Compute master_secret, traffic_secret_0
	c.masterSecret = hkdfExtract(c.params.hash, c.mSS, c.mES)

	// Compute traffic_secret_0
	c.trafficSecret = hkdfExpandLabel(c.params.hash, c.masterSecret, labelTrafficSecret, handshakeHash, L)

	// Compute client and server Finished keys
	c.serverFinishedKey = hkdfExpandLabel(c.params.hash, c.masterSecret, labelServerFinished, []byte{}, L)
	c.clientFinishedKey = hkdfExpandLabel(c.params.hash, c.masterSecret, labelClientFinished, []byte{}, L)

	// Compute ServerFinished and add to transcript
	serverFinishedMAC := hmac.New(c.params.hash.New, c.serverFinishedKey)
	serverFinishedMAC.Write(handshakeHash)
	c.serverFinishedData = serverFinishedMAC.Sum(nil)
	c.serverFinished = &finishedBody{
		verifyDataLen: L,
		verifyData:    c.serverFinishedData,
	}

	finishedMessage, err := handshakeMessageFromBody(c.serverFinished)
	if err != nil {
		return err
	}
	c.transcript = append(c.transcript, finishedMessage)

	// Compute client_finished_key and client Finished
	h.Write(finishedMessage.Marshal())
	handshakeHash = h.Sum(nil)
	log.Printf("handshake hash for client Finished: [%d] %x", len(handshakeHash), handshakeHash)

	clientFinishedMAC := hmac.New(c.params.hash.New, c.clientFinishedKey)
	clientFinishedMAC.Write(handshakeHash)
	c.clientFinishedData = clientFinishedMAC.Sum(nil)
	log.Printf("client Finished data: [%d] %x", len(handshakeHash), handshakeHash)

	c.clientFinished = &finishedBody{
		verifyDataLen: L,
		verifyData:    c.clientFinishedData,
	}

	// application_key_0
	c.applicationKeys = c.makeTrafficKeys(c.trafficSecret, phaseApplication, handshakeHash)

	return nil
}

func (c *cryptoContext) UpdateKeys() {
	// XXX: Assumes that nothing further has been added after the ServerFinished
	handshakeThroughFinished := c.marshalTranscript()
	c.trafficSecret = hkdfExpandLabel(c.params.hash, c.trafficSecret, labelTrafficSecret, []byte{}, c.params.hash.Size())
	c.applicationKeys = c.makeTrafficKeys(c.trafficSecret, phaseApplication, handshakeThroughFinished)
}
