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

func sign(hash crypto.Hash, privateKey crypto.Signer, digest []byte) (signatureAlgorithm, []byte, error) {
	var opts crypto.SignerOpts
	var sigAlg signatureAlgorithm

	switch privateKey.(type) {
	case *rsa.PrivateKey:
		sigAlg = signatureAlgorithmRSAPSS
		opts = &rsa.PSSOptions{SaltLength: hash.Size(), Hash: hash}
	case *ecdsa.PrivateKey:
		sigAlg = signatureAlgorithmECDSA
	}

	sig, err := privateKey.Sign(prng, digest, opts)
	return sigAlg, sig, err
}

func verify(alg signatureAndHashAlgorithm, publicKey crypto.PublicKey, digest []byte, sig []byte) error {
	hash := hashMap[alg.hash]

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if alg.signature != signatureAlgorithmRSAPSS {
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

func hkdfEncodeLabel(labelIn string, hashValue []byte, outLen int) []byte {
	label := "TLS 1.3," + labelIn

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
	return hkdfExpand(hash, secret, hkdfEncodeLabel(label, hashValue, outLen), outLen)
}

const (
	labelXSS            = "expanded static secret"
	labelXES            = "expanded ephemeral secret"
	labelTrafficSecret  = "traffic secret"
	labelServerFinished = "server finished"
	labelClientFinished = "client finished"

	phaseEarlyHandshake = "early handshake key expansion"
	phaseEarlyData      = "early application data key expansion"
	phaseHandshake      = "handshake key expansion"
	phaseApplication    = "application data key expansion"

	purposeClientWriteKey = "client write key"
	purposeServerWriteKey = "server write key"
	purposeClientWriteIV  = "client write IV"
	purposeServerWriteIV  = "server write IV"
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

func (c *cryptoContext) addToTranscript(body handshakeMessageBody) error {
	msg, err := handshakeMessageFromBody(body)
	if err != nil {
		return err
	}
	c.transcript = append(c.transcript, msg)
	return nil
}

func (c *cryptoContext) marshalTranscript() []byte {
	data := []byte{}
	for _, msg := range c.transcript {
		data = append(data, msg.Marshal()...)
	}
	return data
}

func (c *cryptoContext) makeTrafficKeys(secret []byte, phase string, context []byte) keySet {
	return keySet{
		clientWriteKey: hkdfExpandLabel(c.params.hash, secret, phase+", "+purposeClientWriteKey, context, c.params.keyLen),
		serverWriteKey: hkdfExpandLabel(c.params.hash, secret, phase+", "+purposeServerWriteKey, context, c.params.keyLen),
		clientWriteIV:  hkdfExpandLabel(c.params.hash, secret, phase+", "+purposeClientWriteIV, context, c.params.ivLen),
		serverWriteIV:  hkdfExpandLabel(c.params.hash, secret, phase+", "+purposeServerWriteIV, context, c.params.ivLen),
	}
}

func (c *cryptoContext) Init(ch *clientHelloBody, sh *serverHelloBody, SS, ES []byte, suite cipherSuite) error {
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
	err := c.addToTranscript(ch)
	if err != nil {
		return err
	}
	err = c.addToTranscript(sh)
	if err != nil {
		return err
	}

	// Compute xSS, xES = HKDF-Extract(0, ES)
	c.SS = make([]byte, len(SS))
	c.ES = make([]byte, len(ES))
	copy(c.ES, ES)
	copy(c.SS, ES)
	c.xSS = hkdfExtract(c.params.hash, nil, c.SS)
	c.xES = hkdfExtract(c.params.hash, nil, c.ES)

	// Compute handshakeKeys
	context := c.marshalTranscript()
	c.handshakeKeys = c.makeTrafficKeys(c.xES, phaseHandshake, context)

	c.initialized = true
	return nil
}

func (c *cryptoContext) Update(bodies []handshakeMessageBody) error {
	if !c.initialized {
		return fmt.Errorf("tls.updatecontext: Called on uninitialized context")
	}

	// Add messages to transcript
	for _, msg := range bodies {
		err := c.addToTranscript(msg)
		if err != nil {
			return err
		}
	}
	handshakeSoFar := c.marshalTranscript()

	// Compute handshake hash
	h := c.params.hash.New()
	h.Write(handshakeSoFar)
	handshakeHash := h.Sum(nil)

	// Compute mSS, mES = HKDF-Expand-Label(xSS, label, handshake_hash, L)
	L := c.params.hash.Size()
	c.mSS = hkdfExpandLabel(c.params.hash, c.xSS, labelXSS, handshakeHash, L)
	c.mES = hkdfExpandLabel(c.params.hash, c.xSS, labelXES, handshakeHash, L)

	// Compute master_secret, traffic_secret_0
	c.masterSecret = hkdfExtract(c.params.hash, c.mSS, c.mES)

	// Compute traffic_secret_0
	c.trafficSecret = hkdfExpandLabel(c.params.hash, c.masterSecret, labelTrafficSecret, handshakeHash, L)

	// Compute client and server Finished keys
	c.serverFinishedKey = hkdfExpandLabel(c.params.hash, c.masterSecret, labelServerFinished, []byte{}, L)
	c.clientFinishedKey = hkdfExpandLabel(c.params.hash, c.masterSecret, labelClientFinished, []byte{}, L)

	// Compute ServerFinished and add to transcript
	serverFinishedMAC := hmac.New(c.params.hash.New, c.serverFinishedKey)
	serverFinishedMAC.Write(handshakeSoFar)
	c.serverFinishedData = serverFinishedMAC.Sum(nil)
	c.serverFinished = &finishedBody{
		verifyDataLen: L,
		verifyData:    c.serverFinishedData,
	}
	c.addToTranscript(c.serverFinished)

	// Compute client_finished_key
	handshakeThroughFinished := c.marshalTranscript()
	clientFinishedMAC := hmac.New(c.params.hash.New, c.clientFinishedKey)
	clientFinishedMAC.Write(handshakeSoFar)
	c.clientFinishedData = clientFinishedMAC.Sum(nil)
	c.clientFinished = &finishedBody{
		verifyDataLen: L,
		verifyData:    c.clientFinishedData,
	}

	// application_key_0
	c.applicationKeys = c.makeTrafficKeys(c.trafficSecret, phaseApplication, handshakeThroughFinished)

	return nil
}

func (c *cryptoContext) UpdateKeys() {
	// XXX: Assumes that nothing further has been added after the ServerFinished
	handshakeThroughFinished := c.marshalTranscript()
	c.trafficSecret = hkdfExpandLabel(c.params.hash, c.trafficSecret, labelTrafficSecret, []byte{}, c.params.hash.Size())
	c.applicationKeys = c.makeTrafficKeys(c.trafficSecret, phaseApplication, handshakeThroughFinished)
}
