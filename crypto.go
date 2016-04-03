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
	"time"

	// Blank includes to ensure hash support
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

var prng = rand.Reader

type handshakeMode uint8

const (
	handshakeModeUnknown handshakeMode = iota
	handshakeModePSK
	handshakeModePSKAndDH
	handshakeModeDH
)

type cipherSuiteParams struct {
	sig    signatureAlgorithm // RSA, ECDSA, or both
	mode   handshakeMode      // PSK, DH, or both
	hash   crypto.Hash        // Hash function
	keyLen int                // Key length in octets
	ivLen  int                // IV length in octets
}

var (
	hashMap = map[hashAlgorithm]crypto.Hash{
		hashAlgorithmSHA1:   crypto.SHA1,
		hashAlgorithmSHA256: crypto.SHA256,
		hashAlgorithmSHA384: crypto.SHA384,
		hashAlgorithmSHA512: crypto.SHA512,
	}

	cipherSuiteMap = map[cipherSuite]cipherSuiteParams{
		// REQUIRED
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: cipherSuiteParams{
			sig:    signatureAlgorithmECDSA,
			mode:   handshakeModeDH,
			hash:   crypto.SHA256,
			keyLen: 16,
			ivLen:  12,
		},
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: cipherSuiteParams{
			sig:    signatureAlgorithmRSA,
			mode:   handshakeModeDH,
			hash:   crypto.SHA256,
			keyLen: 16,
			ivLen:  12,
		},
		// RECOMMENDED
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: cipherSuiteParams{
			sig:    signatureAlgorithmECDSA,
			mode:   handshakeModeDH,
			hash:   crypto.SHA384,
			keyLen: 32,
			ivLen:  12,
		},
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: cipherSuiteParams{
			sig:    signatureAlgorithmRSA,
			mode:   handshakeModeDH,
			hash:   crypto.SHA384,
			keyLen: 32,
			ivLen:  12,
		},
		// OTHER
		TLS_PSK_WITH_AES_128_GCM_SHA256: cipherSuiteParams{
			mode:   handshakeModePSK,
			hash:   crypto.SHA256,
			keyLen: 16,
			ivLen:  12,
		},
		TLS_PSK_WITH_AES_256_GCM_SHA384: cipherSuiteParams{
			mode:   handshakeModePSK,
			hash:   crypto.SHA384,
			keyLen: 32,
			ivLen:  12,
		},
		TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: cipherSuiteParams{
			sig:    signatureAlgorithmRSA,
			mode:   handshakeModeDH,
			hash:   crypto.SHA256,
			keyLen: 16,
			ivLen:  12,
		},
		TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: cipherSuiteParams{
			sig:    signatureAlgorithmRSA,
			mode:   handshakeModeDH,
			hash:   crypto.SHA384,
			keyLen: 32,
			ivLen:  12,
		},
		TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256: cipherSuiteParams{
			mode:   handshakeModePSKAndDH,
			hash:   crypto.SHA256,
			keyLen: 16,
			ivLen:  12,
		},
		TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384: cipherSuiteParams{
			mode:   handshakeModePSKAndDH,
			hash:   crypto.SHA384,
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

func primeFromNamedGroup(group namedGroup) (p *big.Int) {
	switch group {
	case namedGroupFF2048:
		p = finiteFieldPrime2048
	case namedGroupFF3072:
		p = finiteFieldPrime3072
	case namedGroupFF4096:
		p = finiteFieldPrime4096
	case namedGroupFF6144:
		p = finiteFieldPrime6144
	case namedGroupFF8192:
		p = finiteFieldPrime8192
	}
	return
}

func ffdheKeyShareFromPrime(p *big.Int) (priv, pub *big.Int, err error) {
	// g = 2 for all ffdhe groups
	priv, err = rand.Int(prng, p)
	if err != nil {
		return
	}

	pub = big.NewInt(0)
	pub.Exp(big.NewInt(2), priv, p)
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

	case namedGroupFF2048, namedGroupFF3072, namedGroupFF4096,
		namedGroupFF6144, namedGroupFF8192:
		p := primeFromNamedGroup(group)
		x, X, err2 := ffdheKeyShareFromPrime(p)
		if err2 != nil {
			err = err2
			return
		}

		priv = x.Bytes()
		pub = X.Bytes()
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

	case namedGroupFF2048, namedGroupFF3072, namedGroupFF4096,
		namedGroupFF6144, namedGroupFF8192:
		p := primeFromNamedGroup(group)
		x := big.NewInt(0).SetBytes(priv)
		Y := big.NewInt(0).SetBytes(pub)
		Z := big.NewInt(0).Exp(Y, x, p)
		return Z.Bytes(), nil

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
	if len(name) == 0 {
		return nil, fmt.Errorf("tls.selfsigned: No name provided")
	}

	template := &x509.Certificate{
		SerialNumber:       big.NewInt(0xA0A0A0A0),
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(0, 0, 1),
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

	logf(logTypeCrypto, "digest to be verified: %x", data)
	digest := encodeSignatureInput(hash, data, context)
	logf(logTypeCrypto, "digest with context: %x", digest)

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
	logf(logTypeCrypto, "signature: %x", sig)
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
		i++
	}
	return out[:outLen]
}

func hkdfExpandLabel(hash crypto.Hash, secret []byte, label string, hashValue []byte, outLen int) []byte {
	info := hkdfEncodeLabel(label, hashValue, outLen)
	derived := hkdfExpand(hash, secret, info, outLen)

	logf(logTypeCrypto, "HKDF Expand: label=[TLS 1.3, ] + '%s',requested length=%d\n", label, outLen)
	logf(logTypeCrypto, "PRK [%d]: %x\n", len(secret), secret)
	logf(logTypeCrypto, "Hash [%d]: %x\n", len(hashValue), hashValue)
	logf(logTypeCrypto, "Info [%d]: %x\n", len(info), info)
	logf(logTypeCrypto, "Derived key [%d]: %x\n", len(derived), derived)

	return derived
}

const (
	labelMSS              = "expanded static secret"
	labelMES              = "expanded ephemeral secret"
	labelTrafficSecret    = "traffic secret"
	labelResumptionSecret = "resumption master secret"
	labelExporterSecret   = "exporter master secret"
	labelServerFinished   = "server finished"
	labelClientFinished   = "client finished"

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

type ctxState uint8

const (
	ctxStateNew ctxState = iota
	ctxStateInit
	ctxStateBase
	ctxStateHello
	ctxStateComplete
)

type cryptoContext struct {
	state ctxState

	suite  cipherSuite
	params cipherSuiteParams

	needKeyShare bool
	needPSK      bool

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

	trafficSecret    []byte
	resumptionSecret []byte
	exporterSecret   []byte
	applicationKeys  keySet

	// 0xRTT early data
	earlyHandshakeKeys   keySet
	earlyApplicationKeys keySet
	earlyFinishedKey     []byte
	earlyFinishedData    []byte
	earlyFinished        *finishedBody
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

func (c *cryptoContext) Init(suite cipherSuite) error {
	if c.state != ctxStateNew {
		return fmt.Errorf("tls.cryptoinit: wrong state")
	}

	// Configure based on cipherSuite
	params, ok := cipherSuiteMap[suite]
	if !ok {
		return fmt.Errorf("tls.cryptoinit: Unsupported ciphersuite")
	}
	c.suite = suite
	c.params = params

	c.state = ctxStateInit
	return nil
}

func (c *cryptoContext) ComputeEarlySecrets(SS []byte, chm *handshakeMessage) error {
	if c.state != ctxStateInit {
		return fmt.Errorf("tls.cryptobase: wrong state")
	}

	c.SS = make([]byte, len(SS))
	copy(c.SS, SS)

	c.xSS = hkdfExtract(c.params.hash, nil, c.SS)

	// XXX: Assumes ClientHello is the only message in the client's first flight,
	//      i.e., no client authentication
	c.transcript = []*handshakeMessage{chm}
	context := c.marshalTranscript()
	h := c.params.hash.New()
	h.Write(context)
	handshakeHash := h.Sum(nil)

	c.earlyHandshakeKeys = c.makeTrafficKeys(c.xSS, phaseEarlyHandshake, handshakeHash)
	c.earlyApplicationKeys = c.makeTrafficKeys(c.xSS, phaseEarlyData, handshakeHash)

	L := c.params.hash.Size()
	c.earlyFinishedKey = hkdfExpandLabel(c.params.hash, c.xSS, labelClientFinished, []byte{}, L)

	earlyFinishedMAC := hmac.New(c.params.hash.New, c.earlyFinishedKey)
	earlyFinishedMAC.Write(handshakeHash)
	c.earlyFinishedData = earlyFinishedMAC.Sum(nil)
	logf(logTypeCrypto, "client Finished data: [%d] %x", len(handshakeHash), handshakeHash)

	c.earlyFinished = &finishedBody{
		verifyDataLen: L,
		verifyData:    c.earlyFinishedData,
	}

	return nil
}

func (c *cryptoContext) ComputeBaseSecrets(dhSecret, pskSecret []byte) error {
	logf(logTypeCrypto, "dhSecret: [%d] %x", len(dhSecret), dhSecret)
	logf(logTypeCrypto, "pskSecret: [%d] %x", len(pskSecret), pskSecret)

	if c.state != ctxStateInit {
		return fmt.Errorf("tls.cryptobase: wrong state")
	}

	// Compute ES, SS
	switch c.params.mode {
	case handshakeModePSK:
		logf(logTypeHandshake, "ComputeBaseSecrets(PSK)")
		if pskSecret == nil {
			return fmt.Errorf("tls.cryptobase: PSK selected but no PSK secret provided")
		}

		c.SS = make([]byte, len(pskSecret))
		c.ES = make([]byte, len(pskSecret))
		copy(c.SS, pskSecret)
		copy(c.ES, pskSecret)
	case handshakeModePSKAndDH:
		logf(logTypeHandshake, "ComputeBaseSecrets(PSK and DH)")
		if pskSecret == nil {
			return fmt.Errorf("tls.cryptobase: PSK selected but no PSK secret provided")
		}
		if dhSecret == nil {
			return fmt.Errorf("tls.cryptobase: DH selected but no DH secret provided")
		}

		c.SS = make([]byte, len(pskSecret))
		c.ES = make([]byte, len(dhSecret))
		copy(c.SS, pskSecret)
		copy(c.ES, dhSecret)
	case handshakeModeDH:
		logf(logTypeHandshake, "ComputeBaseSecrets(DH)")
		if dhSecret == nil {
			return fmt.Errorf("tls.cryptobase: DH selected but no DH secret provided")
		}

		c.SS = make([]byte, len(dhSecret))
		c.ES = make([]byte, len(dhSecret))
		copy(c.SS, dhSecret)
		copy(c.ES, dhSecret)
	default:
		return fmt.Errorf("tls.cryptobase: Unknown handshake mode")
	}

	// Compute xES, xSS = HKDF-Extract(0, XS)
	c.xSS = hkdfExtract(c.params.hash, nil, c.SS)
	c.xES = hkdfExtract(c.params.hash, nil, c.ES)

	c.state = ctxStateBase
	return nil
}

func (c *cryptoContext) UpdateWithHellos(chm, shm *handshakeMessage) error {
	if c.state != ctxStateBase {
		return fmt.Errorf("tls.cryptohello: wrong state")
	}

	// Set up transcript and initialize transcript hash
	c.transcript = []*handshakeMessage{}

	// Add ClientHello, ServerHello to transcript
	if chm == nil || shm == nil {
		return fmt.Errorf("tls.cryptohello: Nil message provided")
	}
	c.transcript = append(c.transcript, []*handshakeMessage{chm, shm}...)

	// Compute handshakeKeys
	context := c.marshalTranscript()
	h := c.params.hash.New()
	h.Write(context)
	handshakeHash := h.Sum(nil)
	c.handshakeKeys = c.makeTrafficKeys(c.xES, phaseHandshake, handshakeHash)

	c.state = ctxStateBase
	return nil
}

func (c *cryptoContext) Update(messages []*handshakeMessage) error {
	if c.state != ctxStateBase {
		return fmt.Errorf("tls.cryptoupdate: wrong state")
	}

	// Add messages to transcript
	for _, msg := range messages {
		if msg == nil {
			return fmt.Errorf("tls.cryptoupdate: Nil message")
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
	c.mES = hkdfExpandLabel(c.params.hash, c.xES, labelMES, handshakeHash, L)

	// Compute master_secret and traffic secret
	c.masterSecret = hkdfExtract(c.params.hash, c.mSS, c.mES)
	c.trafficSecret = hkdfExpandLabel(c.params.hash, c.masterSecret, labelTrafficSecret, handshakeHash, L)

	// Compute client and server Finished keys
	c.serverFinishedKey = hkdfExpandLabel(c.params.hash, c.masterSecret, labelServerFinished, []byte{}, L)
	c.clientFinishedKey = hkdfExpandLabel(c.params.hash, c.masterSecret, labelClientFinished, []byte{}, L)

	// Compute ServerFinished and add to transcript
	serverFinishedMAC := hmac.New(c.params.hash.New, c.serverFinishedKey)
	serverFinishedMAC.Write(handshakeHash)
	c.serverFinishedData = serverFinishedMAC.Sum(nil)
	c.serverFinished = &finishedBody{
		verifyDataLen: len(c.serverFinishedData),
		verifyData:    c.serverFinishedData,
	}

	// This call can only fail if there's a length mismatch, which can't happen here
	finishedMessage, _ := handshakeMessageFromBody(c.serverFinished)
	c.transcript = append(c.transcript, finishedMessage)

	// Compute client_finished_key and client Finished
	h.Write(finishedMessage.Marshal())
	handshakeHash = h.Sum(nil)
	logf(logTypeCrypto, "handshake hash for client Finished: [%d] %x", len(handshakeHash), handshakeHash)

	clientFinishedMAC := hmac.New(c.params.hash.New, c.clientFinishedKey)
	clientFinishedMAC.Write(handshakeHash)
	c.clientFinishedData = clientFinishedMAC.Sum(nil)
	logf(logTypeCrypto, "client Finished data: [%d] %x", len(handshakeHash), handshakeHash)

	c.clientFinished = &finishedBody{
		verifyDataLen: L,
		verifyData:    c.clientFinishedData,
	}

	// Compute application_key_0
	c.applicationKeys = c.makeTrafficKeys(c.trafficSecret, phaseApplication, handshakeHash)

	// Add clientFinished to transcript and compute the resumption / exporter secrets
	clientFinishedMessage, _ := handshakeMessageFromBody(c.clientFinished)
	h.Write(clientFinishedMessage.Marshal())
	handshakeHash = h.Sum(nil)
	c.resumptionSecret = hkdfExpandLabel(c.params.hash, c.masterSecret, labelResumptionSecret, handshakeHash, L)
	c.exporterSecret = hkdfExpandLabel(c.params.hash, c.masterSecret, labelExporterSecret, handshakeHash, L)

	c.state = ctxStateComplete
	return nil
}

func (c *cryptoContext) UpdateKeys() {
	// XXX: Assumes that nothing further has been added after the ServerFinished
	handshakeThroughFinished := c.marshalTranscript()
	c.trafficSecret = hkdfExpandLabel(c.params.hash, c.trafficSecret, labelTrafficSecret, []byte{}, c.params.hash.Size())
	c.applicationKeys = c.makeTrafficKeys(c.trafficSecret, phaseApplication, handshakeThroughFinished)
}
