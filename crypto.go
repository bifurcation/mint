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
	"hash"
	"math/big"
	"time"

	"golang.org/x/crypto/curve25519"

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
		TLS_DHE_PSK_WITH_AES_128_GCM_SHA256: cipherSuiteParams{
			mode:   handshakeModePSKAndDH,
			hash:   crypto.SHA256,
			keyLen: 16,
			ivLen:  12,
		},
		TLS_DHE_PSK_WITH_AES_256_GCM_SHA384: cipherSuiteParams{
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
	case namedGroupX25519:
		size = 32
	case namedGroupP256:
		size = 65
	case namedGroupP384:
		size = 97
	case namedGroupP521:
		size = 133
	case namedGroupFF2048:
		size = 256
	case namedGroupFF3072:
		size = 384
	case namedGroupFF4096:
		size = 512
	case namedGroupFF6144:
		size = 768
	case namedGroupFF8192:
		size = 1024
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
		pubBytes := X.Bytes()

		numBytes := keyExchangeSizeFromNamedGroup(group)

		pub = make([]byte, numBytes)
		copy(pub[numBytes-len(pubBytes):], pubBytes)

		return

	case namedGroupX25519:
		var private, public [32]byte
		_, err = prng.Read(private[:])
		if err != nil {
			return
		}

		curve25519.ScalarBaseMult(&public, &private)
		priv = private[:]
		pub = public[:]
		return

	default:
		return nil, nil, fmt.Errorf("tls.newkeyshare: Unsupported group %v", group)
	}
}

func keyAgreement(group namedGroup, pub []byte, priv []byte) ([]byte, error) {
	switch group {
	case namedGroupP256, namedGroupP384, namedGroupP521:
		if len(pub) != keyExchangeSizeFromNamedGroup(group) {
			return nil, fmt.Errorf("tls.keyagreement: Wrong public key size")
		}

		crv := curveFromNamedGroup(group)
		pubX, pubY := elliptic.Unmarshal(crv, pub)
		x, _ := crv.Params().ScalarMult(pubX, pubY, priv)
		xBytes := x.Bytes()

		numBytes := len(crv.Params().P.Bytes())

		ret := make([]byte, numBytes)
		copy(ret[numBytes-len(xBytes):], xBytes)

		return ret, nil

	case namedGroupFF2048, namedGroupFF3072, namedGroupFF4096,
		namedGroupFF6144, namedGroupFF8192:
		numBytes := keyExchangeSizeFromNamedGroup(group)
		if len(pub) != numBytes {
			return nil, fmt.Errorf("tls.keyagreement: Wrong public key size")
		}
		p := primeFromNamedGroup(group)
		x := big.NewInt(0).SetBytes(priv)
		Y := big.NewInt(0).SetBytes(pub)
		ZBytes := big.NewInt(0).Exp(Y, x, p).Bytes()

		ret := make([]byte, numBytes)
		copy(ret[numBytes-len(ZBytes):], ZBytes)

		return ret, nil

	case namedGroupX25519:
		if len(pub) != keyExchangeSizeFromNamedGroup(group) {
			return nil, fmt.Errorf("tls.keyagreement: Wrong public key size")
		}

		var private, public, ret [32]byte
		copy(private[:], priv)
		copy(public[:], pub)
		curve25519.ScalarMult(&ret, &private, &public)

		return ret[:], nil

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

	serial, err := rand.Int(rand.Reader, big.NewInt(0xA0A0A0A0))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:       serial,
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
			opts = hash
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
			logf(logTypeHandshake, "verifying with PKCS1, hashSize=[%d]", hash.Size())
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
	out := h.Sum(nil)

	logf(logTypeCrypto, "HKDF Extract:\n")
	logf(logTypeCrypto, "Salt [%d]: %x\n", len(salt), salt)
	logf(logTypeCrypto, "Input [%d]: %x\n", len(input), input)
	logf(logTypeCrypto, "Output [%d]: %x\n", len(out), out)

	return out
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
	labelEarlyTrafficSecret       = "early traffic secret"
	labelHandshakeTrafficSecret   = "handshake traffic secret"
	labelApplicationTrafficSecret = "application traffic secret"
	labelResumptionSecret         = "resumption master secret"
	labelExporterSecret           = "exporter master secret"
	labelServerFinished           = "server finished"
	labelClientFinished           = "client finished"
	labelResumptionPSK            = "resumption psk"
	labelResumptionContext        = "resumption context"

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

// Sine the steps have to be performed linearly (except for early data), we use
// a state variable to indicate the last operation performed.
type ctxState uint8

const (
	ctxStateNew ctxState = iota
	ctxStateClientHello
	ctxStateServerHello
	ctxStateServerFirstFlight
	ctxStateClientSecondFlight
)

// All crypto computations from -13
//
//                 0
//                 |
//                 v
//   PSK ->  HKDF-Extract     ClientHello
//                 |               |
//                 v               V
//           Early Secret  --> Derive-Secret --> early_traffic_secret
//                 |
//                 |
//      ------------------------
//                 | Precompute to here for 1xRTT optimization
//                 |
//                 v
//(EC)DHE -> HKDF-Extract     ClientHello + ServerHello
//                 |               |
//                 v               V
//         Handshake Secret --> Derive-Secret --> handshake_traffic_secret
//                 |
//                 v
//      0 -> HKDF-Extract
//                 |
//                 v
//            Master Secret   ClientHello...ServerFinished
//                 |             |
//                 |             V
//                 +---------> Derive-Secret --> traffic_secret_0
//                 |
//                 |          ClientHello...ClientFinished
//                 |             |
//                 |             V
//                 +---------> Derive-Secret --> exporter_master_secret
//                 |             |
//                 |             V
//                 +---------> Derive-Secret --> resumption_secret
//
// XXX:RLB: Early handshake secret?
//
// ==========
//
// Mode	            Handshake Context	                                      Base Key
// 0-RTT	          ClientHello	                                            early_traffic_secret
// 1-RTT (Server)	  ClientHello, ServerHello, Server...                     handshake_traffic_secret
// 1-RTT (Client)	  ClientHello, ..., SeverFinished, Client...              handshake_traffic_secret
// Post-Handshake	  ClientHello, ..., ClientFinished + CertificateRequest   traffic_secret_0
//
// XXX:RLB: Is the post-handshake line even needed?
// XXX:RLB: If so, why is context not in wire order?
//
// ----------
//
//   client_finished_key =
//       HKDF-Expand-Label(BaseKey, "client finished", "", L)
//
//   server_finished_key =
//       HKDF-Expand-Label(BaseKey, "server finished", "", L)
//
// ----------
//
//   verify_data =
//       HMAC(finished_key, Hash(
//              Handshake Context + Certificate* + CertificateVerify*
//           ) + Hash(resumption_context)
//           )
//
//   * Only included if present.
//
// ==========
//
//   resumption_psk = HKDF-Expand-Label(resumption_secret,
//                                      "resumption psk", "", L)
//
//   resumption_context = HKDF-Expand-Label(resumption_secret,
//                                          "resumption context", "", L)
//
// ====================
// ====================
//
// h1  = ClientHello           --> early_traffic_secret, early_finished_key, EarlyFinished
// h2  = h1 + ServerHello      --> handshake_traffic_secret
// h3  = h2 + Server...        --? server_finished_key, ServerFinished
// h4  = h3 + ServerFinished
// h5  = h4 + Client...
// h6  = h5 + ClientFinished
//
// (PSK?, ClientHello) => EarlySecret, early_traffic_secret
//                     => early_finished_key, EarlyFinished
// (DHE?, ServerHello) => MasterSecret, handshake_traffic_secret
// (Server...)         => server_finished_key, ServerFinished
//                     => traffic_secret_0
// (Client...)         => client_finished_key, ClientFinished
//                     => exporter_master_secret
//                     => resumption_secret

type cryptoContext struct {
	state  ctxState
	suite  cipherSuite
	params cipherSuiteParams
	zero   []byte

	earlyHandshakeHash hash.Hash
	handshakeHash      hash.Hash
	h1                 []byte // = ClientHello
	hE                 []byte // = h1 + Client...
	h2                 []byte // = h1 + ServerHello
	h3                 []byte // = h2 + Server...
	h4                 []byte // = h3 + ServerFinished
	h5                 []byte // = h4 + Client...
	h6                 []byte // = h5 + ClientFinished

	pskSecret      []byte
	dhSecret       []byte
	resumptionHash []byte

	earlySecret          []byte
	earlyTrafficSecret   []byte
	earlyHandshakeKeys   keySet
	earlyApplicationKeys keySet

	earlyFinishedKey  []byte
	earlyFinishedData []byte
	earlyFinished     *finishedBody

	handshakeSecret        []byte
	handshakeTrafficSecret []byte
	handshakeKeys          keySet

	serverFinishedKey  []byte
	serverFinishedData []byte
	serverFinished     *finishedBody

	clientFinishedKey  []byte
	clientFinishedData []byte
	clientFinished     *finishedBody

	masterSecret      []byte
	trafficSecret     []byte
	trafficKeys       keySet
	exporterSecret    []byte
	resumptionSecret  []byte
	resumptionPSK     []byte
	resumptionContext []byte
}

func (ctx cryptoContext) deriveSecret(secret []byte, label string, messageHash []byte) []byte {
	return hkdfExpandLabel(ctx.params.hash, secret, label, append(messageHash, ctx.resumptionHash...), ctx.params.hash.Size())
}

func (ctx cryptoContext) makeTrafficKeys(secret []byte, phase string) keySet {
	logf(logTypeCrypto, "making traffic keys: secret=%x phase=[%s]", secret, phase)
	Lk := ctx.params.keyLen
	Liv := ctx.params.ivLen
	H := ctx.params.hash
	return keySet{
		clientWriteKey: hkdfExpandLabel(H, secret, phase+", "+purposeClientWriteKey, []byte{}, Lk),
		serverWriteKey: hkdfExpandLabel(H, secret, phase+", "+purposeServerWriteKey, []byte{}, Lk),
		clientWriteIV:  hkdfExpandLabel(H, secret, phase+", "+purposeClientWriteIV, []byte{}, Liv),
		serverWriteIV:  hkdfExpandLabel(H, secret, phase+", "+purposeServerWriteIV, []byte{}, Liv),
	}
}

func (ctx *cryptoContext) init(suite cipherSuite, pskSecret []byte) error {
	logf(logTypeCrypto, "Initializing crypto context")

	// Configure based on cipherSuite
	params, ok := cipherSuiteMap[suite]
	if !ok {
		return fmt.Errorf("tls.cryptoinit: Unsupported ciphersuite")
	}
	ctx.suite = suite
	ctx.params = params
	ctx.zero = bytes.Repeat([]byte{0}, ctx.params.hash.Size())

	// Import the PSK secret if required by the ciphersuite
	if pskSecret != nil {
		ctx.pskSecret = make([]byte, len(pskSecret))
		copy(ctx.pskSecret, pskSecret)
	} else if ctx.params.mode == handshakeModePSK || ctx.params.mode == handshakeModePSKAndDH {
		return fmt.Errorf("tls.cryptoinit: PSK required by ciphersuite and not provided")
	} else {
		ctx.pskSecret = make([]byte, len(ctx.zero))
		copy(ctx.pskSecret, ctx.zero)
	}

	// Compute the early secret
	ctx.earlySecret = hkdfExtract(ctx.params.hash, ctx.zero, ctx.pskSecret)

	ctx.state = ctxStateNew
	return nil
}

func (ctx *cryptoContext) updateWithClientHello(chm *handshakeMessage, resumptionContext []byte) error {
	logf(logTypeCrypto, "Updating crypto context with ClientHello")

	if ctx.state != ctxStateNew {
		return fmt.Errorf("cryptoContext.updateWithClientHello called with invalid state %v", ctx.state)
	}

	// Start up the handshake hash
	bytes := chm.Marshal()
	logf(logTypeCrypto, "input to handshake hash [%d]: %x", len(bytes), bytes)
	ctx.handshakeHash = ctx.params.hash.New()
	ctx.handshakeHash.Write(bytes)
	ctx.h1 = ctx.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 1 [%d]: %x", len(ctx.h1), ctx.h1)

	// ... and it's early-handshake cousin
	ctx.earlyHandshakeHash = ctx.params.hash.New()
	ctx.earlyHandshakeHash.Write(bytes)

	// Import the resumption context
	contextOrZero := ctx.zero
	if resumptionContext == nil {
		ctx.resumptionContext = make([]byte, len(resumptionContext))
		copy(ctx.resumptionContext, resumptionContext)
	}
	h := ctx.params.hash.New()
	h.Write(contextOrZero)
	ctx.resumptionHash = h.Sum(nil)
	logf(logTypeCrypto, "Resumption context [%d]: %x", len(contextOrZero), contextOrZero)
	logf(logTypeCrypto, "Hash of resumption context [%d]: %x", len(ctx.resumptionHash), ctx.resumptionHash)

	// Derive keys derived from earlySecret
	ctx.earlyTrafficSecret = ctx.deriveSecret(ctx.earlySecret, labelEarlyTrafficSecret, ctx.h1)
	ctx.earlyHandshakeKeys = ctx.makeTrafficKeys(ctx.earlyTrafficSecret, phaseEarlyHandshake)
	ctx.earlyApplicationKeys = ctx.makeTrafficKeys(ctx.earlyTrafficSecret, phaseEarlyData)
	ctx.earlyFinishedKey = hkdfExpandLabel(ctx.params.hash, ctx.earlyTrafficSecret, labelClientFinished, []byte{}, ctx.params.hash.Size())

	ctx.state = ctxStateClientHello
	return nil
}

func (ctx *cryptoContext) updateWithEarlyHandshake(msgs []*handshakeMessage) error {
	logf(logTypeCrypto, "Updating crypto context with early handshake")

	if ctx.state != ctxStateClientHello {
		return fmt.Errorf("cryptoContext.updateWithEarlyHandshake called with invalid state %v", ctx.state)
	}

	// Compute the early Finished message
	for _, msg := range msgs {
		ctx.earlyHandshakeHash.Write(msg.Marshal())
	}
	ctx.hE = ctx.earlyHandshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash for early Finished: [%d] %x", len(ctx.hE), ctx.hE)
	logf(logTypeCrypto, "resumption hash for early Finished: [%d] %x", len(ctx.resumptionHash), ctx.resumptionHash)

	finishedMAC := hmac.New(ctx.params.hash.New, ctx.earlyFinishedKey)
	finishedMAC.Write(ctx.hE)
	finishedMAC.Write(ctx.resumptionHash)
	ctx.earlyFinishedData = finishedMAC.Sum(nil)
	logf(logTypeCrypto, "early Finished data: [%d] %x", len(ctx.earlyFinishedData), ctx.earlyFinishedData)

	ctx.earlyFinished = &finishedBody{
		verifyDataLen: ctx.params.hash.Size(),
		verifyData:    ctx.earlyFinishedData,
	}

	return nil
}

func (ctx *cryptoContext) updateWithServerHello(shm *handshakeMessage, dhSecret []byte) error {
	logf(logTypeCrypto, "Updating crypto context with ServerHello")

	if ctx.state != ctxStateClientHello {
		return fmt.Errorf("cryptoContext.updateWithServerHello called with invalid state %v", ctx.state)
	}

	// Update the handshake hash
	bytes := shm.Marshal()
	logf(logTypeCrypto, "input to handshake hash [%d]: %x", len(bytes), bytes)
	ctx.handshakeHash.Write(bytes)
	ctx.h2 = ctx.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 2 [%d]: %x", len(ctx.h2), ctx.h2)

	// Import the DH secret
	if dhSecret != nil {
		ctx.dhSecret = make([]byte, len(dhSecret))
		copy(ctx.dhSecret, dhSecret)
	} else if ctx.params.mode == handshakeModeDH || ctx.params.mode == handshakeModePSKAndDH {
		return fmt.Errorf("tls.cryptoinit: DH info required by ciphersuite and not provided")
	} else {
		ctx.dhSecret = make([]byte, len(ctx.zero))
		copy(ctx.dhSecret, ctx.zero)
	}

	// Compute the handshake secret and derived secrets
	ctx.handshakeSecret = hkdfExtract(ctx.params.hash, ctx.earlySecret, ctx.dhSecret)
	ctx.handshakeTrafficSecret = ctx.deriveSecret(ctx.handshakeSecret, labelHandshakeTrafficSecret, ctx.h2)
	ctx.handshakeKeys = ctx.makeTrafficKeys(ctx.handshakeTrafficSecret, phaseHandshake)

	// Compute the master secret
	ctx.masterSecret = hkdfExtract(ctx.params.hash, ctx.handshakeSecret, ctx.zero)

	ctx.state = ctxStateServerHello
	return nil
}

func (ctx *cryptoContext) updateWithServerFirstFlight(msgs []*handshakeMessage) error {
	logf(logTypeCrypto, "Updating crypto context with server's first flight")

	if ctx.state != ctxStateServerHello {
		return fmt.Errorf("cryptoContext.updateWithServerFirstFlight called with invalid state %v", ctx.state)
	}

	// Update the handshake hash
	for _, msg := range msgs {
		bytes := msg.Marshal()
		logf(logTypeCrypto, "input to handshake hash [%d]: %x", len(bytes), bytes)
		ctx.handshakeHash.Write(bytes)
	}
	ctx.h3 = ctx.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 3 [%d]: %x", len(ctx.h3), ctx.h3)
	logf(logTypeCrypto, "handshake hash for server Finished: [%d] %x", len(ctx.h3), ctx.h3)
	logf(logTypeCrypto, "resumption hash for server Finished: [%d] %x", len(ctx.resumptionHash), ctx.resumptionHash)

	// Compute the server Finished message
	ctx.serverFinishedKey = hkdfExpandLabel(ctx.params.hash, ctx.handshakeTrafficSecret, labelServerFinished, []byte{}, ctx.params.hash.Size())

	finishedMAC := hmac.New(ctx.params.hash.New, ctx.serverFinishedKey)
	finishedMAC.Write(ctx.h3)
	finishedMAC.Write(ctx.resumptionHash)
	ctx.serverFinishedData = finishedMAC.Sum(nil)
	logf(logTypeCrypto, "server Finished data: [%d] %x", len(ctx.serverFinishedData), ctx.serverFinishedData)

	ctx.serverFinished = &finishedBody{
		verifyDataLen: ctx.params.hash.Size(),
		verifyData:    ctx.serverFinishedData,
	}

	// Update the handshake hash
	finishedMessage, _ := handshakeMessageFromBody(ctx.serverFinished)
	ctx.handshakeHash.Write(finishedMessage.Marshal())
	ctx.h4 = ctx.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 4 [%d]: %x", len(ctx.h4), ctx.h4)

	// Compute the traffic secret and keys
	// XXX:RLB: Why not make the traffic secret include the client's second
	// flight as well?  Do we expect the server to start sending before it gets
	// the client's Finished message?
	ctx.trafficSecret = ctx.deriveSecret(ctx.masterSecret, labelApplicationTrafficSecret, ctx.h4)
	ctx.trafficKeys = ctx.makeTrafficKeys(ctx.trafficSecret, phaseApplication)

	ctx.state = ctxStateServerFirstFlight
	return nil
}

func (ctx *cryptoContext) updateWithClientSecondFlight(msgs []*handshakeMessage) error {
	logf(logTypeCrypto, "Updating crypto context with client's second flight")

	if ctx.state != ctxStateServerFirstFlight {
		return fmt.Errorf("cryptoContext.updateWithClientSecondFlight called with invalid state %v", ctx.state)
	}

	// Update the handshake hash
	// XXX:RLB: I'm going to use h5 for the client Finished, even though the spec
	// shows the hash there using a weird ordering of the messages
	for _, msg := range msgs {
		bytes := msg.Marshal()
		logf(logTypeCrypto, "input to handshake hash [%d]: %x", len(bytes), bytes)
		ctx.handshakeHash.Write(bytes)
	}
	ctx.h5 = ctx.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash for client Finished: [%d] %x", len(ctx.h5), ctx.h5)
	logf(logTypeCrypto, "resumption hash for client Finished: [%d] %x", len(ctx.resumptionHash), ctx.resumptionHash)
	logf(logTypeCrypto, "handshake hash 5 [%d]: %x", len(ctx.h5), ctx.h5)

	// Compute the server Finished message
	ctx.clientFinishedKey = hkdfExpandLabel(ctx.params.hash, ctx.handshakeTrafficSecret, labelClientFinished, []byte{}, ctx.params.hash.Size())

	finishedMAC := hmac.New(ctx.params.hash.New, ctx.clientFinishedKey)
	finishedMAC.Write(ctx.h5)
	finishedMAC.Write(ctx.resumptionHash)
	ctx.clientFinishedData = finishedMAC.Sum(nil)
	logf(logTypeCrypto, "server Finished data: [%d] %x", len(ctx.clientFinishedData), ctx.clientFinishedData)

	ctx.clientFinished = &finishedBody{
		verifyDataLen: ctx.params.hash.Size(),
		verifyData:    ctx.clientFinishedData,
	}

	// Update the handshake hash
	finishedMessage, _ := handshakeMessageFromBody(ctx.clientFinished)
	ctx.handshakeHash.Write(finishedMessage.Marshal())
	ctx.h6 = ctx.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 6 [%d]: %x", len(ctx.h6), ctx.h6)

	// Compute the exporter and resumption secrets
	ctx.exporterSecret = ctx.deriveSecret(ctx.masterSecret, labelExporterSecret, ctx.h6)
	ctx.resumptionSecret = ctx.deriveSecret(ctx.masterSecret, labelResumptionSecret, ctx.h6)
	ctx.resumptionPSK = hkdfExpandLabel(ctx.params.hash, ctx.resumptionSecret, labelResumptionPSK, []byte{}, ctx.params.hash.Size())
	ctx.resumptionContext = hkdfExpandLabel(ctx.params.hash, ctx.resumptionSecret, labelResumptionContext, []byte{}, ctx.params.hash.Size())

	ctx.state = ctxStateClientSecondFlight
	return nil
}

func (ctx *cryptoContext) updateKeys() error {
	logf(logTypeCrypto, "Updating crypto context new keys")

	if ctx.state != ctxStateClientSecondFlight {
		return fmt.Errorf("cryptoContext.UpdateKeys called with invalid state %v", ctx.state)
	}

	ctx.trafficSecret = hkdfExpandLabel(ctx.params.hash, ctx.trafficSecret, labelApplicationTrafficSecret,
		[]byte{}, ctx.params.hash.Size())
	ctx.trafficKeys = ctx.makeTrafficKeys(ctx.trafficSecret, phaseApplication)
	return nil
}
