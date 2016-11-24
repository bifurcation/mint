package mint

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
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

type aeadFactory func(key []byte) (cipher.AEAD, error)

type cipherSuiteParams struct {
	cipher aeadFactory // Cipher factory
	hash   crypto.Hash // Hash function
	keyLen int         // Key length in octets
	ivLen  int         // IV length in octets
}

type signatureAlgorithm uint8

const (
	signatureAlgorithmUnknown = iota
	signatureAlgorithmRSA_PKCS1
	signatureAlgorithmRSA_PSS
	signatureAlgorithmECDSA
)

var (
	hashMap = map[SignatureScheme]crypto.Hash{
		RSA_PKCS1_SHA1:    crypto.SHA1,
		RSA_PKCS1_SHA256:  crypto.SHA256,
		RSA_PKCS1_SHA384:  crypto.SHA384,
		RSA_PKCS1_SHA512:  crypto.SHA512,
		ECDSA_P256_SHA256: crypto.SHA256,
		ECDSA_P384_SHA384: crypto.SHA384,
		ECDSA_P521_SHA512: crypto.SHA512,
		RSA_PSS_SHA256:    crypto.SHA256,
		RSA_PSS_SHA384:    crypto.SHA384,
		RSA_PSS_SHA512:    crypto.SHA512,
	}

	sigMap = map[SignatureScheme]signatureAlgorithm{
		RSA_PKCS1_SHA1:    signatureAlgorithmRSA_PKCS1,
		RSA_PKCS1_SHA256:  signatureAlgorithmRSA_PKCS1,
		RSA_PKCS1_SHA384:  signatureAlgorithmRSA_PKCS1,
		RSA_PKCS1_SHA512:  signatureAlgorithmRSA_PKCS1,
		ECDSA_P256_SHA256: signatureAlgorithmECDSA,
		ECDSA_P384_SHA384: signatureAlgorithmECDSA,
		ECDSA_P521_SHA512: signatureAlgorithmECDSA,
		RSA_PSS_SHA256:    signatureAlgorithmRSA_PSS,
		RSA_PSS_SHA384:    signatureAlgorithmRSA_PSS,
		RSA_PSS_SHA512:    signatureAlgorithmRSA_PSS,
	}

	curveMap = map[SignatureScheme]NamedGroup{
		ECDSA_P256_SHA256: P256,
		ECDSA_P384_SHA384: P384,
		ECDSA_P521_SHA512: P521,
	}

	newAESGCM = func(key []byte) (cipher.AEAD, error) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		// TLS always uses 12-byte nonces
		return cipher.NewGCMWithNonceSize(block, 12)
	}

	cipherSuiteMap = map[CipherSuite]cipherSuiteParams{
		TLS_AES_128_GCM_SHA256: cipherSuiteParams{
			cipher: newAESGCM,
			hash:   crypto.SHA256,
			keyLen: 16,
			ivLen:  12,
		},
		TLS_AES_256_GCM_SHA384: cipherSuiteParams{
			cipher: newAESGCM,
			hash:   crypto.SHA384,
			keyLen: 32,
			ivLen:  12,
		},
	}

	x509AlgMap = map[SignatureScheme]x509.SignatureAlgorithm{
		RSA_PKCS1_SHA1:    x509.SHA1WithRSA,
		RSA_PKCS1_SHA256:  x509.SHA256WithRSA,
		RSA_PKCS1_SHA384:  x509.SHA384WithRSA,
		RSA_PKCS1_SHA512:  x509.SHA512WithRSA,
		ECDSA_P256_SHA256: x509.ECDSAWithSHA256,
		ECDSA_P384_SHA384: x509.ECDSAWithSHA384,
		ECDSA_P521_SHA512: x509.ECDSAWithSHA512,
	}

	defaultRSAKeySize = 2048
)

func curveFromNamedGroup(group NamedGroup) (crv elliptic.Curve) {
	switch group {
	case P256:
		crv = elliptic.P256()
	case P384:
		crv = elliptic.P384()
	case P521:
		crv = elliptic.P521()
	}
	return
}

func namedGroupFromECDSAKey(key *ecdsa.PublicKey) (g NamedGroup) {
	switch key.Curve.Params().Name {
	case elliptic.P256().Params().Name:
		g = P256
	case elliptic.P384().Params().Name:
		g = P384
	case elliptic.P521().Params().Name:
		g = P521
	}
	return
}

func keyExchangeSizeFromNamedGroup(group NamedGroup) (size int) {
	size = 0
	switch group {
	case X25519:
		size = 32
	case P256:
		size = 65
	case P384:
		size = 97
	case P521:
		size = 133
	case FFDHE2048:
		size = 256
	case FFDHE3072:
		size = 384
	case FFDHE4096:
		size = 512
	case FFDHE6144:
		size = 768
	case FFDHE8192:
		size = 1024
	}
	return
}

func primeFromNamedGroup(group NamedGroup) (p *big.Int) {
	switch group {
	case FFDHE2048:
		p = finiteFieldPrime2048
	case FFDHE3072:
		p = finiteFieldPrime3072
	case FFDHE4096:
		p = finiteFieldPrime4096
	case FFDHE6144:
		p = finiteFieldPrime6144
	case FFDHE8192:
		p = finiteFieldPrime8192
	}
	return
}

func schemeValidForKey(alg SignatureScheme, key crypto.Signer) bool {
	sigType := sigMap[alg]
	switch key.(type) {
	case *rsa.PrivateKey:
		return sigType == signatureAlgorithmRSA_PKCS1 || sigType == signatureAlgorithmRSA_PSS
	case *ecdsa.PrivateKey:
		return sigType == signatureAlgorithmECDSA
	default:
		return false
	}
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

func newKeyShare(group NamedGroup) (pub []byte, priv []byte, err error) {
	switch group {
	case P256, P384, P521:
		var x, y *big.Int
		crv := curveFromNamedGroup(group)
		priv, x, y, err = elliptic.GenerateKey(crv, prng)
		if err != nil {
			return
		}

		pub = elliptic.Marshal(crv, x, y)
		return

	case FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192:
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

	case X25519:
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

func keyAgreement(group NamedGroup, pub []byte, priv []byte) ([]byte, error) {
	switch group {
	case P256, P384, P521:
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

	case FFDHE2048, FFDHE3072, FFDHE4096, FFDHE6144, FFDHE8192:
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

	case X25519:
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

func newSigningKey(sig SignatureScheme) (crypto.Signer, error) {
	switch sig {
	case RSA_PKCS1_SHA1, RSA_PKCS1_SHA256,
		RSA_PKCS1_SHA384, RSA_PKCS1_SHA512,
		RSA_PSS_SHA256, RSA_PSS_SHA384,
		RSA_PSS_SHA512:
		return rsa.GenerateKey(prng, defaultRSAKeySize)
	case ECDSA_P256_SHA256:
		return ecdsa.GenerateKey(elliptic.P256(), prng)
	case ECDSA_P384_SHA384:
		return ecdsa.GenerateKey(elliptic.P384(), prng)
	case ECDSA_P521_SHA512:
		return ecdsa.GenerateKey(elliptic.P521(), prng)
	default:
		return nil, fmt.Errorf("tls.newsigningkey: Unsupported signature algorithm [%04x]", sig)
	}
}

func newSelfSigned(name string, alg SignatureScheme, priv crypto.Signer) (*x509.Certificate, error) {
	sigAlg, ok := x509AlgMap[alg]
	if !ok {
		return nil, fmt.Errorf("tls.selfsigned: Unknown signature algorithm [%04x]", alg)
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

type pkcs1Opts struct {
	hash crypto.Hash
}

func (opts pkcs1Opts) HashFunc() crypto.Hash {
	return opts.hash
}

func sign(alg SignatureScheme, privateKey crypto.Signer, sigInput []byte) ([]byte, error) {
	var opts crypto.SignerOpts

	hash := hashMap[alg]
	if hash == crypto.SHA1 {
		return nil, fmt.Errorf("tls.crypt.sign: Use of SHA-1 is forbidden")
	}

	sigType := sigMap[alg]
	var realInput []byte
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		switch {
		case allowPKCS1 && sigType == signatureAlgorithmRSA_PKCS1:
			logf(logTypeCrypto, "signing with PKCS1, hashSize=[%d]", hash.Size())
			opts = &pkcs1Opts{hash: hash}
		case !allowPKCS1 && sigType == signatureAlgorithmRSA_PKCS1:
			fallthrough
		case sigType == signatureAlgorithmRSA_PSS:
			logf(logTypeCrypto, "signing with PSS, hashSize=[%d]", hash.Size())
			opts = &rsa.PSSOptions{SaltLength: hash.Size(), Hash: hash}
		default:
			return nil, fmt.Errorf("tls.crypto.sign: Unsupported algorithm for RSA key")
		}

		h := hash.New()
		h.Write(sigInput)
		realInput = h.Sum(nil)
	case *ecdsa.PrivateKey:
		if sigType != signatureAlgorithmECDSA {
			return nil, fmt.Errorf("tls.crypto.sign: Unsupported algorithm for ECDSA key")
		}

		algGroup := curveMap[alg]
		keyGroup := namedGroupFromECDSAKey(key.Public().(*ecdsa.PublicKey))
		if algGroup != keyGroup {
			return nil, fmt.Errorf("tls.crypto.sign: Unsupported hash/curve combination")
		}

		h := hash.New()
		h.Write(sigInput)
		realInput = h.Sum(nil)
	default:
		return nil, fmt.Errorf("tls.crypto.sign: Unsupported private key type")
	}

	sig, err := privateKey.Sign(prng, realInput, opts)
	logf(logTypeCrypto, "signature: %x", sig)
	return sig, err
}

func verify(alg SignatureScheme, publicKey crypto.PublicKey, sigInput []byte, sig []byte) error {
	hash := hashMap[alg]

	if hash == crypto.SHA1 {
		return fmt.Errorf("tls.crypt.sign: Use of SHA-1 is forbidden")
	}

	sigType := sigMap[alg]
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		switch {
		case allowPKCS1 && sigType == signatureAlgorithmRSA_PKCS1:
			logf(logTypeCrypto, "verifying with PKCS1, hashSize=[%d]", hash.Size())

			h := hash.New()
			h.Write(sigInput)
			realInput := h.Sum(nil)
			return rsa.VerifyPKCS1v15(pub, hash, realInput, sig)
		case !allowPKCS1 && sigType == signatureAlgorithmRSA_PKCS1:
			fallthrough
		case sigType == signatureAlgorithmRSA_PSS:
			logf(logTypeCrypto, "verifying with PSS, hashSize=[%d]", hash.Size())
			opts := &rsa.PSSOptions{SaltLength: hash.Size(), Hash: hash}

			h := hash.New()
			h.Write(sigInput)
			realInput := h.Sum(nil)
			return rsa.VerifyPSS(pub, hash, realInput, sig, opts)
		default:
			return fmt.Errorf("tls.verify: Unsupported algorithm for RSA key")
		}

	case *ecdsa.PublicKey:
		if sigType != signatureAlgorithmECDSA {
			return fmt.Errorf("tls.verify: Unsupported algorithm for ECDSA key")
		}

		if curveMap[alg] != namedGroupFromECDSAKey(pub) {
			return fmt.Errorf("tls.verify: Unsupported curve for ECDSA key")
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

		h := hash.New()
		h.Write(sigInput)
		realInput := h.Sum(nil)
		if !ecdsa.Verify(pub, realInput, ecdsaSig.R, ecdsaSig.S) {
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
	labelExternalBinder                 = "external psk binder key"
	labelResumptionBinder               = "resumption psk binder key"
	labelEarlyTrafficSecret             = "client early traffic secret"
	labelEarlyExporterSecret            = "early exporter master secret"
	labelClientHandshakeTrafficSecret   = "client handshake traffic secret"
	labelServerHandshakeTrafficSecret   = "server handshake traffic secret"
	labelClientApplicationTrafficSecret = "client application traffic secret"
	labelServerApplicationTrafficSecret = "server application traffic secret"
	labelExporterSecret                 = "exporter master secret"
	labelResumptionSecret               = "resumption master secret"
	labelFinished                       = "finished"
)

type keySet struct {
	key []byte
	iv  []byte
}

// Sine the steps have to be performed linearly (except for early data), we use
// a state variable to indicate the last operation performed.
type ctxState uint8

const (
	ctxStateUnknown = iota
	ctxStateClientHello
	ctxStateServerHello
	ctxStateServerFirstFlight
	ctxStateClientSecondFlight
)

// All crypto computations from -18
//
//                  0
//                  |
//                  v
//    PSK ->  HKDF-Extract
//                  |
//                  v
//            Early Secret
//                  |
//                  +-----> Derive-Secret(.,
//                  |                     "external psk binder key" |
//                  |                     "resumption psk binder key",
//                  |                     "")
//                  |                     = binder_key
//                  |
//                  +-----> Derive-Secret(., "client early traffic secret",
//                  |                     ClientHello)
//                  |                     = client_early_traffic_secret
//                  |
//                  +-----> Derive-Secret(., "early exporter master secret",
//                  |                     ClientHello)
//                  |                     = early_exporter_secret
//                  v
// (EC)DHE -> HKDF-Extract
//                  |
//                  v
//          Handshake Secret
//                  |
//                  +-----> Derive-Secret(., "client handshake traffic secret",
//                  |                     ClientHello...ServerHello)
//                  |                     = client_handshake_traffic_secret
//                  |
//                  +-----> Derive-Secret(., "server handshake traffic secret",
//                  |                     ClientHello...ServerHello)
//                  |                     = server_handshake_traffic_secret
//                  |
//                  v
//       0 -> HKDF-Extract
//                  |
//                  v
//             Master Secret
//                  |
//                  +-----> Derive-Secret(., "client application traffic secret",
//                  |                     ClientHello...Server Finished)
//                  |                     = client_traffic_secret_0
//                  |
//                  +-----> Derive-Secret(., "server application traffic secret",
//                  |                     ClientHello...Server Finished)
//                  |                     = server_traffic_secret_0
//                  |
//                  +-----> Derive-Secret(., "exporter master secret",
//                  |                     ClientHello...Server Finished)
//                  |                     = exporter_secret
//                  |
//                  +-----> Derive-Secret(., "resumption master secret",
//                                        ClientHello...Client Finished)
//                                        = resumption_secret
//
// ==========
//
// Mode           Handshake Context                                               Base Key
// Server	        ClientHello … later of EncryptedExtensions/CertificateRequest	  server_handshake_traffic_secret
// Client	        ClientHello … ServerFinished	                                  client_handshake_traffic_secret
// Post-Handshake	ClientHello … ClientFinished + CertificateRequest	              client_traffic_secret_N
//
// ----------
//
//   finished_key =
//       HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
//
// ----------
//
//    verify_data =
//        HMAC(finished_key, Hash(
//                                Handshake Context +
//                                Certificate* +
//                                CertificateVerify*
//                           )
//        )
//
//    * Only included if present.
//
// ====================
// ====================
//
// h0 = ""                              -> binder_key
// h1 = ClientHello                     -> client_early_traffic_secret, early_exporter_secret
// h2 = h1 + ServerHello                -> client_handshake_traffic_secret, server_handshake_traffic_secret
// h3 = h2 + Server...                  -> ServerFinished
// h4 = h3 + ServerFinished             -> *_traffic_secret_0, exporter_secret, ClientFinished
// h5 = h4 + Client...
// h6 = h5 + ClientFinished             -> resumption_secret
//
// (PSK?, ClientHello) => EarlySecret
//                     => binder_key, client_early_traffic_secret, early_exporter_secret
// (DHE?, ServerHello) => HandshakeSecret
//                     => client_handshake_traffic_secret, server_handshake_traffic_secret
//                     => client_finished_key, ClientFinished
//                     => server_finished_key, ServerFinished
//                   0 => MasterSecret
//                     => client_traffic_secret_0, server_traffic_secret_0,
//                        exporter_secret, resumption_secret
//

type cryptoContext struct {
	state  ctxState
	suite  CipherSuite
	params cipherSuiteParams
	zero   []byte

	handshakeHash hash.Hash
	h1            []byte // = ClientHello
	h2            []byte // = h1 + ServerHello
	h3            []byte // = h2 + Server...
	h4            []byte // = h3 + ServerFinished
	h5            []byte // = h4 + Client...
	h6            []byte // = h5 + ClientFinished

	// preInit(PreSharedKey)
	earlyHash crypto.Hash
	pskSecret []byte // input
	binderKey []byte

	// earlyUpdateWithClientHello(ClientHello)
	earlySecret            []byte
	earlyTrafficSecret     []byte
	earlyExporterSecret    []byte
	clientEarlyTrafficKeys keySet

	// updateWithServerHello(ServerHello, dhSecret)
	dhSecret                     []byte // input
	handshakeSecret              []byte
	clientHandshakeTrafficSecret []byte
	serverHandshakeTrafficSecret []byte
	clientHandshakeKeys          keySet
	serverHandshakeKeys          keySet
	masterSecret                 []byte
	clientFinishedKey            []byte
	serverFinishedKey            []byte

	// updateWithServerFirstFlight(...)
	serverFinishedData  []byte
	serverFinished      *FinishedBody
	clientTrafficSecret []byte
	serverTrafficSecret []byte
	clientTrafficKeys   keySet
	serverTrafficKeys   keySet
	exporterSecret      []byte

	// updateWithClientSecondFlight(...)
	clientFinishedData []byte
	clientFinished     *FinishedBody
	resumptionSecret   []byte
}

func (ctx cryptoContext) deriveSecret(secret []byte, label string, messageHash []byte) []byte {
	return hkdfExpandLabel(ctx.params.hash, secret, label, messageHash, ctx.params.hash.Size())
}

func (ctx cryptoContext) computeFinishedData(baseKey []byte, input []byte) []byte {
	macKey := hkdfExpandLabel(ctx.params.hash, baseKey, labelFinished, []byte{}, ctx.params.hash.Size())
	mac := hmac.New(ctx.params.hash.New, macKey)
	mac.Write(input)
	return mac.Sum(nil)
}

func (ctx cryptoContext) makeTrafficKeys(secret []byte) keySet {
	logf(logTypeCrypto, "making traffic keys: secret=%x", secret)
	H := ctx.params.hash
	return keySet{
		key: hkdfExpandLabel(H, secret, "key", []byte{}, ctx.params.keyLen),
		iv:  hkdfExpandLabel(H, secret, "iv", []byte{}, ctx.params.ivLen),
	}
}

func (ctx *cryptoContext) preInit(psk PreSharedKey) error {
	// Configure based on cipherSuite
	params, ok := cipherSuiteMap[psk.CipherSuite]
	if !ok {
		return fmt.Errorf("tls.cryptoinit: Unsupported ciphersuite from PSK [%04x]", psk.CipherSuite)
	}
	ctx.suite = psk.CipherSuite
	ctx.params = params
	ctx.zero = bytes.Repeat([]byte{0}, ctx.params.hash.Size())

	// Cache the hash function for this suite so that we can verify it didn't change
	ctx.earlyHash = ctx.params.hash

	// Import the PSK secret
	ctx.pskSecret = make([]byte, len(psk.Key))
	copy(ctx.pskSecret, psk.Key)

	// Compute the early secret
	ctx.earlySecret = hkdfExtract(ctx.params.hash, ctx.zero, ctx.pskSecret)
	logf(logTypeCrypto, "early secret: [%d] %x", len(ctx.earlySecret), ctx.earlySecret)

	// Compute binder
	binderLabel := labelExternalBinder
	if psk.IsResumption {
		binderLabel = labelResumptionBinder
	}

	h := ctx.params.hash.New()
	h.Write([]byte{})
	ctx.binderKey = ctx.deriveSecret(ctx.earlySecret, binderLabel, h.Sum(nil))
	return nil
}

func (ctx *cryptoContext) earlyUpdateWithClientHello(chm *HandshakeMessage) {
	chBytes := chm.Marshal()

	h := ctx.params.hash.New()
	h.Write(chBytes)
	chHash := h.Sum(nil)

	ctx.earlyTrafficSecret = ctx.deriveSecret(ctx.earlySecret, labelEarlyTrafficSecret, chHash)
	ctx.earlyExporterSecret = ctx.deriveSecret(ctx.earlySecret, labelEarlyExporterSecret, chHash)
	ctx.clientEarlyTrafficKeys = ctx.makeTrafficKeys(ctx.earlyTrafficSecret)

	logf(logTypeCrypto, "binder key: [%d] %x", len(ctx.binderKey), ctx.binderKey)
	logf(logTypeCrypto, "early traffic secret: [%d] %x", len(ctx.earlyTrafficSecret), ctx.earlyTrafficSecret)
	logf(logTypeCrypto, "early exporter secret: [%d] %x", len(ctx.earlyExporterSecret), ctx.earlyExporterSecret)
	logf(logTypeCrypto, "early traffic keys: [%d] %x [%d] %x",
		len(ctx.clientEarlyTrafficKeys.key), ctx.clientEarlyTrafficKeys.key,
		len(ctx.clientEarlyTrafficKeys.iv), ctx.clientEarlyTrafficKeys.iv)
}

// TODO: Merge with UpdateWithServerHello?
func (ctx *cryptoContext) init(suite CipherSuite, chm *HandshakeMessage) error {
	logf(logTypeCrypto, "Initializing crypto context")

	// Configure based on cipherSuite
	params, ok := cipherSuiteMap[suite]
	if !ok {
		return fmt.Errorf("tls.cryptoinit: Unsupported ciphersuite [%04x]", suite)
	}
	ctx.suite = suite
	ctx.params = params
	ctx.zero = bytes.Repeat([]byte{0}, ctx.params.hash.Size())

	if ctx.pskSecret != nil {
		if ctx.params.hash != ctx.earlyHash {
			return fmt.Errorf("tls.cryptoinit: Change of hash between early and normal init early=[%02x] suite=[%04x] hash=[%02x]", ctx.earlyHash, ctx.suite, ctx.params.hash)
		}
	} else {
		ctx.pskSecret = make([]byte, len(ctx.zero))
		copy(ctx.pskSecret, ctx.zero)
	}

	ctx.earlySecret = hkdfExtract(ctx.params.hash, ctx.zero, ctx.pskSecret)
	logf(logTypeCrypto, "early secret: [%d] %x", len(ctx.earlySecret), ctx.earlySecret)

	// Start up the handshake hash
	bytes := chm.Marshal()
	logf(logTypeCrypto, "input to handshake hash [%d]: %x", len(bytes), bytes)
	ctx.handshakeHash = ctx.params.hash.New()
	ctx.handshakeHash.Write(bytes)
	ctx.h1 = ctx.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 1 [%d]: %x", len(ctx.h1), ctx.h1)

	ctx.state = ctxStateClientHello
	return nil
}

func (ctx *cryptoContext) updateWithServerHello(shm *HandshakeMessage, dhSecret []byte) error {
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

	// Import the DH secret or set it to zero
	// XXX: Same comment here as with regard to the PSK secret
	if dhSecret != nil {
		ctx.dhSecret = make([]byte, len(dhSecret))
		copy(ctx.dhSecret, dhSecret)
	} else {
		ctx.dhSecret = make([]byte, len(ctx.zero))
		copy(ctx.dhSecret, ctx.zero)
	}

	// Compute the handshake secret and derived secrets
	ctx.handshakeSecret = hkdfExtract(ctx.params.hash, ctx.earlySecret, ctx.dhSecret)
	ctx.clientHandshakeTrafficSecret = ctx.deriveSecret(ctx.handshakeSecret, labelClientHandshakeTrafficSecret, ctx.h2)
	ctx.serverHandshakeTrafficSecret = ctx.deriveSecret(ctx.handshakeSecret, labelServerHandshakeTrafficSecret, ctx.h2)
	ctx.clientHandshakeKeys = ctx.makeTrafficKeys(ctx.clientHandshakeTrafficSecret)
	ctx.serverHandshakeKeys = ctx.makeTrafficKeys(ctx.serverHandshakeTrafficSecret)
	logf(logTypeCrypto, "handshake secret: [%d] %x", len(ctx.handshakeSecret), ctx.handshakeSecret)
	logf(logTypeCrypto, "client handshake traffic secret: [%d] %x", len(ctx.clientHandshakeTrafficSecret), ctx.clientHandshakeTrafficSecret)
	logf(logTypeCrypto, "server handshake traffic secret: [%d] %x", len(ctx.serverHandshakeTrafficSecret), ctx.serverHandshakeTrafficSecret)
	logf(logTypeCrypto, "client handshake traffic keys: [%d] %x [%d] %x",
		len(ctx.clientHandshakeKeys.key), ctx.clientHandshakeKeys.key,
		len(ctx.clientHandshakeKeys.iv), ctx.clientHandshakeKeys.iv)
	logf(logTypeCrypto, "server handshake traffic keys: [%d] %x [%d] %x",
		len(ctx.serverHandshakeKeys.key), ctx.serverHandshakeKeys.key,
		len(ctx.serverHandshakeKeys.iv), ctx.serverHandshakeKeys.iv)

	// Compute the master secret
	ctx.masterSecret = hkdfExtract(ctx.params.hash, ctx.handshakeSecret, ctx.zero)
	logf(logTypeCrypto, "master secret: [%d] %x", len(ctx.masterSecret), ctx.masterSecret)

	ctx.state = ctxStateServerHello
	return nil
}

func (ctx *cryptoContext) updateWithServerFirstFlight(msgs []*HandshakeMessage) error {
	logf(logTypeCrypto, "Updating crypto context with server's first flight")

	if ctx.state != ctxStateServerHello {
		return fmt.Errorf("cryptoContext.updateWithServerFirstFlight called with invalid state %v", ctx.state)
	}

	// Update the handshake hash with the remainder of the server's first flight
	for _, msg := range msgs {
		bytes := msg.Marshal()
		logf(logTypeCrypto, "input to handshake hash [%d]: %x", len(bytes), bytes)
		ctx.handshakeHash.Write(bytes)
	}
	ctx.h3 = ctx.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 3 [%d]: %x", len(ctx.h3), ctx.h3)
	logf(logTypeCrypto, "handshake hash for server Finished: [%d] %x", len(ctx.h3), ctx.h3)

	// Compute the server Finished message
	ctx.serverFinishedData = ctx.computeFinishedData(ctx.serverHandshakeTrafficSecret, ctx.h3)
	logf(logTypeCrypto, "server finished data: [%d] %x", len(ctx.serverFinishedData), ctx.serverFinishedData)

	ctx.serverFinished = &FinishedBody{
		VerifyDataLen: ctx.params.hash.Size(),
		VerifyData:    ctx.serverFinishedData,
	}

	// Update the handshake hash with the Finished message
	finishedMessage, _ := HandshakeMessageFromBody(ctx.serverFinished)
	ctx.handshakeHash.Write(finishedMessage.Marshal())
	ctx.h4 = ctx.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 4 [%d]: %x", len(ctx.h4), ctx.h4)

	// Compute the traffic secret and keys
	// XXX:RLB: Why not make the traffic secret include the client's second
	// flight as well?  Do we expect the server to start sending before it gets
	// the client's Finished message?
	ctx.clientTrafficSecret = ctx.deriveSecret(ctx.masterSecret, labelClientApplicationTrafficSecret, ctx.h4)
	ctx.serverTrafficSecret = ctx.deriveSecret(ctx.masterSecret, labelServerApplicationTrafficSecret, ctx.h4)
	ctx.exporterSecret = ctx.deriveSecret(ctx.masterSecret, labelExporterSecret, ctx.h4)
	ctx.clientTrafficKeys = ctx.makeTrafficKeys(ctx.clientTrafficSecret)
	ctx.serverTrafficKeys = ctx.makeTrafficKeys(ctx.serverTrafficSecret)
	logf(logTypeCrypto, "client traffic secret: [%d] %x", len(ctx.clientTrafficSecret), ctx.clientTrafficSecret)
	logf(logTypeCrypto, "server traffic secret: [%d] %x", len(ctx.serverTrafficSecret), ctx.serverTrafficSecret)
	logf(logTypeCrypto, "exporter secret: [%d] %x", len(ctx.exporterSecret), ctx.exporterSecret)
	logf(logTypeCrypto, "client traffic keys: [%d] %x [%d] %x",
		len(ctx.clientTrafficKeys.key), ctx.clientTrafficKeys.key,
		len(ctx.clientTrafficKeys.iv), ctx.clientTrafficKeys.iv)
	logf(logTypeCrypto, "server traffic keys: [%d] %x [%d] %x",
		len(ctx.serverTrafficKeys.key), ctx.serverTrafficKeys.key,
		len(ctx.serverTrafficKeys.iv), ctx.serverTrafficKeys.iv)

	ctx.state = ctxStateServerFirstFlight
	return nil
}

func (ctx *cryptoContext) updateWithClientSecondFlight(msgs []*HandshakeMessage) error {
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
	logf(logTypeCrypto, "handshake hash 5 [%d]: %x", len(ctx.h5), ctx.h5)

	// Compute the client Finished message
	ctx.clientFinishedData = ctx.computeFinishedData(ctx.clientHandshakeTrafficSecret, ctx.h5)
	logf(logTypeCrypto, "client Finished data: [%d] %x", len(ctx.clientFinishedData), ctx.clientFinishedData)

	ctx.clientFinished = &FinishedBody{
		VerifyDataLen: ctx.params.hash.Size(),
		VerifyData:    ctx.clientFinishedData,
	}

	// Update the handshake hash
	finishedMessage, _ := HandshakeMessageFromBody(ctx.clientFinished)
	ctx.handshakeHash.Write(finishedMessage.Marshal())
	ctx.h6 = ctx.handshakeHash.Sum(nil)
	logf(logTypeCrypto, "handshake hash 6 [%d]: %x", len(ctx.h6), ctx.h6)

	// Compute the exporter and resumption secrets
	ctx.resumptionSecret = ctx.deriveSecret(ctx.masterSecret, labelResumptionSecret, ctx.h6)
	logf(logTypeCrypto, "resumption secret: [%d] %x", len(ctx.resumptionSecret), ctx.resumptionSecret)

	ctx.state = ctxStateClientSecondFlight
	return nil
}

func (ctx *cryptoContext) updateKeys(client bool) error {
	logf(logTypeCrypto, "Updating crypto context new keys client=[%v]", client)

	if ctx.state != ctxStateClientSecondFlight {
		return fmt.Errorf("cryptoContext.UpdateKeys called with invalid state %v", ctx.state)
	}

	if client {
		ctx.clientTrafficSecret = hkdfExpandLabel(ctx.params.hash, ctx.clientTrafficSecret,
			labelClientApplicationTrafficSecret, []byte{}, ctx.params.hash.Size())
		ctx.clientTrafficKeys = ctx.makeTrafficKeys(ctx.clientTrafficSecret)
	} else {
		ctx.serverTrafficSecret = hkdfExpandLabel(ctx.params.hash, ctx.serverTrafficSecret,
			labelServerApplicationTrafficSecret, []byte{}, ctx.params.hash.Size())
		ctx.serverTrafficKeys = ctx.makeTrafficKeys(ctx.serverTrafficSecret)
	}
	return nil
}
