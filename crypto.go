package mint

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
)

var prng = rand.Reader

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
		size = 65
	case namedGroupP384:
		size = 97
	case namedGroupP521:
		size = 133
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

var (
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

/*
// From RFC 5869
// PRK = HMAC-Hash(salt, IKM)
func hkdfExtract(hash crypto.Hash, saltIn []byte, input []byte) []byte {
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
	copy(hkdfLabel[3:3+labelLen], label)
	hkdfLabel[3+labelLen] = byte(hashLen)
	copy(hkdfLabel[3+labelLen+1:], hash)
	return hkdfLabel
}

func hkdfExpand(hash crypto.Hash, prk, info []byte, outLen int) []byte {
	out := []byte{}
	T := []byte{}
	i := byte(1)
	for len(out) < outLen {
		block := append(T, hkdfLabel...)
		block = append(block, i)

		h := hmac.New(hash.New, prk)
		h.Write(block)

		T = h.Sum(nil)
		out = append(out, T...)
		i += 1
	}
	return out[:outLen]
}

func hkdfExpandLabel(hash crypto.Hash, secret, label, hashValue []byte, outLen int) []byte {
	return hkdfExpand(hash, hkdfEncodeLabel(secret, label), outLen)
}

const (
	labelXSS = "expanded static secret"
	labelXES = "expanded ephemeral secret"

	phaseEarlyHandshake = "early handshake key expansion"
	phaseEarlyData      = "early application data key expansion"
	phaseHandshake      = "handshake key expansion"
	phaseApplication    = "application data key expansion"

	purposeClientWriteKey = "client write key"
	purposeServerWriteKey = "server write key"
	purposeServerWriteIV  = "client write IV"
	purposeServerWriteIV  = "server write IV"
)

func computeMasterSecret(hash crypto.Hash, SS, ES, handshakeHash []byte) []byte {
	L := hash.Size()

	xSS := hkdfExtract(hash, nil, SS)
	xES := hkdfExtract(hash, nil, ES)

	mSS := hkdfExpandLabel(hash, xSS, labelXSS, handshakeHash, L)
	mES := hkdfExpandLabel(hash, xES, labelXES, handshakeHash, L)

	masterSecret := hkdfExtract(hash, mSS, mES)
	return masterSecret
}

type keySet struct {
	clientWriteKey []byte
	serverWriteKey []byte
	clientWriteIV  []byte
	serverWriteIV  []byte
}

// XXX: This might be specific to 1xRTT; we'll figure out how to adapt later
type cryptoContext struct {
	suite  cipherSuite
	hash   crypto.Hash
	keyLen int
	ivLen  int

	transcript     []*handshakeMessage
	transcriptHash []byte

	ES, SS        []byte
	xES, xSS      []byte
	handshakeKeys keySet

	mES, mSS           []byte
	masterSecret       []byte
	serverFinishedKey  []byte
	serverFinishedData []byte

	clientFinishedKey  []byte
	clientFinishedData []byte

	trafficSecret   []byte
	application_key keySet
}

func (c *cryptoContext) addToTranscript(body handshakeMessageBody) error {
	msg, err := handshakeMessageFromBody(body)
	if err != nil {
		return err
	}

	data, err := msg.Marshal()
	if err != nil {
		return err
	}

	c.transcript = append(c.transcript, msg)
	c.transcriptHash.Write(data)
}

func (c *cryptoContext) makeTrafficKeys(secret []byte, phase string) keySet {

}

func (c *cryptoContext) Init(ch *clientHelloBody, sh *serverHelloBody, ES []byte, suite cipherSuite) error {
	// Configure based on cipherSuite
	c.hash, c.keyLen, c.ivLen = cipherSuiteDetails(suite)

	// Set up transcript and initialize transcript hash
	c.transcript = []*handshakeMessage{}
	c.transcriptHash = hash.New()

	// Add ClientHello, ServerHello to transcript
	err := c.addToTranscript(ch)
	if err != nil {
		return err
	}
	err := c.addToTranscript(sh)
	if err != nil {
		return err
	}

	// Compute xES = HKDF-Extract(0, ES)
	c.ES = make([]byte, len(ES))
	c.SS = make([]byte, len(ES))
	copy(c.ES, ES)
	copy(c.SS, ES)
	c.xES = hkdfExtract(c.hash, nil, c.ES)
	c.xSS = hkdfExtract(c.hash, nil, c.SS)

	// TODO Compute handshakeKeys
}

func (c *cryptoContext) Update(bodies []handshakeMessageBody) {
	// Add messages to transcript
	// Compute mES, master_secret, traffic_secret_0, server_finished_key
	// Compute ServerFinished
	// Add ServerFinished to transcript
	// Compute client_finished_key, application_key_0
}
*/
