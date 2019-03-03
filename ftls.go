package mint

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"fmt"
	"hash"

	"github.com/bifurcation/mint/syntax"
)

type fCipherSuite uint8

const (
	fX25519_Ed25519_AES128GCM_SHA256 fCipherSuite = 0x01
)

type fSuiteInfo struct {
	Group  NamedGroup
	Scheme SignatureScheme
	Suite  CipherSuite
}

var (
	fSuiteMap = map[fCipherSuite]fSuiteInfo{
		fX25519_Ed25519_AES128GCM_SHA256: {
			Group:  X25519,
			Scheme: Ed25519,
			Suite:  TLS_AES_128_GCM_SHA256,
		},
	}
)

//////////

// struct {
//     HandshakeType type;
//     uint16 length;
//     select (type) { ... }
// } Handshake;
type fHandshake struct {
	Type HandshakeType
	Body []byte `tls:"head=2"`
}

// struct {
//		 CipherSuite cipher_suites<0..255>;
//		 CipherSuite dh_suite;
//		 opaque dh[dh_suite.key_size];
// } ClientHello;
type fClientHello struct {
	Suites  []fCipherSuite `tls:"head=1"`
	DHSuite fCipherSuite
	DH      []byte `tls:"head=none"`
}

// struct {
//		 CipherSuite cipher_suite;
//		 opaque dh[suite.key_size];
// } ServerHello;
type fServerHello struct {
	Suite fCipherSuite
	DH    []byte `tls:"head=none"`
}

// struct {
//		 opaque key_id[Handshake.length];
// }
type fCertificate struct {
	KeyID []byte `tls:"head=none"`
}

// struct {
//		 opaque signature[Handshake.length];
// }
type fCertificateVerify struct {
	Signature []byte `tls:"head=none"`
}

// struct {
//		 opaque finishedData[Handshake.length];
// }
type fFinished struct {
	FinishedData []byte `tls:"head=none"`
}

// struct {
//		 Handshake certificate;
//		 Handshake certificate_verify;
//		 Handshake finished;
// } AuthInfo;
type fAuthInfo struct {
	Certificate       fHandshake
	CertificateVerify fHandshake
	Finished          fHandshake
}

func (ai fAuthInfo) Valid() bool {
	return ai.Certificate.Type == HandshakeTypeCertificate &&
		ai.CertificateVerify.Type == HandshakeTypeCertificateVerify &&
		ai.Finished.Type == HandshakeTypeFinished
}

type fMessage1 struct {
	ClientHello fHandshake
}

type fMessage2 struct {
	ServerHello       fHandshake
	EncryptedAuthInfo []byte `tls:"head=2"`
}

type fMessage3 struct {
	EncryptedAuthInfo []byte `tls:"head=2"`
}

type fHandshakeHash hash.Hash

func writeHandshake(h fHandshakeHash, hs fHandshake) {
	data, err := syntax.Marshal(hs)
	if err != nil {
		panic(err)
	}

	h.Write(data)
}

func writeBody(h fHandshakeHash, hsType HandshakeType, body interface{}) {
	bodyData, err := syntax.Marshal(body)
	if err != nil {
		panic(err)
	}

	writeHandshake(h, fHandshake{hsType, bodyData})
}

//////////

/*
type fMessage1 struct {
	CU      []byte   `tls:"head=1"`
	Suites  []fSuite `tls:"head=1"`
	DHSuite fSuite
	DH      []byte `tls:"head=1"`
}

type fAuthInfo struct {
	KeyID     []byte `tls:"head=1"`
	Signature []byte `tls:"head=1"`
	MAC       []byte `tls:"head=1"`
}

type fMessage2 struct {
	CU          []byte `tls:"head=1"`
	CV          []byte `tls:"head=1"`
	Suite       fSuite
	DH          []byte `tls:"head=1"`
	Ciphertext2 []byte `tls:"head=1"`
}

type fMessage3 struct {
	CV          []byte `tls:"head=1"`
	Ciphertext3 []byte `tls:"head=1"`
}
*/

//////////

func computeHandshakeSecrets(params CipherSuiteParams, h hash.Hash, dhSecret []byte) (chts, shts, ms []byte) {
	zero := bytes.Repeat([]byte{0}, params.Hash.Size())
	earlySecret := HkdfExtract(params.Hash, zero, zero)

	h0 := params.Hash.New().Sum(nil)
	h2 := h.Sum(nil)

	preHandshakeSecret := deriveSecret(params, earlySecret, labelDerived, h0)
	handshakeSecret := HkdfExtract(params.Hash, preHandshakeSecret, dhSecret)
	clientHandshakeTrafficSecret := deriveSecret(params, handshakeSecret, labelClientHandshakeTrafficSecret, h2)
	serverHandshakeTrafficSecret := deriveSecret(params, handshakeSecret, labelServerHandshakeTrafficSecret, h2)
	preMasterSecret := deriveSecret(params, handshakeSecret, labelDerived, h0)
	masterSecret := HkdfExtract(params.Hash, preMasterSecret, zero)

	return clientHandshakeTrafficSecret, serverHandshakeTrafficSecret, masterSecret
}

func computeAuthInfo(params CipherSuiteParams, scheme SignatureScheme, h fHandshakeHash, masterSecret, handshakeTrafficSecret, keyID []byte, sigPriv crypto.Signer) ([]byte, error) {
	certificate := fHandshake{HandshakeTypeCertificate, keyID}
	writeHandshake(h, certificate)
	hcv := h.Sum(nil)
	cv := &CertificateVerifyBody{Algorithm: scheme}
	cv.Sign(sigPriv, hcv)

	certificateVerify := fHandshake{HandshakeTypeCertificate, keyID}
	writeHandshake(h, certificateVerify)

	// Compute MAC
	h3 := h.Sum(nil)
	finishedData := computeFinishedData(params, handshakeTrafficSecret, h3)

	finished := fHandshake{HandshakeTypeFinished, finishedData}
	writeHandshake(h, finished)

	// Serialize AuthInfo
	authInfo := fAuthInfo{
		Certificate:       certificate,
		CertificateVerify: certificateVerify,
		Finished:          finished,
	}

	authInfoData, err := syntax.Marshal(authInfo)
	if err != nil {
		return nil, err
	}

	// Encrypt AuthInfo
	keys := makeTrafficKeys(params, handshakeTrafficSecret)
	aead, err := keys.Cipher(keys.Keys[labelForKey])
	if err != nil {
		return nil, err
	}

	encAuthInfo := aead.Seal(nil, keys.Keys[labelForIV], authInfoData, nil)
	return encAuthInfo, nil
}

func verifyAuthInfo(params CipherSuiteParams, scheme SignatureScheme, h fHandshakeHash, ct, handshakeTrafficSecret, keyID []byte, sigPub crypto.PublicKey) error {
	// Decrypt authInfo
	keys := makeTrafficKeys(params, handshakeTrafficSecret)
	aead, err := keys.Cipher(keys.Keys[labelForKey])
	if err != nil {
		return err
	}

	authInfoData, err := aead.Open(nil, keys.Keys[labelForIV], ct, nil)
	if err != nil {
		return err
	}

	var authInfo fAuthInfo
	_, err = syntax.Unmarshal(authInfoData, &authInfo)
	if err != nil {
		return err
	}
	if !authInfo.Valid() {
		return fmt.Errorf("Incorrect handshake message types")
	}

	// Verify KeyID is known
	if !bytes.Equal(authInfo.Certificate.Body, keyID) {
		return fmt.Errorf("Incorrect key ID")
	}

	// Verify Signature
	writeHandshake(h, authInfo.Certificate)
	hscv := h.Sum(nil)
	cv := &CertificateVerifyBody{
		Algorithm: scheme,
		Signature: authInfo.CertificateVerify.Body,
	}
	err = cv.Verify(sigPub, hscv)
	if err != nil {
		return err
	}

	// Verify MAC
	writeHandshake(h, authInfo.CertificateVerify)
	h3 := h.Sum(nil)
	finishedData := computeFinishedData(params, handshakeTrafficSecret, h3)
	if !hmac.Equal(authInfo.Finished.Body, finishedData) {
		return fmt.Errorf("Incorrect finished MAC")
	}

	writeHandshake(h, authInfo.Finished)
	return nil
}

//////////

type fConfig struct {
	Suites []fCipherSuite

	group  NamedGroup
	scheme SignatureScheme
	params CipherSuiteParams

	myPriv  crypto.Signer
	peerPub crypto.PublicKey

	myKeyID   []byte
	peerKeyID []byte

	connectionID []byte
}

type fClient struct {
	fConfig

	// Ephemeral state
	group         NamedGroup
	scheme        SignatureScheme
	params        CipherSuiteParams
	dhPriv        []byte
	handshakeHash hash.Hash

	// Final state
	clientAppSecret []byte
	serverAppSecret []byte
}

func (c *fClient) NewMessage1() (*fMessage1, error) {
	// Generate DH key pair
	pub, priv, err := newKeyShare(c.group)
	if err != nil {
		return nil, err
	}

	// Construct the first message
	m1 := &fMessage1{
		DH: pub,
	}

	// Start up the handshake hash
	m1data, err := syntax.Marshal(m1)
	if err != nil {
		return nil, err
	}
	handshakeHash := c.params.Hash.New()
	handshakeHash.Write(m1data)

	c.dhPriv = priv
	c.handshakeHash = handshakeHash
	return m1, nil
}

func (c *fClient) HandleMessage2(m2 *fMessage2) (*fMessage3, error) {
	// Complete DH exchange
	dhSecret, err := keyAgreement(c.group, m2.DH, c.dhPriv)
	if err != nil {
		return nil, err
	}

	// Update the handshake hahs
	c.handshakeHash.Write(m2.CU)
	c.handshakeHash.Write(m2.CV)
	c.handshakeHash.Write(m2.DH)

	// Compute handshake secrets
	clientHandshakeTrafficSecret, serverHandshakeTrafficSecret, masterSecret := computeHandshakeSecrets(c.params, c.handshakeHash, dhSecret)

	// Verify server authentication
	err = verifyAuthInfo(c.params, c.scheme, c.handshakeHash, m2.Ciphertext2, serverHandshakeTrafficSecret, c.peerKeyID, c.peerPub)

	// Compute application traffic secrets
	h4 := c.handshakeHash.Sum(nil)
	c.clientAppSecret = deriveSecret(c.params, masterSecret, labelClientApplicationTrafficSecret, h4)
	c.serverAppSecret = deriveSecret(c.params, masterSecret, labelServerApplicationTrafficSecret, h4)

	// Compute encrypted authInfo
	encAuthInfo, err := computeAuthInfo(c.params, c.scheme, c.handshakeHash, masterSecret, clientHandshakeTrafficSecret, c.myKeyID, c.myPriv)

	m3 := &fMessage3{
		CV:          m2.CV,
		Ciphertext3: encAuthInfo,
	}
	return m3, nil
}

//////////

type fServer struct {
	fConfig

	// Ephemeral state
	group                        NamedGroup
	scheme                       SignatureScheme
	params                       CipherSuiteParams
	handshakeHash                hash.Hash
	clientHandshakeTrafficSecret []byte

	// Final state
	clientAppSecret []byte
	serverAppSecret []byte
}

func (s *fServer) HandleMessage1(m1 *fMessage1) (*fMessage2, error) {
	// Generate DH key pair
	pub, priv, err := newKeyShare(s.group)
	if err != nil {
		return nil, err
	}

	// Complete DH exchange
	dhSecret, err := keyAgreement(s.group, m1.DH, priv)
	if err != nil {
		return nil, err
	}

	// Start up the handshake hash
	m1data, err := syntax.Marshal(m1)
	if err != nil {
		return nil, err
	}

	handshakeHash := s.params.Hash.New()
	handshakeHash.Write(m1data)
	handshakeHash.Write(m1.CU)
	handshakeHash.Write(s.connectionID)
	handshakeHash.Write(pub)

	// Compute handshake secrets
	clientHandshakeTrafficSecret, serverHandshakeTrafficSecret, masterSecret := computeHandshakeSecrets(s.params, handshakeHash, dhSecret)

	// Compute encrypted authInfo
	encAuthInfo, err := computeAuthInfo(s.params, s.scheme, handshakeHash, masterSecret, serverHandshakeTrafficSecret, s.myKeyID, s.myPriv)
	if err != nil {
		return nil, err
	}

	// Compute application traffic secrets
	h4 := handshakeHash.Sum(nil)
	clientAppSecret := deriveSecret(s.params, masterSecret, labelClientApplicationTrafficSecret, h4)
	serverAppSecret := deriveSecret(s.params, masterSecret, labelServerApplicationTrafficSecret, h4)

	// Construct message
	m2 := &fMessage2{
		CU:          m1.CU,
		CV:          s.connectionID,
		DH:          pub,
		Ciphertext2: encAuthInfo,
	}

	s.clientHandshakeTrafficSecret = clientHandshakeTrafficSecret
	s.clientAppSecret = clientAppSecret
	s.serverAppSecret = serverAppSecret
	s.handshakeHash = handshakeHash
	return m2, nil
}

func (s *fServer) HandleMessage3(m3 *fMessage3) error {
	// Verify connection ID
	if !bytes.Equal(m3.CV, s.connectionID) {
		return fmt.Errorf("Invalid connection ID in Message3")
	}

	return verifyAuthInfo(s.params, s.scheme, s.handshakeHash, m3.Ciphertext3, s.clientHandshakeTrafficSecret, s.peerKeyID, s.peerPub)
}
