package mint

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"fmt"
	"hash"

	"github.com/bifurcation/mint/syntax"
)

// struct {
//     HandshakeType type;
//     uint16 length;
//     select (type) { ... }
// } Handshake;
type fHandshake struct {
	Type HandshakeType
	Body []byte `tls:"head=2"`
}

func newHandshake(hsType HandshakeType, body interface{}) fHandshake {
	data, err := syntax.Marshal(body)
	if err != nil {
		panic(err)
	}

	return fHandshake{hsType, data}
}

// struct {
//		 CipherSuite cipher_suites<0..255>;
//		 NamedGroup dh_suite;
//		 opaque dh[dh_suite.key_size];
// } ClientHello;
type fClientHello struct {
	Suites []CipherSuite `tls:"head=1"`
	Group  NamedGroup
	DH     []byte `tls:"head=none"`
}

// struct {
//		 CipherSuite cipher_suite;
//		 opaque dh[suite.key_size];
// } ServerHello;
type fServerHello struct {
	Suite CipherSuite
	DH    []byte `tls:"head=none"`
}

// struct {
//		 opaque key_id[Handshake.length];
// }
type fCertificate struct {
	KeyID []byte `tls:"head=none"`
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
	// Compute signature
	certificate := fHandshake{HandshakeTypeCertificate, keyID}
	writeHandshake(h, certificate)
	hcv := h.Sum(nil)
	cv := &CertificateVerifyBody{Algorithm: scheme}
	err := cv.Sign(sigPriv, hcv)
	if err != nil {
		return nil, err
	}

	cvData, err := cv.Marshal()
	if err != nil {
		return nil, err
	}

	certificateVerify := fHandshake{HandshakeTypeCertificateVerify, cvData}
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
	hcv := h.Sum(nil)

	var cv CertificateVerifyBody
	_, err = cv.Unmarshal(authInfo.CertificateVerify.Body)
	if err != nil {
		return err
	}
	err = cv.Verify(sigPub, hcv)
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
	suites []CipherSuite
	groups []NamedGroup

	scheme  SignatureScheme
	myPriv  crypto.Signer
	peerPub crypto.PublicKey

	myKeyID   []byte
	peerKeyID []byte

	connectionID []byte
}

type fClient struct {
	fConfig

	// Ephemeral state
	group       NamedGroup
	params      CipherSuiteParams
	dhPriv      []byte
	clientHello fHandshake

	// Final state
	clientAppSecret []byte
	serverAppSecret []byte
}

func (c *fClient) NewMessage1() (*fMessage1, error) {
	// Generate DH key pair
	c.group = c.groups[0]
	pub, priv, err := newKeyShare(c.group)
	if err != nil {
		return nil, err
	}

	// Construct the first message
	ch := fClientHello{
		Suites: c.suites,
		Group:  c.group,
		DH:     pub,
	}
	chm := newHandshake(HandshakeTypeClientHello, ch)
	m1 := &fMessage1{
		ClientHello: chm,
	}

	c.dhPriv = priv
	c.clientHello = chm
	return m1, nil
}

func (c *fClient) HandleMessage2(m2 *fMessage2) (*fMessage3, error) {
	if m2.ServerHello.Type != HandshakeTypeServerHello {
		return nil, fmt.Errorf("Incorrect handshake type for ServerHello")
	}

	var sh fServerHello
	_, err := syntax.Unmarshal(m2.ServerHello.Body, &sh)
	if err != nil {
		return nil, err
	}

	// Configure based on the ciphersuite
	c.params = cipherSuiteMap[sh.Suite]

	// Complete DH exchange
	dhSecret, err := keyAgreement(c.group, sh.DH, c.dhPriv)
	if err != nil {
		return nil, err
	}

	// Start up the handshake hash
	handshakeHash := fHandshakeHash(c.params.Hash.New())
	writeHandshake(handshakeHash, c.clientHello)
	writeHandshake(handshakeHash, m2.ServerHello)

	// Compute handshake secrets
	clientHandshakeTrafficSecret, serverHandshakeTrafficSecret, masterSecret := computeHandshakeSecrets(c.params, handshakeHash, dhSecret)

	// Verify server authentication
	err = verifyAuthInfo(c.params, c.scheme, handshakeHash, m2.EncryptedAuthInfo, serverHandshakeTrafficSecret, c.peerKeyID, c.peerPub)
	if err != nil {
		return nil, err
	}

	// Compute application traffic secrets
	h4 := handshakeHash.Sum(nil)
	c.clientAppSecret = deriveSecret(c.params, masterSecret, labelClientApplicationTrafficSecret, h4)
	c.serverAppSecret = deriveSecret(c.params, masterSecret, labelServerApplicationTrafficSecret, h4)

	// Compute encrypted authInfo
	encAuthInfo, err := computeAuthInfo(c.params, c.scheme, handshakeHash, masterSecret, clientHandshakeTrafficSecret, c.myKeyID, c.myPriv)
	if err != nil {
		return nil, err
	}

	m3 := &fMessage3{
		EncryptedAuthInfo: encAuthInfo,
	}
	return m3, nil
}

//////////

type fServer struct {
	fConfig

	// Ephemeral state
	params                       CipherSuiteParams
	handshakeHash                hash.Hash
	clientHandshakeTrafficSecret []byte

	// Final state
	clientAppSecret []byte
	serverAppSecret []byte
}

func (s *fServer) HandleMessage1(m1 *fMessage1) (*fMessage2, error) {
	if m1.ClientHello.Type != HandshakeTypeClientHello {
		return nil, fmt.Errorf("Incorrect handshake type for ClientHello")
	}

	var ch fClientHello
	_, err := syntax.Unmarshal(m1.ClientHello.Body, &ch)
	if err != nil {
		return nil, err
	}

	// Negotiate a ciphersuite
	suite, err := CipherSuiteNegotiation(nil, ch.Suites, s.suites)
	if err != nil {
		return nil, fmt.Errorf("No supported ciphersuite")
	}

	s.params = cipherSuiteMap[suite]

	// Generate DH key pair
	dhGroupSupported := false
	for _, group := range s.groups {
		dhGroupSupported = dhGroupSupported || (group == ch.Group)
	}
	if !dhGroupSupported {
		return nil, fmt.Errorf("Unsupported DH group")
	}

	pub, priv, err := newKeyShare(ch.Group)
	if err != nil {
		return nil, err
	}

	// Complete DH exchange
	dhSecret, err := keyAgreement(ch.Group, ch.DH, priv)
	if err != nil {
		return nil, err
	}

	// Create the ServerHello
	sh := fServerHello{
		Suite: suite,
		DH:    pub,
	}

	shm := newHandshake(HandshakeTypeServerHello, sh)

	// Start up the handshake hash
	handshakeHash := fHandshakeHash(s.params.Hash.New())
	writeHandshake(handshakeHash, m1.ClientHello)
	writeHandshake(handshakeHash, shm)

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
		ServerHello:       shm,
		EncryptedAuthInfo: encAuthInfo,
	}

	s.clientHandshakeTrafficSecret = clientHandshakeTrafficSecret
	s.clientAppSecret = clientAppSecret
	s.serverAppSecret = serverAppSecret
	s.handshakeHash = handshakeHash
	return m2, nil
}

func (s *fServer) HandleMessage3(m3 *fMessage3) error {
	return verifyAuthInfo(s.params, s.scheme, s.handshakeHash, m3.EncryptedAuthInfo, s.clientHandshakeTrafficSecret, s.peerKeyID, s.peerPub)
}
