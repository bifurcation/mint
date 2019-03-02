package mint

// TODO Make an fTLS instance struct that spans Client/Server pairs
// TODO Absorb ftls* variables into the instance struct
// TODO factor out creation and verification of AuthInfo

import (
	"bytes"
	"crypto"
	"fmt"
	"hash"

	"github.com/bifurcation/mint/syntax"
)

type fMessage1 struct {
	DH []byte `tls:"head=1"`
}

type fAuthInfo struct {
	KeyID     []byte `tls:"head=1"`
	Signature []byte `tls:"head=1"`
	MAC       []byte `tls:"head=1"`
}

type fMessage2 struct {
	DH          []byte `tls:"head=1"`
	Ciphertext2 []byte `tls:"head=1"`
}

type fMessage3 struct {
	Ciphertext3 []byte `tls:"head=1"`
}

//////////

const (
	// We assume these are negotiated in error messages / signaled via
	// an int value in the first message, as in EDHOC
	ftlsGroup  = X25519
	ftlsScheme = Ed25519
	ftlsSuite  = TLS_AES_128_GCM_SHA256
)

var (
	ftlsClientKeyID = []byte{0, 1, 2, 3}
	ftlsServerKeyID = []byte{4, 5, 6, 7}
)

type fClient struct {
	params        CipherSuiteParams
	dhPriv        []byte
	sigPriv       crypto.Signer
	handshakeHash hash.Hash
	serverSigPub  []byte
	masterSecret  []byte
}

func (c *fClient) NewMessage1() *fMessage1 {
	c.params = cipherSuiteMap[ftlsSuite]

	// Generate DH key pair
	pub, priv, _ := newKeyShare(ftlsGroup)

	// Construct the first message
	m1 := &fMessage1{
		DH: pub,
	}

	// Start up the handshake hash
	m1data, _ := syntax.Marshal(m1)
	handshakeHash := c.params.Hash.New()
	handshakeHash.Write(m1data)

	c.dhPriv = priv
	c.handshakeHash = handshakeHash
	return m1
}

func (c *fClient) HandleMessage2(m2 *fMessage2) (*fMessage3, error) {
	// Complete DH exchange
	dhSecret, _ := keyAgreement(ftlsGroup, m2.DH, c.dhPriv)

	// Update hte handshake hahs
	c.handshakeHash.Write(m2.DH)

	// Compute handshake secrets
	zero := bytes.Repeat([]byte{0}, c.params.Hash.Size())
	earlySecret := HkdfExtract(c.params.Hash, zero, zero)

	h0 := c.params.Hash.New().Sum(nil)
	h2 := c.handshakeHash.Sum(nil)
	preHandshakeSecret := deriveSecret(c.params, earlySecret, labelDerived, h0)
	handshakeSecret := HkdfExtract(c.params.Hash, preHandshakeSecret, dhSecret)
	clientHandshakeTrafficSecret := deriveSecret(c.params, handshakeSecret, labelClientHandshakeTrafficSecret, h2)
	serverHandshakeTrafficSecret := deriveSecret(c.params, handshakeSecret, labelServerHandshakeTrafficSecret, h2)
	preMasterSecret := deriveSecret(c.params, handshakeSecret, labelDerived, h0)
	masterSecret := HkdfExtract(c.params.Hash, preMasterSecret, zero)

	// Decrypt and parse server's AuthInfo
	serverKeys := makeTrafficKeys(c.params, serverHandshakeTrafficSecret)
	serverAEAD, _ := serverKeys.Cipher(serverKeys.Keys[labelForKey])
	serverAuthInfoData, err := serverAEAD.Open(nil, serverKeys.Keys[labelForIV], m2.Ciphertext2, nil)
	if err != nil {
		return nil, err
	}

	var serverAuthInfo fAuthInfo
	_, err = syntax.Unmarshal(serverAuthInfoData, &serverAuthInfo)
	if err != nil {
		return nil, err
	}

	// Verify KeyID is known
	if !bytes.Equal(serverAuthInfo.KeyID, ftlsServerKeyID) {
		return nil, fmt.Errorf("Incorrect key ID")
	}

	// Verify Signature
	c.handshakeHash.Write(serverAuthInfo.KeyID)
	hscv := c.handshakeHash.Sum(nil)
	scv := &CertificateVerifyBody{
		Algorithm: ftlsScheme,
		Signature: serverAuthInfo.Signature,
	}
	err = scv.Verify(c.serverSigPub, hscv)
	if err != nil {
		return nil, err
	}

	// Verify MAC
	// XXX: Constant time
	c.handshakeHash.Write(serverAuthInfo.Signature)
	h3 := c.handshakeHash.Sum(nil)
	serverFinishedData := computeFinishedData(c.params, serverHandshakeTrafficSecret, h3)
	if !bytes.Equal(serverAuthInfo.MAC, serverFinishedData) {
		return nil, fmt.Errorf("Incorrect finished MAC")
	}

	// Compute Signature
	c.handshakeHash.Write(serverAuthInfo.MAC)
	hccv := c.handshakeHash.Sum(nil)
	ccv := &CertificateVerifyBody{Algorithm: ftlsScheme}
	ccv.Sign(c.sigPriv, hccv)
	sig := ccv.Signature

	// Compute MAC
	c.handshakeHash.Write(sig)
	h3 = c.handshakeHash.Sum(nil)
	clientFinishedData := computeFinishedData(c.params, clientHandshakeTrafficSecret, h3)

	// Serialize and encrypt AuthInfo
	clientAuthInfo := fAuthInfo{
		KeyID:     ftlsClientKeyID,
		Signature: ccv.Signature,
		MAC:       clientFinishedData,
	}

	clientAuthInfoData, _ := syntax.Marshal(clientAuthInfo)

	// Encrypt client's AuthInfo
	clientKeys := makeTrafficKeys(c.params, clientHandshakeTrafficSecret)
	clientAEAD, _ := clientKeys.Cipher(clientKeys.Keys[labelForKey])
	ct := clientAEAD.Seal(nil, clientKeys.Keys[labelForIV], clientAuthInfoData, nil)

	c.masterSecret = masterSecret
	m3 := &fMessage3{
		Ciphertext3: ct,
	}
	return m3, nil
}

//////////

type fServer struct {
	params                       CipherSuiteParams
	sigPriv                      crypto.Signer
	clientSigPub                 []byte
	handshakeHash                hash.Hash
	masterSecret                 []byte
	clientHandshakeTrafficSecret []byte
}

func (s *fServer) HandleMessage1(m1 *fMessage1) *fMessage2 {
	s.params = cipherSuiteMap[ftlsSuite]

	// Generate DH key pair
	pub, priv, _ := newKeyShare(ftlsGroup)

	// Complete DH exchange
	dhSecret, _ := keyAgreement(ftlsGroup, m1.DH, priv)

	// Start up the handshake hash
	m1data, _ := syntax.Marshal(m1)
	handshakeHash := s.params.Hash.New()
	handshakeHash.Write(m1data)
	handshakeHash.Write(pub)

	// Compute handshake secrets
	zero := bytes.Repeat([]byte{0}, s.params.Hash.Size())
	earlySecret := HkdfExtract(s.params.Hash, zero, zero)

	h0 := s.params.Hash.New().Sum(nil)
	h2 := handshakeHash.Sum(nil)
	preHandshakeSecret := deriveSecret(s.params, earlySecret, labelDerived, h0)
	handshakeSecret := HkdfExtract(s.params.Hash, preHandshakeSecret, dhSecret)
	clientHandshakeTrafficSecret := deriveSecret(s.params, handshakeSecret, labelClientHandshakeTrafficSecret, h2)
	serverHandshakeTrafficSecret := deriveSecret(s.params, handshakeSecret, labelServerHandshakeTrafficSecret, h2)
	preMasterSecret := deriveSecret(s.params, handshakeSecret, labelDerived, h0)
	masterSecret := HkdfExtract(s.params.Hash, preMasterSecret, zero)

	// Compute signature
	handshakeHash.Write(ftlsServerKeyID)
	hcv := handshakeHash.Sum(nil)
	cv := &CertificateVerifyBody{Algorithm: ftlsScheme}
	cv.Sign(s.sigPriv, hcv)
	sig := cv.Signature
	handshakeHash.Write(sig)

	// Compute MAC
	h3 := handshakeHash.Sum(nil)
	serverFinishedData := computeFinishedData(s.params, serverHandshakeTrafficSecret, h3)

	// Serialize AuthInfo
	authInfo := fAuthInfo{
		KeyID:     ftlsServerKeyID,
		Signature: cv.Signature,
		MAC:       serverFinishedData,
	}

	authInfoData, _ := syntax.Marshal(authInfo)

	// Encrypt AuthInfo
	keys := makeTrafficKeys(s.params, serverHandshakeTrafficSecret)
	aead, _ := keys.Cipher(keys.Keys[labelForKey])
	ct := aead.Seal(nil, keys.Keys[labelForIV], authInfoData, nil)

	// Construct message
	m2 := &fMessage2{
		DH:          pub,
		Ciphertext2: ct,
	}

	s.masterSecret = masterSecret
	s.clientHandshakeTrafficSecret = clientHandshakeTrafficSecret
	s.handshakeHash = handshakeHash
	return m2
}

func (s *fServer) HandleMessage3(m3 *fMessage3) error {
	// Decrypt
	keys := makeTrafficKeys(s.params, s.clientHandshakeTrafficSecret)
	aead, _ := keys.Cipher(keys.Keys[labelForKey])
	authInfoData, err := aead.Open(nil, keys.Keys[labelForIV], m3.Ciphertext3, nil)
	if err != nil {
		return err
	}

	var authInfo fAuthInfo
	_, err = syntax.Unmarshal(authInfoData, &authInfo)
	if err != nil {
		return err
	}

	// Verify KeyID is known
	if !bytes.Equal(authInfo.KeyID, ftlsClientKeyID) {
		return fmt.Errorf("Incorrect key ID")
	}

	// Verify Signature
	s.handshakeHash.Write(authInfo.KeyID)
	hscv := s.handshakeHash.Sum(nil)
	cv := &CertificateVerifyBody{
		Algorithm: ftlsScheme,
		Signature: authInfo.Signature,
	}
	err = cv.Verify(s.clientSigPub, hscv)
	if err != nil {
		return err
	}

	// Verify MAC
	// XXX: Constant time
	s.handshakeHash.Write(authInfo.Signature)
	h3 := s.handshakeHash.Sum(nil)
	clientFinishedData := computeFinishedData(s.params, s.clientHandshakeTrafficSecret, h3)
	if !bytes.Equal(authInfo.MAC, clientFinishedData) {
		return fmt.Errorf("Incorrect finished MAC")
	}

	return nil
}
