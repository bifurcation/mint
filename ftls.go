package mint

// TODO Make an fTLS instance struct that spans Client/Server pairs
// TODO factor out creation and verification of AuthInfo
// TODO Add connection IDs to make it equivalent to EDHOC

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

type fClient struct {
	// Config
	group        NamedGroup
	scheme       SignatureScheme
	params       CipherSuiteParams
	sigPriv      crypto.Signer
	serverSigPub crypto.PublicKey
	clientKeyID  []byte
	serverKeyID  []byte

	// Ephemeral state
	dhPriv        []byte
	handshakeHash hash.Hash
	masterSecret  []byte

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
	serverAEAD, err := serverKeys.Cipher(serverKeys.Keys[labelForKey])
	if err != nil {
		return nil, err
	}

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
	if !bytes.Equal(serverAuthInfo.KeyID, c.serverKeyID) {
		return nil, fmt.Errorf("Incorrect key ID")
	}

	// Verify Signature
	c.handshakeHash.Write(serverAuthInfo.KeyID)
	hscv := c.handshakeHash.Sum(nil)
	scv := &CertificateVerifyBody{
		Algorithm: c.scheme,
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

	// Compute application traffic secrets
	c.handshakeHash.Write(serverAuthInfo.MAC)
	h4 := c.handshakeHash.Sum(nil)
	c.clientAppSecret = deriveSecret(c.params, masterSecret, labelClientApplicationTrafficSecret, h4)
	c.serverAppSecret = deriveSecret(c.params, masterSecret, labelServerApplicationTrafficSecret, h4)

	// Compute Signature
	c.handshakeHash.Write(c.clientKeyID)
	hccv := c.handshakeHash.Sum(nil)
	ccv := &CertificateVerifyBody{Algorithm: c.scheme}
	ccv.Sign(c.sigPriv, hccv)
	sig := ccv.Signature

	// Compute MAC
	c.handshakeHash.Write(sig)
	h3 = c.handshakeHash.Sum(nil)
	clientFinishedData := computeFinishedData(c.params, clientHandshakeTrafficSecret, h3)

	// Serialize and encrypt AuthInfo
	clientAuthInfo := fAuthInfo{
		KeyID:     c.clientKeyID,
		Signature: ccv.Signature,
		MAC:       clientFinishedData,
	}

	clientAuthInfoData, err := syntax.Marshal(clientAuthInfo)
	if err != nil {
		return nil, err
	}

	// Encrypt client's AuthInfo
	clientKeys := makeTrafficKeys(c.params, clientHandshakeTrafficSecret)
	clientAEAD, err := clientKeys.Cipher(clientKeys.Keys[labelForKey])
	if err != nil {
		return nil, err
	}

	ct := clientAEAD.Seal(nil, clientKeys.Keys[labelForIV], clientAuthInfoData, nil)

	c.masterSecret = masterSecret
	m3 := &fMessage3{
		Ciphertext3: ct,
	}
	return m3, nil
}

//////////

type fServer struct {
	// Config
	group        NamedGroup
	scheme       SignatureScheme
	params       CipherSuiteParams
	sigPriv      crypto.Signer
	clientSigPub crypto.PublicKey
	serverKeyID  []byte
	clientKeyID  []byte

	// Ephemeral state
	handshakeHash                hash.Hash
	clientHandshakeTrafficSecret []byte
	masterSecret                 []byte

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
	handshakeHash.Write(s.serverKeyID)
	hcv := handshakeHash.Sum(nil)
	cv := &CertificateVerifyBody{Algorithm: s.scheme}
	cv.Sign(s.sigPriv, hcv)
	sig := cv.Signature
	handshakeHash.Write(sig)

	// Compute MAC
	h3 := handshakeHash.Sum(nil)
	serverFinishedData := computeFinishedData(s.params, serverHandshakeTrafficSecret, h3)

	// Compute application traffic secrets
	handshakeHash.Write(serverFinishedData)
	h4 := handshakeHash.Sum(nil)
	clientAppSecret := deriveSecret(s.params, masterSecret, labelClientApplicationTrafficSecret, h4)
	serverAppSecret := deriveSecret(s.params, masterSecret, labelServerApplicationTrafficSecret, h4)

	// Serialize AuthInfo
	authInfo := fAuthInfo{
		KeyID:     s.serverKeyID,
		Signature: cv.Signature,
		MAC:       serverFinishedData,
	}

	authInfoData, err := syntax.Marshal(authInfo)
	if err != nil {
		return nil, err
	}

	// Encrypt AuthInfo
	keys := makeTrafficKeys(s.params, serverHandshakeTrafficSecret)
	aead, err := keys.Cipher(keys.Keys[labelForKey])
	if err != nil {
		return nil, err
	}

	ct := aead.Seal(nil, keys.Keys[labelForIV], authInfoData, nil)

	// Construct message
	m2 := &fMessage2{
		DH:          pub,
		Ciphertext2: ct,
	}

	s.masterSecret = masterSecret
	s.clientHandshakeTrafficSecret = clientHandshakeTrafficSecret
	s.clientAppSecret = clientAppSecret
	s.serverAppSecret = serverAppSecret
	s.handshakeHash = handshakeHash
	return m2, nil
}

func (s *fServer) HandleMessage3(m3 *fMessage3) error {
	// Decrypt
	keys := makeTrafficKeys(s.params, s.clientHandshakeTrafficSecret)
	aead, err := keys.Cipher(keys.Keys[labelForKey])
	if err != nil {
		return err
	}

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
	if !bytes.Equal(authInfo.KeyID, s.clientKeyID) {
		return fmt.Errorf("Incorrect key ID")
	}

	// Verify Signature
	s.handshakeHash.Write(authInfo.KeyID)
	hscv := s.handshakeHash.Sum(nil)
	cv := &CertificateVerifyBody{
		Algorithm: s.scheme,
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
