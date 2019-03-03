package mint

// TODO Add connection IDs to make it equivalent to EDHOC

import (
	"bytes"
	"crypto"
	"crypto/hmac"
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

func computeAuthInfo(params CipherSuiteParams, scheme SignatureScheme, handshakeHash hash.Hash, masterSecret, handshakeTrafficSecret, keyID []byte, sigPriv crypto.Signer) ([]byte, error) {
	handshakeHash.Write(keyID)
	hcv := handshakeHash.Sum(nil)
	cv := &CertificateVerifyBody{Algorithm: scheme}
	cv.Sign(sigPriv, hcv)
	sig := cv.Signature
	handshakeHash.Write(sig)

	// Compute MAC
	h3 := handshakeHash.Sum(nil)
	finishedData := computeFinishedData(params, handshakeTrafficSecret, h3)
	handshakeHash.Write(finishedData)

	// Serialize AuthInfo
	authInfo := fAuthInfo{
		KeyID:     keyID,
		Signature: cv.Signature,
		MAC:       finishedData,
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

func verifyAuthInfo(params CipherSuiteParams, scheme SignatureScheme, handshakeHash hash.Hash, ct, handshakeTrafficSecret, keyID []byte, sigPub crypto.PublicKey) error {
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

	// Verify KeyID is known
	if !bytes.Equal(authInfo.KeyID, keyID) {
		return fmt.Errorf("Incorrect key ID")
	}

	// Verify Signature
	handshakeHash.Write(keyID)
	hscv := handshakeHash.Sum(nil)
	cv := &CertificateVerifyBody{
		Algorithm: scheme,
		Signature: authInfo.Signature,
	}
	err = cv.Verify(sigPub, hscv)
	if err != nil {
		return err
	}

	// Verify MAC
	handshakeHash.Write(authInfo.Signature)
	h3 := handshakeHash.Sum(nil)
	clientFinishedData := computeFinishedData(params, handshakeTrafficSecret, h3)
	if !hmac.Equal(authInfo.MAC, clientFinishedData) {
		return fmt.Errorf("Incorrect finished MAC")
	}

	handshakeHash.Write(authInfo.MAC)
	return nil
}

//////////

type fConfig struct {
	group  NamedGroup
	scheme SignatureScheme
	params CipherSuiteParams

	myPriv  crypto.Signer
	peerPub crypto.PublicKey

	myKeyID   []byte
	peerKeyID []byte
}

type fClient struct {
	fConfig

	// Ephemeral state
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
		Ciphertext3: encAuthInfo,
	}
	return m3, nil
}

//////////

type fServer struct {
	fConfig

	// Ephemeral state
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
	return verifyAuthInfo(s.params, s.scheme, s.handshakeHash, m3.Ciphertext3, s.clientHandshakeTrafficSecret, s.peerKeyID, s.peerPub)
}
