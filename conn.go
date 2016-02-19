package mint

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

type Config struct {
	// TODO
}

// Conn implements the net.Conn interface, as with "crypto/tls"
// * Read, Write, and Close are provided locally
// * LocalAddr, RemoteAddr, and Set*Deadline are forwarded to the inner Conn
type Conn struct {
	isClient bool

	handshakeErr      error
	handshakeComplete bool

	conn    net.Conn
	in, out *recordLayer
	context cryptoContext
}

// Read application data until the buffer is full.  Handshake and alert records
// are consumed by the Conn object directly.
func (c *Conn) Read(b []byte) (int, error) {
	// TODO
	// Handshake if necessary
	// Lock the input channel
	// While the buffer isn't full
	// * Read record
	// * application data => buffer
	// * alert => error
	// * handshake => process locally
	//
	// *** Need to understand the race condition in the crypto/tls code
	return 0, nil
}

// Write application data
func (c *Conn) Write(b []byte) (int, error) {
	// TODO
	// Lock the output channel
	// Write records
	return 0, nil
}

// Close closes the connection.
func (c *Conn) Close() error {
	// TODO
	// Look at the special mojo in crypto/tls
	// Send closeNotify alert
	// Close the connection
	return nil
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

// SetDeadline sets the read and write deadlines associated with the connection.
// A zero value for t means Read and Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
// A zero value for t means Read will not time out.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the write deadline on the underlying connection.
// A zero value for t means Write will not time out.
// After a Write has timed out, the TLS state is corrupt and all future writes will return the same error.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) Handshake() error {
	// TODO Lock handshakeMutex
	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.handshakeComplete {
		return nil
	}

	if c.isClient {
		c.handshakeErr = c.clientHandshake()
	} else {
		c.handshakeErr = c.serverHandshake()
	}
	return c.handshakeErr
}

func (c *Conn) clientHandshake() error {
	hIn := newHandshakeLayer(c.in)
	hOut := newHandshakeLayer(c.out)

	// XXX Config
	config_serverName := "example.com"
	config_cipherSuites := []cipherSuite{
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
	config_keyShareGroups := []namedGroup{namedGroupP256, namedGroupP384, namedGroupP521}
	config_signatureAlgorithms := []signatureAndHashAlgorithm{
		signatureAndHashAlgorithm{hash: hashAlgorithmSHA256, signature: signatureAlgorithmRSA},
		signatureAndHashAlgorithm{hash: hashAlgorithmSHA384, signature: signatureAlgorithmECDSA},
	}

	// Construct some extensions
	privateKeys := map[namedGroup][]byte{}
	ks := keyShareExtension{
		roleIsServer: false,
		shares:       make([]keyShare, len(config_keyShareGroups)),
	}
	for i, group := range config_keyShareGroups {
		pub, priv, err := newKeyShare(group)
		if err != nil {
			return err
		}

		ks.shares[i].group = group
		ks.shares[i].keyExchange = pub
		privateKeys[group] = priv
	}
	sni := serverNameExtension(config_serverName)
	sg := supportedGroupsExtension{groups: config_keyShareGroups}
	sa := signatureAlgorithmsExtension{algorithms: config_signatureAlgorithms}

	// Construct and write ClientHello
	ch := &clientHelloBody{
		cipherSuites: config_cipherSuites,
	}
	ch.extensions.Add(&sni)
	ch.extensions.Add(&ks)
	ch.extensions.Add(&sg)
	ch.extensions.Add(&sa)
	err := hOut.WriteMessageBody(ch)
	if err != nil {
		return err
	}

	// Read ServerHello
	sh := new(serverHelloBody)
	err = hIn.ReadMessageBody(sh)
	if err != nil {
		return err
	}

	// Read the key_share extension and do key agreement
	serverKeyShares := keyShareExtension{roleIsServer: true}
	found := sh.extensions.Find(&serverKeyShares)
	if !found {
		return err
	}
	sks := serverKeyShares.shares[0]
	priv, ok := privateKeys[sks.group]
	if !ok {
		fmt.Errorf("tls.client: Server sent a private key for a group we didn't send")
	}
	ES, err := keyAgreement(sks.group, sks.keyExchange, priv)
	if err != nil {
		panic(err)
	}

	// Init crypto context and rekey
	ctx := cryptoContext{}
	ctx.Init(ch, sh, ES, ES, sh.cipherSuite)
	err = c.in.Rekey(ctx.suite, ctx.handshakeKeys.serverWriteKey, ctx.handshakeKeys.serverWriteIV)
	if err != nil {
		return err
	}
	err = c.out.Rekey(ctx.suite, ctx.handshakeKeys.serverWriteKey, ctx.handshakeKeys.serverWriteIV)
	if err != nil {
		return err
	}

	// Read to Finished
	transcript := []handshakeMessageBody{}
	var finishedMessage *handshakeMessage
	for {
		hm, err := hIn.ReadMessage()
		if err != nil {
			return err
		}
		if hm.msgType == handshakeTypeFinished {
			finishedMessage = hm
			break
		}

		body, err := hm.toBody()
		if err != nil {
			return err
		}
		transcript = append(transcript, body)
	}

	// TODO: Find and verify Certificate/CertificateVerify

	// Update the crypto context with all but the Finished
	ctx.Update(transcript)

	// Verify server finished
	sfin := new(finishedBody)
	sfin.verifyDataLen = ctx.serverFinished.verifyDataLen
	_, err = sfin.Unmarshal(finishedMessage.body)
	if err != nil {
		return err
	}
	if !bytes.Equal(sfin.verifyData, ctx.serverFinished.verifyData) {
		return fmt.Errorf("tls.client: Server's Finished failed to verify")
	}

	// Send client Finished
	err = hOut.WriteMessageBody(ctx.clientFinished)
	if err != nil {
		return err
	}

	// Rekey to application keys
	err = c.in.Rekey(ctx.suite, ctx.applicationKeys.serverWriteKey, ctx.applicationKeys.serverWriteIV)
	if err != nil {
		return err
	}
	err = c.out.Rekey(ctx.suite, ctx.applicationKeys.serverWriteKey, ctx.applicationKeys.serverWriteIV)
	if err != nil {
		return err
	}

	c.context = ctx
	return nil
}

func (c *Conn) serverHandshake() error {
	hIn := newHandshakeLayer(c.in)
	hOut := newHandshakeLayer(c.out)

	// Config
	config_supportedGroup := map[namedGroup]bool{
		namedGroupP384: true,
		namedGroupP521: true,
	}
	config_supportedCiphersuite := map[cipherSuite]bool{
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
	}

	// Read ClientHello and extract extensions
	ch := new(clientHelloBody)
	err := hIn.ReadMessageBody(ch)
	if err != nil {
		return err
	}

	serverName := new(serverNameExtension)
	supportedGroups := new(supportedGroupsExtension)
	signatureAlgorithms := new(signatureAlgorithmsExtension)
	clientKeyShares := &keyShareExtension{roleIsServer: false}

	gotServerName := ch.extensions.Find(serverName)
	gotSupportedGroups := ch.extensions.Find(supportedGroups)
	gotSignatureAlgorithms := ch.extensions.Find(signatureAlgorithms)
	gotKeyShares := ch.extensions.Find(clientKeyShares)
	if !gotServerName || !gotSupportedGroups || !gotSignatureAlgorithms || !gotKeyShares {
		return fmt.Errorf("tls.server: Missing extension in ClientHello")
	}

	// Find key_share extension and do key agreement
	var serverKeyShare *keyShareExtension
	var ES []byte
	for _, share := range clientKeyShares.shares {
		if config_supportedGroup[share.group] {
			pub, priv, err := newKeyShare(share.group)
			if err != nil {
				return err
			}

			ES, err = keyAgreement(share.group, share.keyExchange, priv)
			serverKeyShare = &keyShareExtension{
				roleIsServer: true,
				shares:       []keyShare{keyShare{group: share.group, keyExchange: pub}},
			}
			break
		}
	}
	if serverKeyShare == nil || len(ES) == 0 {
		return fmt.Errorf("tls.server: Key agreement failed")
	}

	// Pick a ciphersuite
	var chosenSuite cipherSuite
	foundCipherSuite := false
	for _, suite := range ch.cipherSuites {
		if config_supportedCiphersuite[suite] {
			chosenSuite = suite
			foundCipherSuite = true
		}
	}
	if !foundCipherSuite {
		return fmt.Errorf("tls.server: No acceptable ciphersuites")
	}

	// Create and write ServerHello
	sh := &serverHelloBody{
		cipherSuite: chosenSuite,
	}
	sh.extensions.Add(serverKeyShare)
	err = hOut.WriteMessageBody(sh)
	if err != nil {
		return err
	}

	// Init context and rekey to handshake keys
	ctx := cryptoContext{}
	ctx.Init(ch, sh, ES, ES, chosenSuite)
	err = c.in.Rekey(ctx.suite, ctx.handshakeKeys.serverWriteKey, ctx.handshakeKeys.serverWriteIV)
	if err != nil {
		return err
	}
	err = c.out.Rekey(ctx.suite, ctx.handshakeKeys.serverWriteKey, ctx.handshakeKeys.serverWriteIV)
	if err != nil {
		return err
	}

	// TODO Create and send Certificate, CertificateVerify
	transcript := []handshakeMessageBody{}
	ctx.Update(transcript)

	// Update the crypto context

	// Create and write server Finished
	err = hOut.WriteMessageBody(ctx.serverFinished)
	if err != nil {
		return err
	}

	// Read and verify client Finished
	cfin := new(finishedBody)
	cfin.verifyDataLen = ctx.clientFinished.verifyDataLen
	err = hIn.ReadMessageBody(cfin)
	if err != nil {
		return err
	}
	if !bytes.Equal(cfin.verifyData, ctx.clientFinished.verifyData) {
		return fmt.Errorf("tls.client: Client's Finished failed to verify")
	}

	// Rekey to application keys
	err = c.in.Rekey(ctx.suite, ctx.applicationKeys.serverWriteKey, ctx.applicationKeys.serverWriteIV)
	if err != nil {
		return err
	}
	err = c.out.Rekey(ctx.suite, ctx.applicationKeys.serverWriteKey, ctx.applicationKeys.serverWriteIV)
	if err != nil {
		return err
	}

	c.context = ctx
	return nil
}
