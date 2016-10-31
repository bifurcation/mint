package mint

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

type Certificate struct {
	Chain      []*x509.Certificate
	PrivateKey crypto.Signer
}

type PreSharedKey struct {
	Identity []byte
	Key      []byte
	Context  []byte
}

// Config is the struct used to pass configuration settings to a TLS client or
// server instance.  The settings for client and server are pretty different,
// but we just throw them all in here.
type Config struct {
	// Only in crypto/tls:
	// SessionTicketsDisabled   bool               // TODO(#6) -> Both
	// SessionTicketKey         [32]byte           // TODO(#6) -> Server
	// Rand                     io.Reader          // TODO(#23) -> Both
	// PreferServerCipherSuites bool               // TODO(#22) -> Server
	// NextProtos               []string           // TODO(#21) -> Both
	// ClientAuth               ClientAuthType     // TODO(#20)
	// NameToCertificate        map[string]*Certificate // Unused (simplicity)
	// GetCertificate           func(clientHello *ClientHelloInfo) (*Certificate, error) // Unused (simplicity)
	// ClientCAs                *x509.CertPool     // Unused (no PKI)
	// RootCAs                  *x509.CertPool     // Unused (no PKI)
	// InsecureSkipVerify       bool               // Unused (no PKI)
	// MinVersion               uint16             // Unused (only 1.3)
	// MaxVersion               uint16             // Unused (only 1.3)
	// Time                     func() time.Time   // Unused (no time in 1.3)
	// ClientSessionCache       ClientSessionCache // Unused (PSKs only in 1.3)

	// Only here:
	// AuthCertificate          func(chain []*x509.Certificate) error
	// ClientPSKs               map[string]PreSharedKey
	// ServerPSKs               []PreSharedKey

	// ---------------------------------------

	// Client fields
	ServerName      string
	AuthCertificate func(chain []*x509.Certificate) error // TODO(#20) -> Both
	ClientPSKs      map[string]PreSharedKey

	// Server fields
	Certificates       []*Certificate
	ServerPSKs         []PreSharedKey
	SendSessionTickets bool
	TicketLifetime     uint32
	TicketLen          int

	// Shared fields
	CipherSuites        []cipherSuite
	Groups              []namedGroup
	SignatureAlgorithms []signatureAndHashAlgorithm
	NextProtos          []string

	// Hidden fields (used for caching in convenient form)
	enabledSuite map[cipherSuite]bool
	enabledGroup map[namedGroup]bool
	enabledProto map[string]bool
	certsByName  map[string]*Certificate

	// The same config object can be shared among different connections, so it
	// needs its own mutex
	mutex sync.RWMutex
}

func (c *Config) Init(isClient bool) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Set defaults
	if len(c.CipherSuites) == 0 {
		c.CipherSuites = defaultSupportedCipherSuites
	}
	if len(c.Groups) == 0 {
		c.Groups = defaultSupportedGroups
	}
	if len(c.SignatureAlgorithms) == 0 {
		c.SignatureAlgorithms = defaultSignatureAlgorithms
	}
	if c.TicketLen == 0 {
		c.TicketLen = defaultTicketLen
	}
	if c.ClientPSKs == nil {
		c.ClientPSKs = map[string]PreSharedKey{}
	}

	// If there is no certificate, generate one
	if !isClient && len(c.Certificates) == 0 {
		priv, err := newSigningKey(signatureAlgorithmRSA)
		if err != nil {
			return err
		}

		cert, err := newSelfSigned(c.ServerName,
			signatureAndHashAlgorithm{
				hashAlgorithmSHA256,
				signatureAlgorithmRSA,
			},
			priv)
		if err != nil {
			return err
		}

		c.Certificates = []*Certificate{
			&Certificate{
				Chain:      []*x509.Certificate{cert},
				PrivateKey: priv,
			},
		}
	}

	// Build caches
	c.enabledSuite = map[cipherSuite]bool{}
	c.enabledGroup = map[namedGroup]bool{}
	c.enabledProto = map[string]bool{}
	c.certsByName = map[string]*Certificate{}

	for _, group := range c.Groups {
		c.enabledGroup[group] = true
	}
	for _, cert := range c.Certificates {
		if len(cert.Chain) == 0 {
			continue
		}
		for _, name := range cert.Chain[0].DNSNames {
			c.certsByName[name] = cert
		}
		for _, suite := range c.CipherSuites {
			if cipherSuiteMap[suite].sig == signatureAlgorithmRSA {
				if cert.Chain[0].PublicKeyAlgorithm == x509.RSA {
					c.enabledSuite[suite] = true
				}
			} else if cipherSuiteMap[suite].sig == signatureAlgorithmECDSA {
				if cert.Chain[0].PublicKeyAlgorithm == x509.ECDSA {
					c.enabledSuite[suite] = true
				}
			} else {
				// PSK modes work for every handshake signature type
				c.enabledSuite[suite] = true
			}
		}
	}
	for _, proto := range c.NextProtos {
		c.enabledProto[proto] = true
	}
	logf(logTypeCrypto, "Enabled suites [%v]", c.enabledSuite)

	return nil
}

func (c Config) validForServer() bool {
	return len(c.Certificates) > 0 &&
		len(c.Certificates[0].Chain) > 0 &&
		c.Certificates[0].PrivateKey != nil
}

func (c Config) validForClient() bool {
	return len(c.ServerName) > 0
}

var (
	defaultSupportedCipherSuites = []cipherSuite{
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_PSK_WITH_AES_128_GCM_SHA256,
		TLS_PSK_WITH_AES_256_GCM_SHA384,
		TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
		TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
		TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
	}

	defaultSupportedGroups = []namedGroup{
		namedGroupP256,
		namedGroupP384,
		namedGroupFF2048,
	}

	defaultSignatureAlgorithms = []signatureAndHashAlgorithm{
		signatureAndHashAlgorithm{hashAlgorithmSHA256, signatureAlgorithmRSA},
		signatureAndHashAlgorithm{hashAlgorithmSHA256, signatureAlgorithmECDSA},
		signatureAndHashAlgorithm{hashAlgorithmSHA384, signatureAlgorithmRSA},
		signatureAndHashAlgorithm{hashAlgorithmSHA384, signatureAlgorithmECDSA},
		signatureAndHashAlgorithm{hashAlgorithmSHA512, signatureAlgorithmRSA},
		signatureAndHashAlgorithm{hashAlgorithmSHA512, signatureAlgorithmECDSA},
	}

	defaultTicketLen = 16
)

type ConnectionState struct {
	HandshakeComplete bool                // TLS handshake is complete
	CipherSuite       cipherSuite         // cipher suite in use (TLS_RSA_WITH_RC4_128_SHA, ...)
	PeerCertificates  []*x509.Certificate // certificate chain presented by remote peer
}

// Conn implements the net.Conn interface, as with "crypto/tls"
// * Read, Write, and Close are provided locally
// * LocalAddr, RemoteAddr, and Set*Deadline are forwarded to the inner Conn
type Conn struct {
	config   *Config
	conn     net.Conn
	isClient bool

	earlyData        []byte
	earlyCipherSuite cipherSuite

	handshakeMutex    sync.Mutex
	handshakeErr      error
	handshakeComplete bool

	certificateList []*x509.Certificate

	readBuffer        []byte
	in, out           *recordLayer
	inMutex, outMutex sync.Mutex
	context           cryptoContext
}

func newConn(conn net.Conn, config *Config, isClient bool) *Conn {
	c := &Conn{conn: conn, config: config, isClient: isClient}
	c.in = newRecordLayer(c.conn)
	c.out = newRecordLayer(c.conn)
	return c
}

func (c *Conn) extendBuffer(n int) error {
	// XXX: crypto/tls bounds the number of empty records that can be read.  Should we?
	// if there's no more data left, stop reading
	if len(c.in.nextData) == 0 && len(c.readBuffer) > 0 {
		return nil
	}

	for len(c.readBuffer) <= n {
		pt, err := c.in.ReadRecord()

		if pt == nil {
			return err
		}

		switch pt.contentType {
		case recordTypeHandshake:
			// We do not support fragmentation of post-handshake handshake messages
			// TODO: Factor this more elegantly; coalesce with handshakeLayer.ReadMessage()
			start := 0
			for start < len(pt.fragment) {
				if len(pt.fragment[start:]) < handshakeHeaderLen {
					return fmt.Errorf("Post-handshake handshake message too short for header")
				}

				hm := &handshakeMessage{}
				hm.msgType = handshakeType(pt.fragment[start])
				hmLen := (int(pt.fragment[start+1]) << 16) + (int(pt.fragment[start+2]) << 8) + int(pt.fragment[start+3])

				if len(pt.fragment[start+handshakeHeaderLen:]) < hmLen {
					return fmt.Errorf("Post-handshake handshake message too short for body")
				}
				hm.body = pt.fragment[start+handshakeHeaderLen : start+handshakeHeaderLen+hmLen]

				switch hm.msgType {
				case handshakeTypeNewSessionTicket:
					var tkt newSessionTicketBody
					read, err := tkt.Unmarshal(hm.body)
					if err != nil {
						return err
					}
					if read != len(hm.body) {
						return fmt.Errorf("Malformed handshake message [%v] != [%v]", read, len(hm.body))
					}

					logf(logTypeHandshake, "Storing new session ticket with identity [%v]", tkt.ticket)
					psk := PreSharedKey{
						Identity: tkt.ticket,
						Key:      c.context.resumptionPSK,
						Context:  c.context.resumptionContext,
					}
					c.config.ClientPSKs[c.config.ServerName] = psk

				case handshakeTypeKeyUpdate:
					// TODO: Support KeyUpdate
					fallthrough
				default:
					c.sendAlert(alertUnexpectedMessage)
					return fmt.Errorf("Unsupported post-handshake handshake message [%v]", hm.msgType)
				}

				start += handshakeHeaderLen + hmLen
			}
		case recordTypeAlert:
			logf(logTypeIO, "extended buffer (for alert): [%d] %x", len(c.readBuffer), c.readBuffer)
			if len(pt.fragment) != 2 {
				c.sendAlert(alertUnexpectedMessage)
				return io.EOF
			}
			if alert(pt.fragment[1]) == alertCloseNotify {
				return io.EOF
			}

			switch pt.fragment[0] {
			case alertLevelWarning:
				// drop on the floor
			case alertLevelError:
				return alert(pt.fragment[1])
			default:
				c.sendAlert(alertUnexpectedMessage)
				return io.EOF
			}

		case recordTypeApplicationData:
			c.readBuffer = append(c.readBuffer, pt.fragment...)
			logf(logTypeIO, "extended buffer: [%d] %x", len(c.readBuffer), c.readBuffer)
		}

		if err != nil {
			return err
		}

		// if there's no more data left, stop reading
		if len(c.in.nextData) == 0 {
			return nil
		}

		// if we're over the limit and the next record is not an alert, exit
		if len(c.readBuffer) == n && recordType(c.in.nextData[0]) != recordTypeAlert {
			return nil
		}
	}
	return nil
}

// Read application data until the buffer is full.  Handshake and alert records
// are consumed by the Conn object directly.
func (c *Conn) Read(buffer []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	// Lock the input channel
	c.in.Lock()
	defer c.in.Unlock()

	n := len(buffer)
	err := c.extendBuffer(n)
	var read int
	if len(c.readBuffer) < n {
		buffer = buffer[:len(c.readBuffer)]
		copy(buffer, c.readBuffer)
		read = len(c.readBuffer)
		c.readBuffer = c.readBuffer[:0]
	} else {
		logf(logTypeIO, "read buffer larger than than input buffer")
		copy(buffer[:n], c.readBuffer[:n])
		c.readBuffer = c.readBuffer[n:]
		read = n
	}

	return read, err
}

// Write application data
func (c *Conn) Write(buffer []byte) (int, error) {
	// Lock the output channel
	c.out.Lock()
	defer c.out.Unlock()

	// Send full-size fragments
	var start int
	sent := 0
	for start = 0; len(buffer)-start >= maxFragmentLen; start += maxFragmentLen {
		err := c.out.WriteRecord(&tlsPlaintext{
			contentType: recordTypeApplicationData,
			fragment:    buffer[start : start+maxFragmentLen],
		})

		if err != nil {
			return sent, err
		}
		sent += maxFragmentLen
	}

	// Send a final partial fragment if necessary
	if start < len(buffer) {
		err := c.out.WriteRecord(&tlsPlaintext{
			contentType: recordTypeApplicationData,
			fragment:    buffer[start:],
		})

		if err != nil {
			return sent, err
		}
		sent += len(buffer[start:])
	}
	return sent, nil
}

// sendAlert sends a TLS alert message.
// c.out.Mutex <= L.
func (c *Conn) sendAlert(err alert) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	tmp := make([]byte, 2)
	switch err {
	case alertNoRenegotiation, alertCloseNotify:
		tmp[0] = alertLevelWarning
	default:
		tmp[0] = alertLevelError
	}
	tmp[1] = byte(err)
	c.out.WriteRecord(&tlsPlaintext{
		contentType: recordTypeAlert,
		fragment:    tmp},
	)

	// close_notify and end_of_early_data are not actually errors
	if err != alertCloseNotify && err != alertEndOfEarlyData {
		return &net.OpError{Op: "local error", Err: err}
	}
	return nil
}

// Close closes the connection.
func (c *Conn) Close() error {
	// XXX crypto/tls has an interlock with Write here.  Do we need that?

	c.sendAlert(alertCloseNotify)
	return c.conn.Close()
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

func (c *Conn) ConnectionState() ConnectionState {
	return ConnectionState{
		HandshakeComplete: c.handshakeComplete,
		CipherSuite:       c.context.suite,
		PeerCertificates:  c.certificateList,
	}
}

// Handshake causes a TLS handshake on the connection.  The `isClient` member
// determines whether a client or server handshake is performed.  If a
// handshake has already been performed, then its result will be returned.
func (c *Conn) Handshake() error {
	// TODO Lock handshakeMutex
	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.handshakeComplete {
		return nil
	}

	if err := c.config.Init(c.isClient); err != nil {
		return err
	}

	if c.isClient {
		c.handshakeErr = c.clientHandshake()
	} else {
		c.handshakeErr = c.serverHandshake()
	}
	c.handshakeComplete = (c.handshakeErr == nil)

	if c.handshakeErr != nil {
		logf(logTypeHandshake, "Handshake failed: %v", c.handshakeErr)
		c.sendAlert(alertHandshakeFailure)
		c.conn.Close()
	}

	return c.handshakeErr
}

func (c *Conn) clientHandshake() error {
	logf(logTypeHandshake, "Starting clientHandshake")

	hIn := newHandshakeLayer(c.in)
	hOut := newHandshakeLayer(c.out)

	// Construct some extensions
	logf(logTypeHandshake, "Constructing ClientHello")
	privateKeys := map[namedGroup][]byte{}
	ks := keyShareExtension{
		roleIsServer: false,
		shares:       make([]keyShare, len(c.config.Groups)),
	}
	for i, group := range c.config.Groups {
		pub, priv, err := newKeyShare(group)
		if err != nil {
			return err
		}

		ks.shares[i].group = group
		ks.shares[i].keyExchange = pub
		privateKeys[group] = priv
	}
	sv := supportedVersionsExtension{versions: []uint16{tlsVersion13}}
	sni := serverNameExtension(c.config.ServerName)
	sg := supportedGroupsExtension{groups: c.config.Groups}
	sa := signatureAlgorithmsExtension{algorithms: c.config.SignatureAlgorithms}
	dv := draftVersionExtension{version: draftVersionImplemented}

	var alpn *alpnExtension
	if (c.config.NextProtos != nil) && (len(c.config.NextProtos) > 0) {
		alpn = &alpnExtension{protocols: c.config.NextProtos}
	}

	var psk *preSharedKeyExtension
	if key, ok := c.config.ClientPSKs[c.config.ServerName]; ok {
		logf(logTypeHandshake, "Sending PSK")
		psk = &preSharedKeyExtension{
			roleIsServer: false,
			identities:   [][]byte{key.Identity},
		}
	} else {
		logf(logTypeHandshake, "No PSK found for [%v] in %+v", c.config.ServerName, c.config.ClientPSKs)
	}

	var ed *earlyDataExtension
	if c.earlyData != nil {
		if psk == nil {
			return fmt.Errorf("tls.client: Can't send early data without a PSK")
		}

		ed = &earlyDataExtension{
			cipherSuite: c.earlyCipherSuite,
		}
	}

	// Construct and write ClientHello
	ch := &clientHelloBody{
		cipherSuites: c.config.CipherSuites,
	}
	_, err := prng.Read(ch.random[:])
	if err != nil {
		return err
	}
	for _, ext := range []extensionBody{&sv, &sni, &ks, &sg, &sa, &dv} {
		err := ch.extensions.Add(ext)
		if err != nil {
			return err
		}
	}

	// XXX: These can't be folded into the above because Go interface-typed
	// values are never reported as nil
	if alpn != nil {
		err := ch.extensions.Add(alpn)
		if err != nil {
			return err
		}
	}
	if psk != nil {
		err := ch.extensions.Add(psk)
		if err != nil {
			return err
		}
	}
	if ed != nil {
		err := ch.extensions.Add(ed)
		if err != nil {
			return err
		}
	}
	chm, err := hOut.WriteMessageBody(ch)
	if err != nil {
		return err
	}
	logf(logTypeHandshake, "[client] Sent ClientHello")

	// Send early data
	if ed != nil {
		logf(logTypeHandshake, "[client] Processing early data...")
		// We will only get here if we sent exactly one PSK, and this is it
		pskSecret := c.config.ClientPSKs[c.config.ServerName].Key
		pskContext := c.config.ClientPSKs[c.config.ServerName].Context
		ctx := cryptoContext{}
		ctx.init(c.earlyCipherSuite, pskSecret)
		ctx.updateWithClientHello(chm, pskContext)

		// Rekey output to early handshake keys (in case we decide to send EE later)
		logf(logTypeHandshake, "[client] Rekey -> handshake...")
		err = c.out.Rekey(ctx.suite, ctx.earlyHandshakeKeys.clientWriteKey, ctx.earlyHandshakeKeys.clientWriteIV)
		if err != nil {
			return err
		}

		// No further handshake messages, go ahead and compute everything
		err = ctx.updateWithEarlyHandshake([]*handshakeMessage{})
		if err != nil {
			return err
		}

		// Send early finished message
		logf(logTypeHandshake, "[client] Sending Finished...")
		_, err = hOut.WriteMessageBody(ctx.earlyFinished)
		if err != nil {
			return err
		}

		// Rekey output to early data keys
		logf(logTypeHandshake, "[client] Rekey -> application...")
		err = c.out.Rekey(ctx.suite, ctx.earlyApplicationKeys.clientWriteKey, ctx.earlyApplicationKeys.clientWriteIV)
		if err != nil {
			return err
		}

		// Send early application data
		logf(logTypeHandshake, "[client] Sending data...")
		_, err = c.Write(c.earlyData)
		if err != nil {
			return err
		}

		// Send end_of_earlyData
		logf(logTypeHandshake, "[client] Sending end_of_early_data...")
		err = c.sendAlert(alertEndOfEarlyData)
		if err != nil {
			return err
		}
	}

	// Read ServerHello
	sh := new(serverHelloBody)
	shm, err := hIn.ReadMessageBody(sh)
	if err != nil {
		logf(logTypeHandshake, "[client] Error reading ServerHello")
		return err
	}
	logf(logTypeHandshake, "[client] Received ServerHello")

	// Do PSK or key agreement depending on the ciphersuite
	serverPSK := preSharedKeyExtension{roleIsServer: true}
	foundPSK := sh.extensions.Find(&serverPSK)
	serverKeyShare := keyShareExtension{roleIsServer: true}
	foundKeyShare := sh.extensions.Find(&serverKeyShare)

	var pskSecret, pskContext, dhSecret []byte
	if foundPSK && (serverPSK.selectedIdentity < uint16(len(psk.identities))) {
		pskSecret = c.config.ClientPSKs[c.config.ServerName].Key
		pskContext = c.config.ClientPSKs[c.config.ServerName].Context
		logf(logTypeHandshake, "[client] got PSK extension")
	}
	if foundKeyShare {
		sks := serverKeyShare.shares[0]
		priv, ok := privateKeys[sks.group]
		if !ok {
			return fmt.Errorf("Server key share for unknown group")
		}

		dhSecret, _ = keyAgreement(sks.group, sks.keyExchange, priv)
		logf(logTypeHandshake, "[client] got key share extension")
	}

	// Init crypto context
	ctx := cryptoContext{}
	err = ctx.init(sh.cipherSuite, pskSecret)
	if err != nil {
		return err
	}
	err = ctx.updateWithClientHello(chm, pskContext)
	if err != nil {
		return err
	}
	err = ctx.updateWithServerHello(shm, dhSecret)
	if err != nil {
		return err
	}

	// Rekey to handshake keys
	err = c.in.Rekey(ctx.suite, ctx.handshakeKeys.serverWriteKey, ctx.handshakeKeys.serverWriteIV)
	if err != nil {
		logf(logTypeHandshake, "[client] Unable to rekey inbound")
		return err
	}
	err = c.out.Rekey(ctx.suite, ctx.handshakeKeys.clientWriteKey, ctx.handshakeKeys.clientWriteIV)
	if err != nil {
		logf(logTypeHandshake, "[client] Unable to rekey outbound")
		return err
	}
	logf(logTypeHandshake, "[client] Completed rekey")
	dumpCryptoContext("client", ctx)

	// Read to Finished
	transcript := []*handshakeMessage{}
	var cert *certificateBody
	var certVerify *certificateVerifyBody
	var finishedMessage *handshakeMessage
	for {
		hm, err := hIn.ReadMessage()
		if err != nil {
			logf(logTypeHandshake, "Error reading message: %v", err)
			return err
		}
		logf(logTypeHandshake, "Read message with type: %v", hm.msgType)

		if hm.msgType == handshakeTypeFinished {
			finishedMessage = hm
			break
		} else {
			if hm.msgType == handshakeTypeCertificate {
				cert = new(certificateBody)
				_, err = cert.Unmarshal(hm.body)
			} else if hm.msgType == handshakeTypeCertificateVerify {
				certVerify = new(certificateVerifyBody)
				_, err = certVerify.Unmarshal(hm.body)
			}
			transcript = append(transcript, hm)
		}

		if err != nil {
			logf(logTypeHandshake, "Error processing handshake message: %v", err)
			return err
		}
	}
	logf(logTypeHandshake, "[client] Done reading server's first flight")

	// Verify the server's certificate if required
	if ctx.params.mode != handshakeModePSK && ctx.params.mode != handshakeModePSKAndDH {
		if cert == nil || certVerify == nil {
			return fmt.Errorf("tls.client: No server auth data provided")
		}
		c.certificateList = cert.certificateList

		transcriptForCertVerify := append([]*handshakeMessage{chm, shm}, transcript[:len(transcript)-1]...)
		logf(logTypeHandshake, "[client] Transcript for certVerify")
		for _, hm := range transcriptForCertVerify {
			logf(logTypeHandshake, "  [%d] %x", hm.msgType, hm.body)
		}
		logf(logTypeHandshake, "===")

		serverPublicKey := cert.certificateList[0].PublicKey
		if err = certVerify.Verify(serverPublicKey, transcriptForCertVerify, ctx); err != nil {
			return err
		}

		if c.config.AuthCertificate != nil {
			err = c.config.AuthCertificate(cert.certificateList)
			if err != nil {
				return err
			}
		}
	}

	// Update the crypto context with all but the Finished
	ctx.updateWithServerFirstFlight(transcript)

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

	// Update the crypto context with the (empty) client second flight
	err = ctx.updateWithClientSecondFlight(nil)
	if err != nil {
		return err
	}

	// Send client Finished
	_, err = hOut.WriteMessageBody(ctx.clientFinished)
	if err != nil {
		return err
	}

	// Rekey to application keys
	err = c.in.Rekey(ctx.suite, ctx.trafficKeys.serverWriteKey, ctx.trafficKeys.serverWriteIV)
	if err != nil {
		return err
	}
	err = c.out.Rekey(ctx.suite, ctx.trafficKeys.clientWriteKey, ctx.trafficKeys.clientWriteIV)
	if err != nil {
		return err
	}

	c.context = ctx
	return nil
}

func (c *Conn) serverHandshake() error {
	logf(logTypeHandshake, "Starting serverHandshake")

	hIn := newHandshakeLayer(c.in)
	hOut := newHandshakeLayer(c.out)

	// Read ClientHello and extract extensions
	ch := new(clientHelloBody)
	chm, err := hIn.ReadMessageBody(ch)
	if err != nil {
		logf(logTypeHandshake, "Unable to read ClientHello: %v", err)
		return err
	}
	logf(logTypeHandshake, "[server] Read ClientHello")

	supportedVersions := new(supportedVersionsExtension)
	serverName := new(serverNameExtension)
	supportedGroups := new(supportedGroupsExtension)
	signatureAlgorithms := new(signatureAlgorithmsExtension)
	clientKeyShares := &keyShareExtension{roleIsServer: false}
	clientPSK := &preSharedKeyExtension{roleIsServer: false}
	clientEarlyData := &earlyDataExtension{roleIsServer: false}
	clientALPN := new(alpnExtension)

	gotSupportedVersions := ch.extensions.Find(supportedVersions)
	gotServerName := ch.extensions.Find(serverName)
	gotSupportedGroups := ch.extensions.Find(supportedGroups)
	gotSignatureAlgorithms := ch.extensions.Find(signatureAlgorithms)
	gotKeyShares := ch.extensions.Find(clientKeyShares)
	gotPSK := ch.extensions.Find(clientPSK)
	gotEarlyData := ch.extensions.Find(clientEarlyData)
	gotALPN := ch.extensions.Find(clientALPN)

	// If the client didn't send supportedVersions or doesn't support 1.3,
	// then we're done here.
	if !gotSupportedVersions {
		logf(logTypeHandshake, "[server] Client did not send supported_versions")
		return fmt.Errorf("tls.server: Client did not send supported_versions")
	}
	clientSupports13 := false
	for _, version := range supportedVersions.versions {
		clientSupports13 = (version == tlsVersion13)
		if clientSupports13 {
			break
		}
	}
	if !clientSupports13 {
		logf(logTypeHandshake, "[server] Client does not support TLS 1.3")
		return fmt.Errorf("tls.server: Client does not support TLS 1.3")
	}

	// Find pre_shared_key extension and look it up
	var serverPSK *preSharedKeyExtension
	var pskSecret []byte
	var pskContext []byte
	if gotPSK {
		logf(logTypeHandshake, "[server] Got PSK extension; processing")
		for _, id := range clientPSK.identities {
			logf(logTypeHandshake, "[server] Client provided PSK identity %x", id)
		}

		for i, key := range c.config.ServerPSKs {
			logf(logTypeHandshake, "[server] Checking for %x", key.Identity)
			if clientPSK.HasIdentity(key.Identity) {
				logf(logTypeHandshake, "Matched %x", key.Identity)
				pskSecret = make([]byte, len(key.Key))
				copy(pskSecret, key.Key)
				pskContext = make([]byte, len(key.Context))
				copy(pskContext, key.Context)

				serverPSK = &preSharedKeyExtension{
					roleIsServer:     true,
					selectedIdentity: uint16(i),
				}
			}
		}
	}

	// Find the ALPN extension and select a protocol
	var serverALPN *alpnExtension
	if gotALPN {
		logf(logTypeHandshake, "[server] Got ALPN offer: %v", clientALPN.protocols)
		for _, proto := range clientALPN.protocols {
			if c.config.enabledProto[proto] {
				logf(logTypeHandshake, "[server] Sending ALPN value %v", proto)
				serverALPN = &alpnExtension{protocols: []string{proto}}
				break
			}
		}
	}

	// Find key_share extension and do key agreement
	var serverKeyShare *keyShareExtension
	var dhSecret []byte
	if gotKeyShares {
		logf(logTypeHandshake, "[server] Got KeyShare extension; processing")
		for _, share := range clientKeyShares.shares {
			if c.config.enabledGroup[share.group] {
				pub, priv, err := newKeyShare(share.group)
				if err != nil {
					return err
				}

				dhSecret, err = keyAgreement(share.group, share.keyExchange, priv)
				serverKeyShare = &keyShareExtension{
					roleIsServer: true,
					shares:       []keyShare{keyShare{group: share.group, keyExchange: pub}},
				}
				if err != nil {
					return err
				}
				break
			}
		}
	}

	// Find early_data extension and handle early data
	if gotEarlyData {
		logf(logTypeHandshake, "[server] Processing early data")

		// Can't do early data if we don't have a PSK
		// TODO Handle this more elegantly
		if pskSecret == nil {
			return fmt.Errorf("tls.server: EarlyData with no PSK")
		}
		if !c.config.enabledSuite[clientEarlyData.cipherSuite] {
			return fmt.Errorf("tls.server: EarlyData with an unsupported ciphersuite")
		}

		// Compute early handshake / traffic keys from pskSecret
		// XXX: We init different contexts for early vs. main handshakes, that
		// means that in principle, we could end up with different ciphersuites for
		// early data vs. the main record flow.  Probably not ideal.
		logf(logTypeHandshake, "[server] Computing early secrets...")
		ctx := cryptoContext{}
		ctx.init(clientEarlyData.cipherSuite, pskSecret)
		ctx.updateWithClientHello(chm, pskContext)

		// Rekey read channel to early handshake keys
		logf(logTypeHandshake, "[server] Rekey -> handshake...")
		err = c.in.Rekey(ctx.suite, ctx.earlyHandshakeKeys.clientWriteKey, ctx.earlyHandshakeKeys.clientWriteIV)
		if err != nil {
			return err
		}

		// Read to Finished
		transcript := []*handshakeMessage{}
		var finishedMessage *handshakeMessage
		for {
			hm, err := hIn.ReadMessage()
			if err != nil {
				logf(logTypeHandshake, "Error reading message: %v", err)
				return err
			}
			logf(logTypeHandshake, "Read message with type: %v", hm.msgType)

			if hm.msgType == handshakeTypeFinished {
				finishedMessage = hm
				break
			} else {
				// XXX: Other early handshake messages are ignored, but still included in the transcript
				transcript = append(transcript, hm)
			}
		}

		// Update crypto context with remainder of handshake and verify the Finished
		err = ctx.updateWithEarlyHandshake(transcript)
		if err != nil {
			return err
		}

		// Read Finished message and verify
		logf(logTypeHandshake, "[server] Reading finished...")
		earlyFin := new(finishedBody)
		earlyFin.verifyDataLen = ctx.earlyFinished.verifyDataLen
		_, err = earlyFin.Unmarshal(finishedMessage.body)
		if err != nil {
			return err
		}
		if !bytes.Equal(earlyFin.verifyData, ctx.earlyFinished.verifyData) {
			return fmt.Errorf("tls.client: Client's early Finished failed to verify")
		}

		// Rekey read channel to early traffic keys
		logf(logTypeHandshake, "[server] Rekey -> application...")
		err = c.in.Rekey(ctx.suite, ctx.earlyApplicationKeys.clientWriteKey, ctx.earlyApplicationKeys.clientWriteIV)
		if err != nil {
			return err
		}

		// Read to end of early data
		logf(logTypeHandshake, "[server] Reading early data...")
		done := false
		for !done {
			logf(logTypeHandshake, "  Record!")
			pt, err := c.in.ReadRecord()
			if err != nil {
				return err
			}

			switch pt.contentType {
			case recordTypeAlert:
				alertType := alert(pt.fragment[1])
				if alertType == alertEndOfEarlyData {
					done = true
				} else {
					return fmt.Errorf("tls.server: Unexpected alert in early data [%v]", alertType)
				}
			case recordTypeApplicationData:
				// XXX: Should expose early data differently
				c.readBuffer = append(c.readBuffer, pt.fragment...)
			default:
				return fmt.Errorf("tls.server: Unexpected content type in early data [%v] %x", pt.contentType, pt.fragment)
			}
		}

		logf(logTypeHandshake, "[server] Done reading early data [%d] %x", len(c.readBuffer), c.readBuffer)
	}

	// Pick a ciphersuite
	var chosenSuite cipherSuite
	foundCipherSuite := false
	sendKeyShare := false
	sendPSK := false
	for _, suite := range ch.cipherSuites {
		mode := cipherSuiteMap[suite].mode
		sendKeyShare = (mode == handshakeModeDH || mode == handshakeModePSKAndDH)
		sendPSK = (mode == handshakeModePSK || mode == handshakeModePSKAndDH)

		// Use a DH mode iff we have DH information
		if (sendKeyShare && (serverKeyShare == nil)) && (!sendKeyShare && (serverKeyShare != nil)) {
			continue
		}

		// Use a PSK mode iff we have a PSK
		if (sendPSK && (serverPSK == nil)) || (!sendPSK && (serverPSK != nil)) {
			continue
		}

		if c.config.enabledSuite[suite] {
			chosenSuite = suite
			foundCipherSuite = true
			break
		}
	}

	// If there are no matching suites and PSK is present, check non-PSK
	if !foundCipherSuite {
		for _, suite := range ch.cipherSuites {
			if c.config.enabledSuite[suite] {
				chosenSuite = suite
				foundCipherSuite = true
				break
			}
		}
	}

	logf(logTypeCrypto, "Supported Client suites [%v]", ch.cipherSuites)
	if !foundCipherSuite {
		logf(logTypeHandshake, "No acceptable ciphersuites")
		return fmt.Errorf("tls.server: No acceptable ciphersuites")
	}
	logf(logTypeHandshake, "[server] Chose CipherSuite %x", chosenSuite)

	// Init context and decide whether to send KeyShare/PreSharedKey
	ctx := cryptoContext{}
	err = ctx.init(chosenSuite, pskSecret)
	if err != nil {
		return err
	}
	err = ctx.updateWithClientHello(chm, pskContext)
	if err != nil {
		return err
	}
	logf(logTypeHandshake, "[server] Initialized context %v %v", sendKeyShare, sendPSK)

	// If we're not using a PSK mode, then we need to have certain extensions
	if !sendPSK && (!gotServerName || !gotSupportedGroups || !gotSignatureAlgorithms) {
		logf(logTypeHandshake, "[server] Insufficient extensions (%v %v %v %v)",
			gotServerName, gotSupportedGroups, gotSignatureAlgorithms, gotKeyShares)
		return fmt.Errorf("tls.server: Missing extension in ClientHello")
	}

	// Create the ServerHello
	sh := &serverHelloBody{
		cipherSuite: chosenSuite,
	}
	_, err = prng.Read(sh.random[:])
	if err != nil {
		return err
	}
	if sendKeyShare {
		logf(logTypeHandshake, "[server] sending key share extension")
		err = sh.extensions.Add(serverKeyShare)
		if err != nil {
			return err
		}
	} else {
		logf(logTypeHandshake, "[server] not key share extension; deleting DH secret")
		dhSecret = nil
	}
	if sendPSK {
		logf(logTypeHandshake, "[server] sending PSK extension")
		err = sh.extensions.Add(serverPSK)
		if err != nil {
			return err
		}
	}
	logf(logTypeHandshake, "[server] Done creating ServerHello")

	// Write ServerHello and update the crypto context
	shm, err := hOut.WriteMessageBody(sh)
	if err != nil {
		logf(logTypeHandshake, "[server] Unable to send ServerHello %v", err)
		return err
	}
	logf(logTypeHandshake, "[server] Wrote ServerHello")
	err = ctx.updateWithServerHello(shm, dhSecret)
	if err != nil {
		return err
	}

	// Rekey to handshake keys
	err = c.in.Rekey(ctx.suite, ctx.handshakeKeys.clientWriteKey, ctx.handshakeKeys.clientWriteIV)
	if err != nil {
		return err
	}
	err = c.out.Rekey(ctx.suite, ctx.handshakeKeys.serverWriteKey, ctx.handshakeKeys.serverWriteIV)
	if err != nil {
		return err
	}
	logf(logTypeHandshake, "[server] Completed rekey")
	dumpCryptoContext("server", ctx)

	// Send an EncryptedExtensions message (even if it's empty)
	eeList := extensionList{}
	if serverALPN != nil {
		logf(logTypeHandshake, "[server] sending ALPN extension")
		err = eeList.Add(serverALPN)
		if err != nil {
			return err
		}
	}
	ee := encryptedExtensionsBody(eeList)
	eem, err := hOut.WriteMessageBody(&ee)
	if err != nil {
		return err
	}
	transcript := []*handshakeMessage{eem}

	// Authenticate with a certificate if required
	if !sendPSK {
		// Select a certificate
		var privateKey crypto.Signer
		var chain []*x509.Certificate
		for _, cert := range c.config.Certificates {
			for _, name := range cert.Chain[0].DNSNames {
				if name == string(*serverName) {
					chain = cert.Chain
					privateKey = cert.PrivateKey
				}
			}
		}

		// If there's no name match, use the first in the list or fail
		if chain == nil {
			if len(c.config.Certificates) > 0 {
				chain = c.config.Certificates[0].Chain
				privateKey = c.config.Certificates[0].PrivateKey
			} else {
				return fmt.Errorf("No certificate found for %s", string(*serverName))
			}
		}

		// Create and send Certificate, CertificateVerify
		// TODO Certificate selection based on ClientHello
		certificate := &certificateBody{
			certificateList: chain,
		}
		certm, err := hOut.WriteMessageBody(certificate)
		if err != nil {
			return err
		}

		certificateVerify := &certificateVerifyBody{
			alg: signatureAndHashAlgorithm{hashAlgorithmSHA256, signatureAlgorithmRSA},
		}
		err = certificateVerify.Sign(privateKey, []*handshakeMessage{chm, shm, eem, certm}, ctx)
		if err != nil {
			return err
		}
		certvm, err := hOut.WriteMessageBody(certificateVerify)
		if err != nil {
			return err
		}

		transcript = append(transcript, []*handshakeMessage{certm, certvm}...)
	}

	// Update the crypto context (assumes no further client messages except Finished)
	err = ctx.updateWithServerFirstFlight(transcript)
	if err != nil {
		return err
	}
	err = ctx.updateWithClientSecondFlight(nil)
	if err != nil {
		return err
	}

	// Create and write server Finished
	_, err = hOut.WriteMessageBody(ctx.serverFinished)
	if err != nil {
		return err
	}

	// Read and verify client Finished
	cfin := new(finishedBody)
	cfin.verifyDataLen = ctx.clientFinished.verifyDataLen
	_, err = hIn.ReadMessageBody(cfin)
	if err != nil {
		return err
	}
	if !bytes.Equal(cfin.verifyData, ctx.clientFinished.verifyData) {
		return fmt.Errorf("tls.client: Client's Finished failed to verify")
	}

	// Rekey to application keys
	err = c.in.Rekey(ctx.suite, ctx.trafficKeys.clientWriteKey, ctx.trafficKeys.clientWriteIV)
	if err != nil {
		return err
	}
	err = c.out.Rekey(ctx.suite, ctx.trafficKeys.serverWriteKey, ctx.trafficKeys.serverWriteIV)
	if err != nil {
		return err
	}

	// Send a new session ticket
	tkt, err := newSessionTicket(c.config.TicketLen)
	if err != nil {
		return err
	}
	tkt.lifetime = c.config.TicketLifetime

	if c.config.SendSessionTickets {
		newPSK := PreSharedKey{
			Identity: tkt.ticket,
			Key:      ctx.resumptionPSK,
			Context:  ctx.resumptionContext,
		}
		c.config.ServerPSKs = append(c.config.ServerPSKs, newPSK)

		ticketBytes, err := tkt.Marshal()
		logf(logTypeHandshake, "About to write NewSessionTicket %x", ticketBytes)
		_, err = hOut.WriteMessageBody(tkt)
		if err != nil {
			logf(logTypeHandshake, "Returning error: %x", ticketBytes)
			return err
		}
		logf(logTypeHandshake, "Wrote NewSessionTicket %x", tkt.ticket)
	}

	c.context = ctx
	return nil
}
