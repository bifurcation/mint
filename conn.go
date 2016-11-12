package mint

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
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
	CipherSuite  CipherSuite
	IsResumption bool
	Identity     []byte
	Key          []byte
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
	AuthCertificate func(chain []certificateEntry) error // TODO(#20) -> Both

	// Server fields
	Certificates       []*Certificate
	SendSessionTickets bool
	TicketLifetime     uint32
	TicketLen          int

	// Shared fields
	CipherSuites     []CipherSuite
	Groups           []namedGroup
	SignatureSchemes []SignatureScheme
	NextProtos       []string
	PSKs             map[string]PreSharedKey

	// Hidden fields (used for caching in convenient form)
	enabledSuite  map[CipherSuite]bool
	enabledGroup  map[namedGroup]bool
	enabledProto  map[string]bool
	enabledScheme map[SignatureScheme]bool
	certsByName   map[string]*Certificate

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
	if len(c.SignatureSchemes) == 0 {
		c.SignatureSchemes = defaultSignatureSchemes
	}
	if c.TicketLen == 0 {
		c.TicketLen = defaultTicketLen
	}
	if c.PSKs == nil {
		c.PSKs = map[string]PreSharedKey{}
	}

	// If there is no certificate, generate one
	if !isClient && len(c.Certificates) == 0 {
		priv, err := newSigningKey(RSA_PSS_SHA256)
		if err != nil {
			return err
		}

		cert, err := newSelfSigned(c.ServerName, RSA_PKCS1_SHA256, priv)
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
	defaultSupportedCipherSuites = []CipherSuite{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
	}

	defaultSupportedGroups = []namedGroup{
		namedGroupP256,
		namedGroupP384,
		namedGroupFF2048,
		namedGroupX25519,
	}

	defaultSignatureSchemes = []SignatureScheme{
		RSA_PSS_SHA256,
		RSA_PSS_SHA384,
		RSA_PSS_SHA512,
		ECDSA_P256_SHA256,
		ECDSA_P384_SHA384,
		ECDSA_P521_SHA512,
	}

	defaultTicketLen = 16
)

type ConnectionState struct {
	HandshakeComplete bool                // TLS handshake is complete
	CipherSuite       CipherSuite         // cipher suite in use (TLS_RSA_WITH_RC4_128_SHA, ...)
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
	earlyCipherSuite CipherSuite

	handshakeMutex    sync.Mutex
	handshakeErr      error
	handshakeComplete bool

	certificateList []certificateEntry

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

					logf(logTypeHandshake, "Storing new session ticket with identity [%v]", tkt.Ticket)
					psk := PreSharedKey{
						CipherSuite:  c.context.suite,
						IsResumption: true,
						Identity:     tkt.Ticket,
						Key:          c.context.resumptionSecret,
					}
					c.config.PSKs[c.config.ServerName] = psk

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
	certList := make([]*x509.Certificate, len(c.certificateList))
	for i, entry := range c.certificateList {
		certList[i] = entry.certData
	}

	return ConnectionState{
		HandshakeComplete: c.handshakeComplete,
		CipherSuite:       c.context.suite,
		PeerCertificates:  certList,
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

	h := &clientHandshake{}
	hIn := newHandshakeLayer(c.in)
	hOut := newHandshakeLayer(c.out)

	// Generate ClientHello
	caps := capabilities{
		CipherSuites:     c.config.CipherSuites,
		Groups:           c.config.Groups,
		SignatureSchemes: c.config.SignatureSchemes,
		PSKs:             c.config.PSKs,
	}
	opts := connectionOptions{
		ServerName: c.config.ServerName,
		NextProtos: c.config.NextProtos,
		EarlyData:  c.earlyData,
	}

	chm, err := h.CreateClientHello(opts, caps)
	if err != nil {
		return err
	}

	// Write ClientHello
	err = hOut.WriteMessage(chm)
	if err != nil {
		return err
	}

	// Send early data
	if opts.EarlyData != nil {
		// Rekey output to early data keys
		logf(logTypeHandshake, "[client] Rekey -> early...")
		err = c.out.Rekey(h.Context.params.cipher, h.Context.clientEarlyTrafficKeys.key, h.Context.clientEarlyTrafficKeys.iv)
		if err != nil {
			return err
		}

		// Send early application data
		logf(logTypeHandshake, "[client] Sending data...")
		_, err = c.Write(opts.EarlyData)
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

	// Read and Process ServerHello
	logf(logTypeHandshake, "[client] Awaiting ServerHello")
	shm, err := hIn.ReadMessage()
	if err != nil {
		logf(logTypeHandshake, "[client] Error reading ServerHello")
		return err
	}
	logf(logTypeHandshake, "[client] Received ServerHello")

	err = h.HandleServerHello(shm)
	if err != nil {
		return err
	}

	// Rekey to handshake keys
	err = c.in.Rekey(h.Context.params.cipher, h.Context.serverHandshakeKeys.key, h.Context.serverHandshakeKeys.iv)
	if err != nil {
		logf(logTypeHandshake, "[client] Unable to rekey inbound")
		return err
	}
	err = c.out.Rekey(h.Context.params.cipher, h.Context.clientHandshakeKeys.key, h.Context.clientHandshakeKeys.iv)
	if err != nil {
		logf(logTypeHandshake, "[client] Unable to rekey outbound")
		return err
	}
	logf(logTypeHandshake, "[client] Completed rekey")
	dumpCryptoContext("client", h.Context)

	// Read and process server's first flight
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
			transcript = append(transcript, hm)
		}
	}
	logf(logTypeHandshake, "[client] Done reading server's first flight")

	err = h.HandleServerFirstFlight(transcript, finishedMessage)
	if err != nil {
		return err
	}

	// Update the crypto context with the (empty) client second flight
	err = h.Context.updateWithClientSecondFlight(nil)
	if err != nil {
		return err
	}

	// Send client Finished
	_, err = hOut.WriteMessageBody(h.Context.clientFinished)
	if err != nil {
		return err
	}

	// Rekey to application keys
	err = c.in.Rekey(h.Context.params.cipher, h.Context.serverTrafficKeys.key, h.Context.serverTrafficKeys.iv)
	if err != nil {
		return err
	}
	err = c.out.Rekey(h.Context.params.cipher, h.Context.clientTrafficKeys.key, h.Context.clientTrafficKeys.iv)
	if err != nil {
		return err
	}

	c.context = h.Context
	return nil
}

func (c *Conn) serverHandshake() error {
	logf(logTypeHandshake, "Starting serverHandshake")

	h := &serverHandshake{}
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

	// Create the server's first flight
	caps := capabilities{
		CipherSuites:     c.config.CipherSuites,
		Groups:           c.config.Groups,
		SignatureSchemes: c.config.SignatureSchemes,
		PSKs:             c.config.PSKs,
		NextProtos:       c.config.NextProtos,
		Certificates:     c.config.Certificates,
	}
	shm, serverFirstFlight, signaledEarlyData, err := h.HandleClientHello(chm, caps)
	if err != nil {
		return err
	}

	// Write ServerHello and update the crypto context
	err = hOut.WriteMessage(shm)
	if err != nil {
		logf(logTypeHandshake, "[server] Unable to send ServerHello %v", err)
		return err
	}
	logf(logTypeHandshake, "[server] Wrote ServerHello")

	// Rekey outbound to handshake keys
	err = c.out.Rekey(h.Context.params.cipher, h.Context.serverHandshakeKeys.key, h.Context.serverHandshakeKeys.iv)
	if err != nil {
		return err
	}
	logf(logTypeHandshake, "[server] Completed rekey")
	dumpCryptoContext("server", h.Context)

	// Write remainder of server first flight
	for _, msg := range serverFirstFlight {
		err := hOut.WriteMessage(msg)
		if err != nil {
			logf(logTypeHandshake, "[server] Unable to send handshake message %v", err)
			return err
		}
	}

	// Find early_data extension and handle early data
	if signaledEarlyData {
		logf(logTypeHandshake, "[server] Processing early data")

		// Compute early handshake / traffic keys from pskSecret
		// XXX: We init different contexts for early vs. main handshakes, that
		// means that in principle, we could end up with different ciphersuites for
		// early data vs. the main record flow.  Probably not ideal.
		logf(logTypeHandshake, "[server] Computing early secrets...")
		h.Context.earlyUpdateWithClientHello(chm)

		// Rekey read channel to early traffic keys
		logf(logTypeHandshake, "[server] Rekey -> handshake...")
		err = c.in.Rekey(h.Context.params.cipher, h.Context.clientEarlyTrafficKeys.key, h.Context.clientEarlyTrafficKeys.iv)
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
				logf(logTypeHandshake, "Alert record")
				alertType := alert(pt.fragment[1])
				if alertType == alertEndOfEarlyData {
					done = true
				} else {
					return fmt.Errorf("tls.server: Unexpected alert in early data [%v]", alertType)
				}
			case recordTypeApplicationData:
				// XXX: Should expose early data differently
				logf(logTypeHandshake, "App data")
				c.readBuffer = append(c.readBuffer, pt.fragment...)
			default:
				return fmt.Errorf("tls.server: Unexpected content type in early data [%v] %x", pt.contentType, pt.fragment)
			}
		}

		logf(logTypeHandshake, "[server] Done reading early data [%d] %x", len(c.readBuffer), c.readBuffer)
	}

	// Rekey input to handshake keys
	err = c.in.Rekey(h.Context.params.cipher, h.Context.clientHandshakeKeys.key, h.Context.clientHandshakeKeys.iv)
	if err != nil {
		return err
	}

	// Read and process the client's second flight
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
			transcript = append(transcript, hm)
		}
	}
	logf(logTypeHandshake, "[client] Done reading server's first flight")

	err = h.HandleClientSecondFlight(transcript, finishedMessage)
	if err != nil {
		return err
	}

	// Rekey to application keys
	err = c.in.Rekey(h.Context.params.cipher, h.Context.clientTrafficKeys.key, h.Context.clientTrafficKeys.iv)
	if err != nil {
		return err
	}
	err = c.out.Rekey(h.Context.params.cipher, h.Context.serverTrafficKeys.key, h.Context.serverTrafficKeys.iv)
	if err != nil {
		return err
	}

	// Send a new session ticket
	if c.config.SendSessionTickets {
		newPSK, newSessionTicket, err := h.CreateNewSessionTicket(c.config.TicketLen, c.config.TicketLifetime)
		if err != nil {
			return err
		}

		pskIDHex := hex.EncodeToString(newPSK.Identity)
		c.config.PSKs[pskIDHex] = newPSK

		err = hOut.WriteMessage(newSessionTicket)
		if err != nil {
			return err
		}
		logf(logTypeHandshake, "Wrote NewSessionTicket %x", newPSK.Identity)
	}

	c.context = h.Context
	return nil
}
