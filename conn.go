package mint

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"reflect"
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
	NextProto    string
}

type PreSharedKeyCache interface {
	Get(string) (PreSharedKey, bool)
	Put(string, PreSharedKey)
	Size() int
}

type PSKMapCache map[string]PreSharedKey

func (cache PSKMapCache) Get(key string) (psk PreSharedKey, ok bool) {
	psk, ok = cache[key]
	return
}

func (cache *PSKMapCache) Put(key string, psk PreSharedKey) {
	(*cache)[key] = psk
}

func (cache PSKMapCache) Size() int {
	return len(cache)
}

// Config is the struct used to pass configuration settings to a TLS client or
// server instance.  The settings for client and server are pretty different,
// but we just throw them all in here.
type Config struct {
	// Client fields
	ServerName string

	// Server fields
	SendSessionTickets bool
	TicketLifetime     uint32
	TicketLen          int
	AllowEarlyData     bool
	RequireCookie      bool
	RequireClientAuth  bool

	// Shared fields
	Certificates     []*Certificate
	AuthCertificate  func(chain []CertificateEntry) error
	CipherSuites     []CipherSuite
	Groups           []NamedGroup
	SignatureSchemes []SignatureScheme
	NextProtos       []string
	PSKs             PreSharedKeyCache
	PSKModes         []PSKKeyExchangeMode

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
	if !reflect.ValueOf(c.PSKs).IsValid() {
		c.PSKs = &PSKMapCache{}
	}
	if len(c.PSKModes) == 0 {
		c.PSKModes = defaultPSKModes
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
			{
				Chain:      []*x509.Certificate{cert},
				PrivateKey: priv,
			},
		}
	}

	return nil
}

func (c Config) ValidForServer() bool {
	return (reflect.ValueOf(c.PSKs).IsValid() && c.PSKs.Size() > 0) ||
		(len(c.Certificates) > 0 &&
			len(c.Certificates[0].Chain) > 0 &&
			c.Certificates[0].PrivateKey != nil)
}

func (c Config) ValidForClient() bool {
	return len(c.ServerName) > 0
}

var (
	defaultSupportedCipherSuites = []CipherSuite{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
	}

	defaultSupportedGroups = []NamedGroup{
		P256,
		P384,
		FFDHE2048,
		X25519,
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

	defaultPSKModes = []PSKKeyExchangeMode{
		PSKModeKE,
		PSKModeDHEKE,
	}
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

	earlyData []byte

	state             StateConnected
	handshakeMutex    sync.Mutex
	handshakeAlert    Alert
	handshakeComplete bool

	readBuffer []byte
	in, out    *RecordLayer
	hIn, hOut  *HandshakeLayer
}

func NewConn(conn net.Conn, config *Config, isClient bool) *Conn {
	c := &Conn{conn: conn, config: config, isClient: isClient}
	c.in = NewRecordLayer(c.conn)
	c.out = NewRecordLayer(c.conn)
	c.hIn = NewHandshakeLayer(c.in)
	c.hOut = NewHandshakeLayer(c.out)
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
		case RecordTypeHandshake:
			// We do not support fragmentation of post-handshake handshake messages
			// TODO: Factor this more elegantly; coalesce with handshakeLayer.ReadMessage()
			start := 0
			for start < len(pt.fragment) {
				if len(pt.fragment[start:]) < handshakeHeaderLen {
					return fmt.Errorf("Post-handshake handshake message too short for header")
				}

				hm := &HandshakeMessage{}
				hm.msgType = HandshakeType(pt.fragment[start])
				hmLen := (int(pt.fragment[start+1]) << 16) + (int(pt.fragment[start+2]) << 8) + int(pt.fragment[start+3])

				if len(pt.fragment[start+handshakeHeaderLen:]) < hmLen {
					return fmt.Errorf("Post-handshake handshake message too short for body")
				}
				hm.body = pt.fragment[start+handshakeHeaderLen : start+handshakeHeaderLen+hmLen]

				switch hm.msgType {
				/*
						TODO: Re-enable NST / KU
					case HandshakeTypeNewSessionTicket:
						psk, err := c.handshake.HandleNewSessionTicket(hm)
						if err != nil {
							return err
						}

						logf(logTypeHandshake, "Storing new session ticket with identity [%x]", psk.Identity)
						c.config.PSKs.Put(c.config.ServerName, psk)

					case HandshakeTypeKeyUpdate:
						outboundUpdate, err := c.handshake.HandleKeyUpdate(hm)
						if err != nil {
							return err
						}

						// Rekey inbound
						cipher, keys := c.handshake.inboundKeys()
						err = c.in.Rekey(cipher, keys.key, keys.iv)
						if err != nil {
							return err
						}

						if outboundUpdate != nil {
							// Send KeyUpdate
							err = c.out.WriteRecord(&TLSPlaintext{
								contentType: RecordTypeHandshake,
								fragment:    outboundUpdate.Marshal(),
							})
							if err != nil {
								return err
							}

							// Rekey outbound
							cipher, keys := c.handshake.outboundKeys()
							err = c.out.Rekey(cipher, keys.key, keys.iv)
							if err != nil {
								return err
							}
						}
				*/
				default:
					c.sendAlert(AlertUnexpectedMessage)
					return fmt.Errorf("Unsupported post-handshake handshake message [%v]", hm.msgType)
				}

				start += handshakeHeaderLen + hmLen
			}
		case RecordTypeAlert:
			logf(logTypeIO, "extended buffer (for alert): [%d] %x", len(c.readBuffer), c.readBuffer)
			if len(pt.fragment) != 2 {
				c.sendAlert(AlertUnexpectedMessage)
				return io.EOF
			}
			if Alert(pt.fragment[1]) == AlertCloseNotify {
				return io.EOF
			}

			switch pt.fragment[0] {
			case AlertLevelWarning:
				// drop on the floor
			case AlertLevelError:
				return Alert(pt.fragment[1])
			default:
				c.sendAlert(AlertUnexpectedMessage)
				return io.EOF
			}

		case RecordTypeApplicationData:
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
		if len(c.readBuffer) == n && RecordType(c.in.nextData[0]) != RecordTypeAlert {
			return nil
		}
	}
	return nil
}

// Read application data until the buffer is full.  Handshake and alert records
// are consumed by the Conn object directly.
func (c *Conn) Read(buffer []byte) (int, error) {
	if alert := c.Handshake(); alert != AlertNoAlert {
		return 0, alert
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
		err := c.out.WriteRecord(&TLSPlaintext{
			contentType: RecordTypeApplicationData,
			fragment:    buffer[start : start+maxFragmentLen],
		})

		if err != nil {
			return sent, err
		}
		sent += maxFragmentLen
	}

	// Send a final partial fragment if necessary
	if start < len(buffer) {
		err := c.out.WriteRecord(&TLSPlaintext{
			contentType: RecordTypeApplicationData,
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
func (c *Conn) sendAlert(err Alert) error {
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	tmp := make([]byte, 2)
	switch err {
	case AlertNoRenegotiation, AlertCloseNotify:
		tmp[0] = AlertLevelWarning
	default:
		tmp[0] = AlertLevelError
	}
	tmp[1] = byte(err)
	c.out.WriteRecord(&TLSPlaintext{
		contentType: RecordTypeAlert,
		fragment:    tmp,
	})

	// close_notify and end_of_early_data are not actually errors
	if err != AlertCloseNotify && err != AlertEndOfEarlyData {
		return &net.OpError{Op: "local error", Err: err}
	}
	return nil
}

// Close closes the connection.
func (c *Conn) Close() error {
	// XXX crypto/tls has an interlock with Write here.  Do we need that?

	c.sendAlert(AlertCloseNotify)
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

func (c *Conn) followInstruction(instrGeneric HandshakeInstruction) Alert {
	switch instr := instrGeneric.(type) {
	case SendHandshakeMessage:
		err := c.hOut.WriteMessage(instr.Message)
		if err != nil {
			logf(logTypeHandshake, "Error writing handshake message: %v", err)
			return AlertInternalError
		}

	case RekeyIn:
		logf(logTypeHandshake, "Rekeying in to: %+v", instr.KeySet)
		err := c.in.Rekey(instr.KeySet.cipher, instr.KeySet.key, instr.KeySet.iv)
		if err != nil {
			logf(logTypeHandshake, "Unable to rekey inbound: %v", err)
			return AlertInternalError
		}

	case RekeyOut:
		logf(logTypeHandshake, "Rekeying out to: %+v", instr.KeySet)
		err := c.out.Rekey(instr.KeySet.cipher, instr.KeySet.key, instr.KeySet.iv)
		if err != nil {
			logf(logTypeHandshake, "Unable to rekey outbound: %v", err)
			return AlertInternalError
		}

	case SendEarlyData:
		// TODO

	case ReadEarlyData:
		// TODO: Needs something like "NextRecordType"

	default:
		logf(logTypeHandshake, "Unknown instruction type")
		return AlertInternalError
	}

	return AlertNoAlert
}

// Handshake causes a TLS handshake on the connection.  The `isClient` member
// determines whether a client or server handshake is performed.  If a
// handshake has already been performed, then its result will be returned.
func (c *Conn) Handshake() Alert {
	// TODO Lock handshakeMutex
	// TODO Remove CloseNotify hack
	if c.handshakeAlert != AlertNoAlert && c.handshakeAlert != AlertCloseNotify {
		logf(logTypeHandshake, "Pre-existing handshake error: %v", c.handshakeAlert)
		return c.handshakeAlert
	}
	if c.handshakeComplete {
		return AlertNoAlert
	}

	if err := c.config.Init(c.isClient); err != nil {
		logf(logTypeHandshake, "Error initializing config: %v", err)
		return AlertInternalError
	}

	/*
		if c.isClient {
			c.handshakeAlert = c.clientHandshake()
		} else {
			c.handshakeAlert = c.serverHandshake()
		}
		c.handshakeComplete = (c.handshakeAlert == AlertNoAlert)

		if c.handshakeAlert != AlertNoAlert {
			logf(logTypeHandshake, "Handshake failed: %v", c.handshakeAlert)
			c.sendAlert(AlertHandshakeFailure)
			c.conn.Close()
		}
	*/

	// Set things up
	caps := Capabilities{
		CipherSuites:      c.config.CipherSuites,
		Groups:            c.config.Groups,
		SignatureSchemes:  c.config.SignatureSchemes,
		PSKs:              c.config.PSKs,
		AllowEarlyData:    c.config.AllowEarlyData,
		RequireCookie:     c.config.RequireCookie,
		RequireClientAuth: c.config.RequireClientAuth,
		NextProtos:        c.config.NextProtos,
		Certificates:      c.config.Certificates,
	}
	opts := ConnectionOptions{
		ServerName: c.config.ServerName,
		NextProtos: c.config.NextProtos,
		EarlyData:  c.earlyData,
	}
	connState := connectionState{
		Caps: caps,
		Opts: opts,
	}

	var state HandshakeState
	var instructions []HandshakeInstruction
	var alert Alert
	connected := false

	if c.isClient {
		state, instructions, alert = ClientStateStart{state: &connState}.Next(nil)
		if alert != AlertNoAlert {
			logf(logTypeHandshake, "Error initializing client state: %v", alert)
			return alert
		}

		for _, instr := range instructions {
			alert = c.followInstruction(instr)
			if alert != AlertNoAlert {
				logf(logTypeHandshake, "Error following instructions: %v", alert)
				return alert
			}
		}

		_, connected = state.(StateConnected)
	} else {
		state = ServerStateStart{state: &connState}
	}

	for !connected {
		// Read a handshake message
		hm, err := c.hIn.ReadMessage()
		if err != nil {
			logf(logTypeHandshake, "Error reading message: %v", err)
			return AlertInternalError
		}
		logf(logTypeHandshake, "Read message with type: %v", hm.msgType)

		// Advance the state machine
		state, instructions, alert = state.Next(hm)

		if alert != AlertNoAlert {
			logf(logTypeHandshake, "Error in state transition: %v", alert)
			return alert
		}

		for _, instr := range instructions {
			alert = c.followInstruction(instr)
			if alert != AlertNoAlert {
				logf(logTypeHandshake, "Error following instructions: %v", alert)
				return alert
			}
		}

		_, connected = state.(StateConnected)
	}

	c.state = state.(StateConnected)
	return AlertNoAlert
}

func (c *Conn) clientHandshake() Alert {
	/*
		var err error
		logf(logTypeHandshake, "Starting clientHandshake")

		hIn := NewHandshakeLayer(c.in)
		hOut := NewHandshakeLayer(c.out)

		// Generate ClientHello
		caps := Capabilities{
			CipherSuites:     c.config.CipherSuites,
			Groups:           c.config.Groups,
			SignatureSchemes: c.config.SignatureSchemes,
			PSKs:             c.config.PSKs,
			PSKModes:         c.config.PSKModes,
			Certificates:     c.config.Certificates,
		}
		opts := ConnectionOptions{
			ServerName: c.config.ServerName,
			NextProtos: c.config.NextProtos,
			EarlyData:  c.earlyData,
		}

		connState := connectionState{
			Opts: opts,
			Caps: caps,
		}
		state := HandshakeState(ClientStateStart{state: &connState})
		state, toSend, alert := state.Next(nil)

		if alert != AlertNoAlert {
			return alert
		}

		// Write ClientHello
		for _, body := range toSend {
			hm, err := HandshakeMessageFromBody(body)
			if err != nil {
				logf(logTypeHandshake, "Error encoding handshake message: %v", err)
				return AlertInternalError
			}

			err = hOut.WriteMessage(hm)
			if err != nil {
				logf(logTypeHandshake, "Error writing handshake message: %v", err)
				return AlertInternalError
			}
		}

		// Send early data
		if opts.EarlyData != nil {
			// Rekey output to early data keys
			logf(logTypeHandshake, "[client] rekey out to early")
			err := c.out.Rekey(
				connState.Context.params.cipher,
				connState.Context.clientEarlyTrafficKeys.key,
				connState.Context.clientEarlyTrafficKeys.iv)
			if err != nil {
				logf(logTypeHandshake, "[client] Error in rekey: %v", err)
				return AlertInternalError
			}

			// Send early application data
			logf(logTypeHandshake, "[client] Sending data...")
			_, err = c.Write(opts.EarlyData)
			if err != nil {
				logf(logTypeHandshake, "[client] Error writing early data: %v", err)
				return AlertInternalError
			}
		}

		// Read and process the ServerHello
		hm, err := hIn.ReadMessage()
		if err != nil {
			logf(logTypeHandshake, "[ServerHello] Error reading message: %v", err)
			return AlertInternalError
		}
		logf(logTypeHandshake, "Read message with type: %v", hm.msgType)

		body, err := hm.ToBody()
		if err != nil {
			logf(logTypeHandshake, "Error decoding handshake message: %v", err)
			return AlertDecodeError
		}

		// Advance the state machine
		state, toSend, alert = state.Next(body)
		if alert != AlertNoAlert {
			return alert
		}

		// Send any messages that need to be sent
		for _, body := range toSend {
			hm, err := HandshakeMessageFromBody(body)
			if err != nil {
				logf(logTypeHandshake, "Error encoding handshake message: %v", err)
				return AlertInternalError
			}

			err = hOut.WriteMessage(hm)
			if err != nil {
				logf(logTypeHandshake, "Error writing handshake message: %v", err)
				return AlertInternalError
			}
		}

		// Retry on HelloRetryRequest
		_, ok := state.(ClientStateWaitSH)
		if ok {
			// Read and process the ServerHello
			hm, err := hIn.ReadMessage()
			if err != nil {
				logf(logTypeHandshake, "[ServerHello] Error reading message: %v", err)
				return AlertInternalError
			}
			logf(logTypeHandshake, "Read message with type: %v", hm.msgType)

			body, err := hm.ToBody()
			if err != nil {
				logf(logTypeHandshake, "Error decoding handshake message: %v", err)
				return AlertDecodeError
			}

			// Advance the state machine
			state, toSend, alert = state.Next(body)
			if alert != AlertNoAlert {
				return alert
			}

			// Send any messages that need to be sent
			for _, body := range toSend {
				hm, err := HandshakeMessageFromBody(body)
				if err != nil {
					logf(logTypeHandshake, "Error encoding handshake message: %v", err)
					return AlertInternalError
				}

				err = hOut.WriteMessage(hm)
				if err != nil {
					logf(logTypeHandshake, "Error writing handshake message: %v", err)
					return AlertInternalError
				}
			}
		}

		// Rekey to handshake keys
		logf(logTypeHandshake, "[client] rekey in to handshake")
		err = c.in.Rekey(
			connState.Context.params.cipher,
			connState.Context.serverHandshakeKeys.key,
			connState.Context.serverHandshakeKeys.iv)
		if err != nil {
			logf(logTypeHandshake, "[client] Unable to rekey inbound: %v", err)
			return AlertInternalError
		}

		_, ok = state.(StateConnected)
		for !ok {
			// Read a handshake message
			hm, err := hIn.ReadMessage()
			if err != nil {
				logf(logTypeHandshake, "[Further] Error reading message: %v", err)
				return AlertInternalError
			}
			logf(logTypeHandshake, "Read message with type: %v", hm.msgType)

			body, err := hm.ToBody()
			if err != nil {
				logf(logTypeHandshake, "Error decoding handshake message: %v", err)
				return AlertDecodeError
			}

			// Advance the state machine
			state, toSend, alert = state.Next(body)
			if alert != AlertNoAlert {
				return alert
			}

			// Send any messages that need to be sent
			for i, body := range toSend {
				hm, err := HandshakeMessageFromBody(body)
				if err != nil {
					logf(logTypeHandshake, "Error encoding handshake message: %v", err)
					return AlertInternalError
				}

				err = hOut.WriteMessage(hm)
				if err != nil {
					logf(logTypeHandshake, "Error writing handshake message: %v", err)
					return AlertInternalError
				}

				if i > 0 {
					continue
				}

				// Rekey to handshake keys after EOED (first message of first iteration)
				// XXX: Total hack
				logf(logTypeHandshake, "[client] rekey out to handshake")
				err = c.out.Rekey(
					connState.Context.params.cipher,
					connState.Context.clientHandshakeKeys.key,
					connState.Context.clientHandshakeKeys.iv)
				if err != nil {
					logf(logTypeHandshake, "[client] Unable to rekey outbound: %v", err)
					return AlertInternalError
				}
			}

			_, ok = state.(StateConnected)
		}

		// Rekey to application keys
		logf(logTypeHandshake, "[client] rekey in to application")
		err = c.in.Rekey(
			connState.Context.params.cipher,
			connState.Context.serverTrafficKeys.key,
			connState.Context.serverTrafficKeys.iv)
		if err != nil {
			logf(logTypeHandshake, "[client] Unable to rekey inbound: %v", err)
			return AlertInternalError
		}
		logf(logTypeHandshake, "[client] rekey out to application")
		err = c.out.Rekey(
			connState.Context.params.cipher,
			connState.Context.clientTrafficKeys.key,
			connState.Context.clientTrafficKeys.iv)
		if err != nil {
			logf(logTypeHandshake, "[client] Unable to rekey outbound: %v", err)
			return AlertInternalError
		}

		c.state = state.(StateConnected)
	*/
	return AlertNoAlert
}

func (c *Conn) serverHandshake() Alert {
	/*
		var err error
		logf(logTypeHandshake, "Starting serverHandshake")

		h := &ServerHandshake{}
		hIn := NewHandshakeLayer(c.in)
		hOut := NewHandshakeLayer(c.out)

		// Start up the state machine
		caps := Capabilities{
			CipherSuites:      c.config.CipherSuites,
			Groups:            c.config.Groups,
			SignatureSchemes:  c.config.SignatureSchemes,
			PSKs:              c.config.PSKs,
			AllowEarlyData:    c.config.AllowEarlyData,
			RequireCookie:     c.config.RequireCookie,
			RequireClientAuth: c.config.RequireClientAuth,
			NextProtos:        c.config.NextProtos,
			Certificates:      c.config.Certificates,
		}
		connState := connectionState{Caps: caps}
		state := HandshakeState(ServerStateStart{state: &connState})

		// Read and process the ClientHello
		chm, err := hIn.ReadMessage()
		if err != nil {
			logf(logTypeHandshake, "Unable to read ClientHello: %v", err)
			return AlertInternalError
		}
		logf(logTypeHandshake, "Read message of type: %v", chm.msgType)

		ch, err := chm.ToBody()
		if err != nil {
			logf(logTypeHandshake, "Unable to decode ClientHello: %v", err)
			return AlertDecodeError
		}

		state, toSend, alert := state.Next(ch)
		if alert != AlertNoAlert {
			return alert
		}

		_, ok := state.(ServerStateStart)
		if ok {
			// If HRR, retry
			logf(logTypeHandshake, "Sending HelloRetryRequest")

			for _, body := range toSend {
				hm, err := HandshakeMessageFromBody(body)
				if err != nil {
					logf(logTypeHandshake, "Error encoding handshake message: %v", err)
					return AlertInternalError
				}

				err = hOut.WriteMessage(hm)
				if err != nil {
					logf(logTypeHandshake, "Error writing handshake message: %v", err)
					return AlertInternalError
				}
			}

			chm, err := hIn.ReadMessage()
			if err != nil {
				logf(logTypeHandshake, "Unable to read ClientHello: %v", err)
				return AlertInternalError
			}
			logf(logTypeHandshake, "Read message of type: %v", chm.msgType)

			ch, err := chm.ToBody()
			if err != nil {
				logf(logTypeHandshake, "Unable to decode ClientHello: %v", err)
				return AlertDecodeError
			}

			state, toSend, alert = state.Next(ch)
			if alert != AlertNoAlert {
				return alert
			}
		}

		// Send the ServerHello unencrypted
		// XXX: Assumes toSend has >= 1 element
		sh := toSend[0]
		toSend = toSend[1:]
		shm, err := HandshakeMessageFromBody(sh)
		if err != nil {
			logf(logTypeHandshake, "Error encoding handshake message: %v", err)
			return AlertInternalError
		}

		err = hOut.WriteMessage(shm)
		if err != nil {
			logf(logTypeHandshake, "Error writing handshake message: %v", err)
			return AlertInternalError
		}

		// Rekey out to handshake keys
		logf(logTypeHandshake, "[server] rekey out to handshake")
		err = c.out.Rekey(
			connState.Context.params.cipher,
			connState.Context.serverHandshakeKeys.key,
			connState.Context.serverHandshakeKeys.iv)
		if err != nil {
			logf(logTypeHandshake, "[server] Unable to rekey outbound: %v", err)
			return AlertInternalError
		}

		// Send the remainder of the server's first flight
		for _, body := range toSend {
			hm, err := HandshakeMessageFromBody(body)
			if err != nil {
				logf(logTypeHandshake, "Error encoding handshake message: %v", err)
				return AlertInternalError
			}

			err = hOut.WriteMessage(hm)
			if err != nil {
				logf(logTypeHandshake, "Error writing handshake message: %v", err)
				return AlertInternalError
			}
		}

		// Read early data if necessary'
		var body HandshakeMessageBody
		if h.Params.ClientSendingEarlyData {
			logf(logTypeHandshake, "[server] Processing early data")

			// Rekey in to early data keys; read early data
			logf(logTypeHandshake, "[server] rekey in to early")
			err := c.in.Rekey(
				connState.Context.params.cipher,
				connState.Context.clientEarlyTrafficKeys.key,
				connState.Context.clientEarlyTrafficKeys.iv)
			if err != nil {
				logf(logTypeHandshake, "[client] Error in rekey: %v", err)
				return AlertInternalError
			}

			// Read to end of early data
			logf(logTypeHandshake, "[server] Reading early data...")
			done := false
			for !done {
				logf(logTypeHandshake, "  Record!")
				pt, err := c.in.ReadRecord()
				if err != nil {
					logf(logTypeHandshake, "[server] Error reading record: %v", err)
					return AlertInternalError
				}

				switch pt.contentType {
				case RecordTypeHandshake:
					logf(logTypeHandshake, "Handshake record")

					// XXX: Manually decoding handshake record
					// XXX: Assumes record is non-empty
					// XXX: Assumes entire fragment is one record
					hm := &HandshakeMessage{}
					hm.msgType = HandshakeType(pt.fragment[0])
					hm.body = pt.fragment[1:]

					body, err = hm.ToBody()
					if err != nil {
						logf(logTypeHandshake, "Error decoding handshake message: %v", err)
						return AlertDecodeError
					}
					logf(logTypeHandshake, "Read message of type: %v", hm.msgType)

				case RecordTypeApplicationData:
					// XXX: Should expose early data differently
					logf(logTypeHandshake, "App data")
					c.readBuffer = append(c.readBuffer, pt.fragment...)
				default:
					return AlertUnexpectedMessage
				}
			}

			logf(logTypeHandshake, "[server] Done reading early data [%d] %x", len(c.readBuffer), c.readBuffer)
		}

		// Rekey in to handshake keys and complete handshake
		logf(logTypeHandshake, "[server] rekey in to handshake")
		err = c.in.Rekey(
			connState.Context.params.cipher,
			connState.Context.clientHandshakeKeys.key,
			connState.Context.clientHandshakeKeys.iv)
		if err != nil {
			logf(logTypeHandshake, "[server] Unable to rekey inbound: %v", err)
			return AlertInternalError
		}

		_, ok = state.(StateConnected)
		for !ok {
			if body == nil {
				hm, err := hIn.ReadMessage()
				if err != nil {
					logf(logTypeHandshake, "Unable to read message: %v", err)
					return AlertInternalError
				}
				logf(logTypeHandshake, "Read message of type: %v", hm.msgType)

				body, err = hm.ToBody()
				if err != nil {
					logf(logTypeHandshake, "Unable to decode message: %v", err)
					return AlertDecodeError
				}
			}

			state, toSend, alert = state.Next(body)

			if alert != AlertNoAlert {
				return alert
			}

			for _, body := range toSend {
				hm, err := HandshakeMessageFromBody(body)
				if err != nil {
					logf(logTypeHandshake, "Error encoding handshake message: %v", err)
					return AlertInternalError
				}

				err = hOut.WriteMessage(hm)
				if err != nil {
					logf(logTypeHandshake, "Error writing handshake message: %v", err)
					return AlertInternalError
				}
			}

			body = nil
			_, ok = state.(StateConnected)
		}

		// Rekey to application keys
		logf(logTypeHandshake, "[server] rekey out to application")
		err = c.out.Rekey(
			connState.Context.params.cipher,
			connState.Context.serverTrafficKeys.key,
			connState.Context.serverTrafficKeys.iv)
		if err != nil {
			logf(logTypeHandshake, "[server] Unable to rekey inbound: %v", err)
			return AlertInternalError
		}
		logf(logTypeHandshake, "[server] rekey in to application")
		err = c.in.Rekey(
			connState.Context.params.cipher,
			connState.Context.clientTrafficKeys.key,
			connState.Context.clientTrafficKeys.iv)
		if err != nil {
			logf(logTypeHandshake, "[server] Unable to rekey outbound: %v", err)
			return AlertInternalError
		}

		c.state = state.(StateConnected)
	*/
	return AlertNoAlert
}

func (c *Conn) SendKeyUpdate(requestUpdate bool) error {
	return nil
	// TODO: Re-enable
	/*
		if !c.handshakeComplete {
			return fmt.Errorf("Cannot update keys until after handshake")
		}

		request := KeyUpdateNotRequested
		if requestUpdate {
			request = KeyUpdateRequested
		}

		// Create the key update and update the keys internally
		kum, err := c.handshake.CreateKeyUpdate(request)
		if err != nil {
			return err
		}

		// Send key update
		err = c.out.WriteRecord(&TLSPlaintext{
			contentType: RecordTypeHandshake,
			fragment:    kum.Marshal(),
		})
		if err != nil {
			return err
		}

		// Rekey outbound
		cipher, keys := c.handshake.outboundKeys()
		err = c.out.Rekey(cipher, keys.key, keys.iv)
		return err
	*/
}
