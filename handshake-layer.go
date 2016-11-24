package mint

import (
	"fmt"
	"io"
	"net"
)

const (
	handshakeHeaderLen     = 4       // handshake message header length
	maxHandshakeMessageLen = 1 << 24 // max handshake message length
)

// struct {
//     HandshakeType msg_type;    /* handshake type */
//     uint24 length;             /* bytes in message */
//     select (HandshakeType) {
//       ...
//     } body;
// } Handshake;
//
// We do the select{...} part in a different layer, so we treat the
// actual message body as opaque:
//
// struct {
//     HandshakeType msg_type;
//     opaque msg<0..2^24-1>
// } Handshake;
//
// TODO: File a spec bug
type HandshakeMessage struct {
	// Omitted: length
	msgType HandshakeType
	body    []byte
}

// Note: This could be done with the `syntax` module, using the simplified
// syntax as discussed above.  However, since this is so simple, there's not
// much benefit to doing so.
func (hm HandshakeMessage) Marshal() []byte {
	msgLen := len(hm.body)
	data := make([]byte, 4+len(hm.body))
	data[0] = byte(hm.msgType)
	data[1] = byte(msgLen >> 16)
	data[2] = byte(msgLen >> 8)
	data[3] = byte(msgLen)
	copy(data[4:], hm.body)
	return data
}

func (hm HandshakeMessage) ToBody() (HandshakeMessageBody, error) {
	logf(logTypeHandshake, "HandshakeMessage.toBody [%d] [%x]", hm.msgType, hm.body)

	var body HandshakeMessageBody
	switch hm.msgType {
	case HandshakeTypeClientHello:
		body = new(ClientHelloBody)
	case HandshakeTypeServerHello:
		body = new(ServerHelloBody)
	case HandshakeTypeEncryptedExtensions:
		body = new(EncryptedExtensionsBody)
	case HandshakeTypeCertificate:
		body = new(CertificateBody)
	case HandshakeTypeCertificateVerify:
		body = new(CertificateVerifyBody)
	case HandshakeTypeFinished:
		body = new(FinishedBody)
	case HandshakeTypeNewSessionTicket:
		body = new(NewSessionTicketBody)
	default:
		return body, fmt.Errorf("tls.handshakemessage: Unsupported body type")
	}

	_, err := body.Unmarshal(hm.body)
	return body, err
}

func HandshakeMessageFromBody(body HandshakeMessageBody) (*HandshakeMessage, error) {
	data, err := body.Marshal()
	if err != nil {
		return nil, err
	}

	return &HandshakeMessage{
		msgType: body.Type(),
		body:    data,
	}, nil
}

type HandshakeLayer struct {
	conn   *RecordLayer // Used for reading/writing records
	buffer []byte       // Read buffer
}

func NewHandshakeLayer(r *RecordLayer) *HandshakeLayer {
	h := HandshakeLayer{}
	h.conn = r
	h.buffer = []byte{}
	return &h
}

func (h *HandshakeLayer) extendBuffer(n int) error {
	for len(h.buffer) < n {
		pt, err := h.conn.ReadRecord()
		if err != nil {
			return err
		}

		if pt.contentType != RecordTypeHandshake &&
			pt.contentType != RecordTypeAlert {
			return fmt.Errorf("tls.handshakelayer: Unexpected record type %04x", pt.contentType)
		}

		if pt.contentType == RecordTypeAlert {
			logf(logTypeIO, "extended buffer (for alert): [%d] %x", len(h.buffer), h.buffer)
			if len(pt.fragment) < 2 {
				h.sendAlert(AlertUnexpectedMessage)
				return io.EOF
			}
			if Alert(pt.fragment[1]) == AlertEndOfEarlyData {
				// TODO: add a state change for 0-RTT here
				return nil
			}
			return Alert(pt.fragment[1])
		}

		h.buffer = append(h.buffer, pt.fragment...)
	}
	return nil
}

// sendAlert sends a TLS alert message.
func (h *HandshakeLayer) sendAlert(err Alert) error {
	tmp := make([]byte, 2)
	tmp[0] = AlertLevelError
	tmp[1] = byte(err)
	h.conn.WriteRecord(&TLSPlaintext{
		contentType: RecordTypeAlert,
		fragment:    tmp},
	)

	// closeNotify is a special case in that it isn't an error:
	if err != AlertCloseNotify {
		return &net.OpError{Op: "local error", Err: err}
	}
	return nil
}

func (h *HandshakeLayer) ReadMessage() (*HandshakeMessage, error) {
	// Read the header
	err := h.extendBuffer(handshakeHeaderLen)
	if err != nil {
		return nil, err
	}

	hm := &HandshakeMessage{}
	hm.msgType = HandshakeType(h.buffer[0])
	hmLen := (int(h.buffer[1]) << 16) + (int(h.buffer[2]) << 8) + int(h.buffer[3])

	// Read the body
	err = h.extendBuffer(handshakeHeaderLen + hmLen)
	if err != nil {
		return nil, err
	}

	hm.body = h.buffer[handshakeHeaderLen : handshakeHeaderLen+hmLen]
	h.buffer = h.buffer[handshakeHeaderLen+hmLen:]
	return hm, nil
}

func (h *HandshakeLayer) WriteMessage(hm *HandshakeMessage) error {
	return h.WriteMessages([]*HandshakeMessage{hm})
}

func (h *HandshakeLayer) WriteMessages(hms []*HandshakeMessage) error {
	for _, hm := range hms {
		logf(logTypeHandshake, "WriteMessage [%d] %x", hm.msgType, hm.body)
	}

	// Write out headers and bodies
	buffer := []byte{}
	for _, msg := range hms {
		msgLen := len(msg.body)
		if msgLen > maxHandshakeMessageLen {
			return fmt.Errorf("tls.handshakelayer: Message too large to send")
		}

		buffer = append(buffer, msg.Marshal()...)
	}

	// Send full-size fragments
	var start int
	for start = 0; len(buffer)-start >= maxFragmentLen; start += maxFragmentLen {
		err := h.conn.WriteRecord(&TLSPlaintext{
			contentType: RecordTypeHandshake,
			fragment:    buffer[start : start+maxFragmentLen],
		})

		if err != nil {
			return err
		}
	}

	// Send a final partial fragment if necessary
	if start < len(buffer) {
		err := h.conn.WriteRecord(&TLSPlaintext{
			contentType: RecordTypeHandshake,
			fragment:    buffer[start:],
		})

		if err != nil {
			return err
		}
	}
	return nil
}
