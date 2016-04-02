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
type handshakeMessage struct {
	// Omitted: length
	msgType handshakeType
	body    []byte
}

func (hm handshakeMessage) Marshal() []byte {
	msgLen := len(hm.body)
	data := make([]byte, 4+len(hm.body))
	data[0] = byte(hm.msgType)
	data[1] = byte(msgLen >> 16)
	data[2] = byte(msgLen >> 8)
	data[3] = byte(msgLen)
	copy(data[4:], hm.body)
	return data
}

func (hm handshakeMessage) toBody() (handshakeMessageBody, error) {
	logf(logTypeHandshake, "handshakeMessage.toBody [%d] [%x]", hm.msgType, hm.body)

	var body handshakeMessageBody
	switch hm.msgType {
	case handshakeTypeClientHello:
		body = new(clientHelloBody)
	case handshakeTypeServerHello:
		body = new(serverHelloBody)
	case handshakeTypeEncryptedExtensions:
		body = new(encryptedExtensionsBody)
	case handshakeTypeCertificate:
		body = new(certificateBody)
	case handshakeTypeCertificateVerify:
		body = new(certificateVerifyBody)
	case handshakeTypeFinished:
		body = new(finishedBody)
	case handshakeTypeNewSessionTicket:
		body = new(newSessionTicketBody)
	default:
		return body, fmt.Errorf("tls.handshakemessage: Unsupported body type")
	}

	_, err := body.Unmarshal(hm.body)
	if err != nil {
		return body, err
	}

	return body, nil
}

func handshakeMessageFromBody(body handshakeMessageBody) (*handshakeMessage, error) {
	data, err := body.Marshal()
	if err != nil {
		return nil, err
	}

	return &handshakeMessage{
		msgType: body.Type(),
		body:    data,
	}, nil
}

type handshakeLayer struct {
	conn   *recordLayer // Used for reading/writing records
	buffer []byte       // Read buffer
}

func newHandshakeLayer(r *recordLayer) *handshakeLayer {
	h := handshakeLayer{}
	h.conn = r
	h.buffer = []byte{}
	return &h
}

func (h *handshakeLayer) extendBuffer(n int) error {
	for len(h.buffer) < n {
		pt, err := h.conn.ReadRecord()
		if err != nil {
			return err
		}

		if pt.contentType != recordTypeHandshake &&
			pt.contentType != recordTypeAlert {
			return fmt.Errorf("tls.handshakelayer: Unexpected record type %04x", pt.contentType)
		}

		if pt.contentType == recordTypeAlert {
			logf(logTypeIO, "extended buffer (for alert): [%d] %x", len(h.buffer), h.buffer)
			if len(pt.fragment) < 2 {
				h.sendAlert(alertUnexpectedMessage)
				return io.EOF
			}
			if alert(pt.fragment[1]) == alertEndOfEarlyData {
				// TODO: add a state change for 0-RTT here
				return nil
			} else {
				return alert(pt.fragment[1])
			}
		}

		h.buffer = append(h.buffer, pt.fragment...)
	}
	return nil
}

// sendAlert sends a TLS alert message.
func (h *handshakeLayer) sendAlert(err alert) error {
	tmp := make([]byte, 2)
	tmp[0] = alertLevelError
	tmp[1] = byte(err)
	h.conn.WriteRecord(&tlsPlaintext{
		contentType: recordTypeAlert,
		fragment:    tmp},
	)

	// closeNotify is a special case in that it isn't an error:
	if err != alertCloseNotify {
		return &net.OpError{Op: "local error", Err: err}
	}
	return nil
}

func (h *handshakeLayer) ReadMessage() (*handshakeMessage, error) {
	// Read the header
	err := h.extendBuffer(handshakeHeaderLen)
	if err != nil {
		return nil, err
	}

	hm := &handshakeMessage{}
	hm.msgType = handshakeType(h.buffer[0])
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

func (h *handshakeLayer) ReadMessageBody(body handshakeMessageBody) (*handshakeMessage, error) {
	hm, err := h.ReadMessage()
	if err != nil {
		return nil, err
	}

	if hm.msgType != body.Type() {
		return nil, fmt.Errorf("tls.handshakelayer: Unexpected message type %v != %v", hm.msgType, body.Type())
	}

	read, err := body.Unmarshal(hm.body)
	if err != nil {
		return nil, err
	}

	if read < len(hm.body) {
		return nil, fmt.Errorf("tls.handshakelayer: Extra data in message (%d)", len(hm.body)-read)
	}
	return hm, nil
}

func (h *handshakeLayer) WriteMessage(hm *handshakeMessage) error {
	return h.WriteMessages([]*handshakeMessage{hm})
}

func (h *handshakeLayer) WriteMessages(hms []*handshakeMessage) error {
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
		err := h.conn.WriteRecord(&tlsPlaintext{
			contentType: recordTypeHandshake,
			fragment:    buffer[start : start+maxFragmentLen],
		})

		if err != nil {
			return err
		}
	}

	// Send a final partial fragment if necessary
	if start < len(buffer) {
		err := h.conn.WriteRecord(&tlsPlaintext{
			contentType: recordTypeHandshake,
			fragment:    buffer[start:],
		})

		if err != nil {
			return err
		}
	}
	return nil
}

func (h *handshakeLayer) WriteMessageBody(body handshakeMessageBody) (*handshakeMessage, error) {
	hms, err := h.WriteMessageBodies([]handshakeMessageBody{body})
	if err != nil {
		return nil, err
	}

	// When it succeeds, WriteMessageBodies always returns as many messages as
	// bodies were provided in the input array
	return hms[0], nil
}

func (h *handshakeLayer) WriteMessageBodies(bodies []handshakeMessageBody) ([]*handshakeMessage, error) {
	hms := make([]*handshakeMessage, len(bodies))
	for i, body := range bodies {
		hm, err := handshakeMessageFromBody(body)
		if err != nil {
			return nil, err
		}
		hms[i] = hm
	}

	return hms, h.WriteMessages(hms)
}
