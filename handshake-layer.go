package mint

import (
	"fmt"
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

		if pt.contentType != recordTypeHandshake {
			return fmt.Errorf("tls.handshakelayer: Unexpected record type")
		}

		h.buffer = append(h.buffer, pt.fragment...)
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

func (h *handshakeLayer) ReadMessageBody(body handshakeMessageBody) error {
	hm, err := h.ReadMessage()
	if err != nil {
		return err
	}

	if hm.msgType != body.Type() {
		return fmt.Errorf("tls.handshakelayer: Unexpected message type %v", hm.msgType)
	}

	read, err := body.Unmarshal(hm.body)
	if err != nil {
		return err
	}

	if read < len(hm.body) {
		return fmt.Errorf("tls.handshakelayer: Extra data in message (%d)", len(hm.body)-read)
	}
	return nil
}

func (h *handshakeLayer) WriteMessage(hm *handshakeMessage) error {
	return h.WriteMessages([]*handshakeMessage{hm})
}

func (h *handshakeLayer) WriteMessages(hms []*handshakeMessage) error {
	// Write out headers and bodies
	buffer := []byte{}
	for _, msg := range hms {
		msgLen := len(msg.body)
		if msgLen > maxHandshakeMessageLen {
			return fmt.Errorf("tls.handshakelayer: Message too large to send")
		}

		header := []byte{byte(msg.msgType), byte(msgLen >> 16), byte(msgLen >> 8), byte(msgLen)}
		buffer = append(buffer, header...)
		buffer = append(buffer, msg.body...)
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

func (h *handshakeLayer) WriteMessageBody(body handshakeMessageBody) error {
	return h.WriteMessageBodies([]handshakeMessageBody{body})
}

func (h *handshakeLayer) WriteMessageBodies(bodies []handshakeMessageBody) error {
	hms := make([]*handshakeMessage, len(bodies))
	for i, body := range bodies {
		hm, err := handshakeMessageFromBody(body)
		if err != nil {
			return err
		}
		hms[i] = hm
	}

	return h.WriteMessages(hms)
}
