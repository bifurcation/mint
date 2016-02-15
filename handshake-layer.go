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

// Write a single handshake message in a record
func (h *handshakeLayer) WriteMessage(hm *handshakeMessage) error {
	return h.WriteMessages([]*handshakeMessage{hm})
}

// Write a bundle of handhsake messages, packed into as few records as possible
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
