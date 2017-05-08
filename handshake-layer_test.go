package mint

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

type ErrorReadWriter struct{}

func (e ErrorReadWriter) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("Unknown read error")
}

func (e ErrorReadWriter) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("Unknown write error")
}

func recordHeaderHex(data []byte) string {
	dataLen := len(data)
	return hex.EncodeToString([]byte{0x16, 0x03, 0x01, byte(dataLen >> 8), byte(dataLen)})
}

var (
	messageType = HandshakeTypeClientHello

	tinyMessageIn = &HandshakeMessage{
		msgType: messageType,
		body:    []byte{0, 0, 0, 0},
	}
	tinyMessageHex = "0100000400000000"

	// short: 0x000040
	// long:  0x007fe0 = 0x4000 + 0x3fe0
	shortMessageLen = 64
	longMessageLen  = 2*maxFragmentLen - (shortMessageLen / 2)

	shortMessageHeader    = []byte{byte(messageType), 0x00, 0x00, byte(shortMessageLen)}
	shortMessageBody      = bytes.Repeat([]byte{0xab}, shortMessageLen)
	shortMessage          = append(shortMessageHeader, shortMessageBody...)
	longMessageHeader     = []byte{byte(messageType), 0x00, byte(longMessageLen >> 8), byte(longMessageLen)}
	longMessageBody       = bytes.Repeat([]byte{0xcd}, longMessageLen)
	longMessage           = append(longMessageHeader, longMessageBody...)
	shortLongMessage      = append(shortMessage, longMessage...)
	shortLongShortMessage = append(shortLongMessage, shortMessage...)

	shortHex = recordHeaderHex(shortMessage) + hex.EncodeToString(shortMessage)

	shortMessageIn = &HandshakeMessage{
		msgType: messageType,
		body:    shortMessageBody,
	}
	longMessageIn = &HandshakeMessage{
		msgType: messageType,
		body:    longMessageBody,
	}
	tooLongMessageIn = &HandshakeMessage{
		msgType: messageType,
		body:    bytes.Repeat([]byte{0xef}, maxHandshakeMessageLen+1),
	}

	longFragment1 = longMessage[:maxFragmentLen]
	longFragment2 = longMessage[maxFragmentLen:]
	longHex       = recordHeaderHex(longFragment1) + hex.EncodeToString(longFragment1) +
		recordHeaderHex(longFragment2) + hex.EncodeToString(longFragment2)

	slsFragment1      = shortLongShortMessage[:maxFragmentLen]
	slsFragment2      = shortLongShortMessage[maxFragmentLen : 2*maxFragmentLen]
	slsFragment3      = shortLongShortMessage[2*maxFragmentLen:]
	shortLongShortHex = recordHeaderHex(slsFragment1) + hex.EncodeToString(slsFragment1) +
		recordHeaderHex(slsFragment2) + hex.EncodeToString(slsFragment2) +
		recordHeaderHex(slsFragment3) + hex.EncodeToString(slsFragment3)

	insufficientDataHex = "1603010004" + "01000004" + "1603010002" + "0000"
	nonHandshakeHex     = "15030100020000"
)

func TestMessageMarshal(t *testing.T) {
	tinyMessage := unhex(tinyMessageHex)

	out := tinyMessageIn.Marshal()
	assertByteEquals(t, out, tinyMessage)
}

func TestMessageToBody(t *testing.T) {
	// Borrowing serialized bodies from handshake-messages_test.go
	chValid := unhex(chValidHex)
	shValid := unhex(shValidHex)
	finValid := unhex(finValidHex)
	encExtValid := unhex(encExtValidHex)
	certValid := unhex(certValidHex)
	certVerifyValid := unhex(certVerifyValidHex)
	ticketValid := unhex(ticketValidHex)

	// Test successful marshal of ClientHello
	hm := HandshakeMessage{HandshakeTypeClientHello, chValid}
	_, err := hm.ToBody()
	assertNotError(t, err, "Failed to convert ClientHello body")

	// Test successful marshal of ServerHello
	hm = HandshakeMessage{HandshakeTypeServerHello, shValid}
	_, err = hm.ToBody()
	assertNotError(t, err, "Failed to convert ServerHello body")

	// Test successful marshal of EncryptedExtensions
	hm = HandshakeMessage{HandshakeTypeEncryptedExtensions, encExtValid}
	_, err = hm.ToBody()
	assertNotError(t, err, "Failed to convert EncryptedExtensions body")

	// Test successful marshal of Certificate
	hm = HandshakeMessage{HandshakeTypeCertificate, certValid}
	_, err = hm.ToBody()
	assertNotError(t, err, "Failed to convert Certificate body")

	// Test successful marshal of CertificateVerify
	hm = HandshakeMessage{HandshakeTypeCertificateVerify, certVerifyValid}
	_, err = hm.ToBody()
	assertNotError(t, err, "Failed to convert CertificateVerify body")

	// Test successful marshal of Finished
	hm = HandshakeMessage{HandshakeTypeFinished, finValid}
	_, err = hm.ToBody()
	assertNotError(t, err, "Failed to convert Finished body")

	// Test successful marshal of NewSessionTicket
	hm = HandshakeMessage{HandshakeTypeNewSessionTicket, ticketValid}
	_, err = hm.ToBody()
	assertNotError(t, err, "Failed to convert NewSessionTicket body")

	// Test failure on unsupported body type
	hm = HandshakeMessage{HandshakeTypeHelloRetryRequest, []byte{}}
	_, err = hm.ToBody()
	assertError(t, err, "Converted an unsupported message")

	// Test failure on marshal failure
	hm = HandshakeMessage{HandshakeTypeClientHello, []byte{}}
	_, err = hm.ToBody()
	assertError(t, err, "Converted an empty message")

}

func TestMessageFromBody(t *testing.T) {
	chValid := unhex(chValidHex)

	// Test successful conversion
	hm, err := HandshakeMessageFromBody(&chValidIn)
	assertNotError(t, err, "Failed to convert ClientHello body to message")
	assertEquals(t, hm.msgType, chValidIn.Type())
	assertByteEquals(t, hm.body, chValid)

	// Test conversion failure on marshal failure
	chValidIn.CipherSuites = []CipherSuite{}
	hm, err = HandshakeMessageFromBody(&chValidIn)
	assertError(t, err, "Converted a ClientHello that should not have marshaled")
	chValidIn.CipherSuites = chCipherSuites
}

func TestReadHandshakeMessage(t *testing.T) {
	short := unhex(shortHex)
	long := unhex(longHex)
	shortLongShort := unhex(shortLongShortHex)
	insufficientData := unhex(insufficientDataHex)
	nonHandshake := unhex(nonHandshakeHex)

	// Test successful read of a message in a single record
	b := bytes.NewBuffer(short)
	h := NewHandshakeLayer(NewRecordLayer(b))
	hm, err := h.ReadMessage()
	assertNotError(t, err, "Failed to read a short handshake message")
	assertDeepEquals(t, hm, shortMessageIn)

	// Test successful read of a message split across records
	b = bytes.NewBuffer(long)
	h = NewHandshakeLayer(NewRecordLayer(b))
	hm, err = h.ReadMessage()
	assertNotError(t, err, "Failed to read a long handshake message")
	assertDeepEquals(t, hm, longMessageIn)

	// Test successful read of multiple messages sequentially
	b = bytes.NewBuffer(shortLongShort)
	h = NewHandshakeLayer(NewRecordLayer(b))
	hm1, err := h.ReadMessage()
	assertNotError(t, err, "Failed to read first handshake message")
	assertDeepEquals(t, hm1, shortMessageIn)
	hm2, err := h.ReadMessage()
	assertNotError(t, err, "Failed to read second handshake message")
	assertDeepEquals(t, hm2, longMessageIn)
	hm3, err := h.ReadMessage()
	assertNotError(t, err, "Failed to read third handshake message")
	assertDeepEquals(t, hm3, shortMessageIn)

	// Test read failure on inability to read header
	b = bytes.NewBuffer(short[:handshakeHeaderLen-1])
	h = NewHandshakeLayer(NewRecordLayer(b))
	hm, err = h.ReadMessage()
	assertError(t, err, "Read handshake message with an incomplete header")

	// Test read failure on inability to read body
	b = bytes.NewBuffer(insufficientData)
	h = NewHandshakeLayer(NewRecordLayer(b))
	hm, err = h.ReadMessage()
	assertError(t, err, "Read handshake message with an incomplete body")

	// Test read failure on receiving a non-handshake record
	b = bytes.NewBuffer(nonHandshake)
	h = NewHandshakeLayer(NewRecordLayer(b))
	hm, err = h.ReadMessage()
	assertError(t, err, "Read handshake message from a non-handshake record")
}

func TestWriteHandshakeMessage(t *testing.T) {
	short := unhex(shortHex)
	long := unhex(longHex)
	shortLongShort := unhex(shortLongShortHex)

	// Test successful write of single message
	b := bytes.NewBuffer(nil)
	h := NewHandshakeLayer(NewRecordLayer(b))
	err := h.WriteMessage(shortMessageIn)
	assertNotError(t, err, "Failed to write valid short message")
	assertByteEquals(t, b.Bytes(), short)

	// Test successful write of single long message
	b = bytes.NewBuffer(nil)
	h = NewHandshakeLayer(NewRecordLayer(b))
	err = h.WriteMessage(longMessageIn)
	assertNotError(t, err, "Failed to write valid long message")
	assertByteEquals(t, b.Bytes(), long)

	// Test successful write of multiple messages sequentially
	b = bytes.NewBuffer(nil)
	h = NewHandshakeLayer(NewRecordLayer(b))
	err = h.WriteMessages([]*HandshakeMessage{shortMessageIn, longMessageIn, shortMessageIn})
	assertNotError(t, err, "Failed to write valid long message")
	assertByteEquals(t, b.Bytes(), shortLongShort)

	// Test write failure on message too large
	b = bytes.NewBuffer(nil)
	h = NewHandshakeLayer(NewRecordLayer(b))
	err = h.WriteMessage(tooLongMessageIn)
	assertError(t, err, "Wrote a message exceeding the length bound")

	// Test write failure on underlying write failure
	h = NewHandshakeLayer(NewRecordLayer(ErrorReadWriter{}))
	err = h.WriteMessage(longMessageIn)
	assertError(t, err, "Write succeeded despite error in full fragment send")
	err = h.WriteMessage(shortMessageIn)
	assertError(t, err, "Write succeeded despite error in last fragment send")
}
