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
		length:  4,
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
		length:  uint32(len(shortMessageBody)),
	}
	longMessageIn = &HandshakeMessage{
		msgType: messageType,
		body:    longMessageBody,
		length:  uint32(len(longMessageBody)),
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

func newTestHandshakeMessage(t HandshakeType, m []byte) HandshakeMessage {
	return HandshakeMessage{
		msgType: t,
		body:    m,
	}
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
	hm := newTestHandshakeMessage(HandshakeTypeClientHello, chValid)
	_, err := hm.ToBody()
	assertNotError(t, err, "Failed to convert ClientHello body")

	// Test successful marshal of ServerHello
	hm = newTestHandshakeMessage(HandshakeTypeServerHello, shValid)
	_, err = hm.ToBody()
	assertNotError(t, err, "Failed to convert ServerHello body")

	// Test successful marshal of EncryptedExtensions
	hm = newTestHandshakeMessage(HandshakeTypeEncryptedExtensions, encExtValid)
	_, err = hm.ToBody()
	assertNotError(t, err, "Failed to convert EncryptedExtensions body")

	// Test successful marshal of Certificate
	hm = newTestHandshakeMessage(HandshakeTypeCertificate, certValid)
	_, err = hm.ToBody()
	assertNotError(t, err, "Failed to convert Certificate body")

	// Test successful marshal of CertificateVerify
	hm = newTestHandshakeMessage(HandshakeTypeCertificateVerify, certVerifyValid)
	_, err = hm.ToBody()
	assertNotError(t, err, "Failed to convert CertificateVerify body")

	// Test successful marshal of Finished
	hm = newTestHandshakeMessage(HandshakeTypeFinished, finValid)
	_, err = hm.ToBody()
	assertNotError(t, err, "Failed to convert Finished body")

	// Test successful marshal of NewSessionTicket
	hm = newTestHandshakeMessage(HandshakeTypeNewSessionTicket, ticketValid)
	_, err = hm.ToBody()
	assertNotError(t, err, "Failed to convert NewSessionTicket body")

	// Test failure on unsupported body type
	hm = newTestHandshakeMessage(HandshakeTypeHelloRetryRequest, []byte{})
	_, err = hm.ToBody()
	assertError(t, err, "Converted an unsupported message")

	// Test failure on marshal failure
	hm = newTestHandshakeMessage(HandshakeTypeClientHello, []byte{})
	_, err = hm.ToBody()
	assertError(t, err, "Converted an empty message")

}

func TestMessageFromBody(t *testing.T) {
	chValid := unhex(chValidHex)

	b := bytes.NewBuffer(nil)
	h := NewHandshakeLayerTLS(&HandshakeContext{}, NewRecordLayerTLS(b, directionRead))

	// Test successful conversion
	hm, err := h.HandshakeMessageFromBody(&chValidIn)
	assertNotError(t, err, "Failed to convert ClientHello body to message")
	assertEquals(t, hm.msgType, chValidIn.Type())
	assertByteEquals(t, hm.body, chValid)

	// Test conversion failure on marshal failure
	chValidIn.CipherSuites = []CipherSuite{}
	hm, err = h.HandshakeMessageFromBody(&chValidIn)
	assertError(t, err, "Converted a ClientHello that should not have marshaled")
	chValidIn.CipherSuites = chCipherSuites
}

func newHandshakeLayerFromBytes(d []byte) *HandshakeLayer {
	hc := &HandshakeContext{}
	b := bytes.NewBuffer(d)
	hc.hIn = NewHandshakeLayerTLS(hc, NewRecordLayerTLS(b, directionRead))
	return hc.hIn
}

func TestReadHandshakeMessage(t *testing.T) {
	short := unhex(shortHex)
	long := unhex(longHex)
	shortLongShort := unhex(shortLongShortHex)
	insufficientData := unhex(insufficientDataHex)
	nonHandshake := unhex(nonHandshakeHex)

	// Test successful read of a message in a single record
	h := newHandshakeLayerFromBytes(short)
	hm, err := h.ReadMessage()
	assertNotError(t, err, "Failed to read a short handshake message")
	assertDeepEquals(t, hm, shortMessageIn)

	// Test successful read of a message split across records
	h = newHandshakeLayerFromBytes(long)
	hm, err = h.ReadMessage()
	assertNotError(t, err, "Failed to read a long handshake message")
	assertDeepEquals(t, hm, longMessageIn)

	// Test successful read of multiple messages sequentially
	h = newHandshakeLayerFromBytes(shortLongShort)
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
	h = newHandshakeLayerFromBytes(short[:handshakeHeaderLenTLS-1])
	hm, err = h.ReadMessage()
	assertError(t, err, "Read handshake message with an incomplete header")

	// Test read failure on inability to read body
	h = newHandshakeLayerFromBytes(insufficientData)
	hm, err = h.ReadMessage()
	assertError(t, err, "Read handshake message with an incomplete body")

	// Test read failure on receiving a non-handshake record
	h = newHandshakeLayerFromBytes(nonHandshake)
	hm, err = h.ReadMessage()
	assertError(t, err, "Read handshake message from a non-handshake record")
}

func testWriteHandshakeMessage(h *HandshakeLayer, hm *HandshakeMessage) error {
	hm.cipher = h.conn.cipher
	_, err := h.WriteMessage(hm)
	return err
}

func TestWriteHandshakeMessage(t *testing.T) {
	short := unhex(shortHex)
	long := unhex(longHex)

	// Test successful write of single message
	b := bytes.NewBuffer(nil)
	h := NewHandshakeLayerTLS(&HandshakeContext{}, NewRecordLayerTLS(b, directionWrite))
	err := testWriteHandshakeMessage(h, shortMessageIn)
	assertNotError(t, err, "Failed to write valid short message")
	assertByteEquals(t, b.Bytes(), short)

	// Test successful write of single long message
	b = bytes.NewBuffer(nil)
	h = NewHandshakeLayerTLS(&HandshakeContext{}, NewRecordLayerTLS(b, directionWrite))
	err = testWriteHandshakeMessage(h, longMessageIn)
	assertNotError(t, err, "Failed to write valid long message")
	assertByteEquals(t, b.Bytes(), long)

	// Test write failure on message too large
	b = bytes.NewBuffer(nil)
	h = NewHandshakeLayerTLS(&HandshakeContext{}, NewRecordLayerTLS(b, directionWrite))
	err = testWriteHandshakeMessage(h, tooLongMessageIn)
	assertError(t, err, "Wrote a message exceeding the length bound")

	// Test write failure on underlying write failure
	h = NewHandshakeLayerTLS(&HandshakeContext{}, NewRecordLayerTLS(ErrorReadWriter{}, directionWrite))
	err = testWriteHandshakeMessage(h, longMessageIn)
	assertError(t, err, "Write succeeded despite error in full fragment send")
	err = testWriteHandshakeMessage(h, shortMessageIn)
	assertError(t, err, "Write succeeded despite error in last fragment send")
}

type testReassembleFixture struct {
	t     *testing.T
	c     HandshakeContext
	h     *HandshakeLayer
	r     *RecordLayer
	rd    *pipeConn
	wr    *pipeConn
	m0    *HandshakeMessage
	m0f0  *HandshakeMessage
	m0f1  *HandshakeMessage
	m0f2  *HandshakeMessage
	m0f1x *HandshakeMessage
	m0f1y *HandshakeMessage
	m1    *HandshakeMessage
}

func newTestReassembleFixture(t *testing.T) *testReassembleFixture {
	f := testReassembleFixture{t: t}
	// Make two messages, m0 and m1, with m0 fragmented
	m0 := make([]byte, 2048)
	for i := range m0 {
		m0[i] = byte(i % 13)
	}
	f.m0 = newHsFragment(m0, 0, 0, 2048)
	f.m0f0 = newHsFragment(m0, 0, 0, 1024)
	f.m0f1 = newHsFragment(m0, 0, 1024, 512)
	f.m0f2 = newHsFragment(m0, 0, 1536, 512)
	f.m0f1x = newHsFragment(m0, 0, 512, 1000)
	f.m0f1y = newHsFragment(m0, 0, 512, 1048)

	m1 := make([]byte, 2048)
	for i := range m1 {
		m1[i] = byte(i % 23)
	}
	f.m1 = newHsFragment(m1, 1, 0, 2048)
	f.rd, f.wr = pipe()

	f.r = NewRecordLayerDTLS(f.rd, directionRead)
	f.h = NewHandshakeLayerDTLS(&f.c, f.r)
	f.c.hIn = f.h
	f.c.timers = newTimerSet()
	f.h.nonblocking = true

	return &f
}

func newHsFragment(full []byte, seq uint32, offset uint32, fragLen uint32) *HandshakeMessage {
	return &HandshakeMessage{
		HandshakeTypeClientHello,
		seq,
		full[offset : offset+fragLen],
		true,
		offset,
		uint32(len(full)),
		nil,
	}
}

func (f *testReassembleFixture) addFragment(in *HandshakeMessage, expected *HandshakeMessage) {
	if in != nil {
		b := in.Marshal()
		r := []byte{byte(RecordTypeHandshake), 0xfe, 0xff,
			0, 0, 0, 0, 0, 0, 0, 0,
			byte((len(b) >> 8) & 0xff), byte(len(b) & 0xff)}
		r = append(r, b...)
		f.wr.Write(r)
	}
	h2, err := f.h.ReadMessage()
	if expected == nil {
		assertEquals(f.t, (*HandshakeMessage)(nil), h2)
		assertEquals(f.t, nil, err)
	} else {
		assertNotError(f.t, err, "Error reading handshake")
		assertEquals(f.t, expected.seq, h2.seq)
		assertByteEquals(f.t, expected.body, h2.body)
	}
}

func TestHandshakeDTLSInOrder(t *testing.T) {
	f := newTestReassembleFixture(t)

	f.addFragment(f.m0, f.m0)
	f.addFragment(f.m0, nil)
	f.addFragment(f.m1, f.m1)
}

func TestHandshakeDTLSOutOfOrder(t *testing.T) {
	f := newTestReassembleFixture(t)

	f.addFragment(f.m1, nil)
	f.addFragment(f.m0, f.m0)
	f.addFragment(nil, f.m1)
}

func TestHandshakeDTLSNonOverlappingFragments(t *testing.T) {
	f := newTestReassembleFixture(t)

	f.addFragment(f.m0f0, nil)
	f.addFragment(f.m0f1, nil)
	f.addFragment(f.m0f2, f.m0)
}

func TestHandshakeDTLSNonOverlappingFragmentsOO(t *testing.T) {
	f := newTestReassembleFixture(t)

	f.addFragment(f.m0f0, nil)
	f.addFragment(f.m0f2, nil)
	f.addFragment(f.m0f1, f.m0)
}

func TestHandshakeDTLSOverlappingFragments1(t *testing.T) {
	f := newTestReassembleFixture(t)

	f.addFragment(f.m0f0, nil)
	f.addFragment(f.m0f1, nil)
	f.addFragment(f.m0f1x, nil)
	f.addFragment(f.m0f2, f.m0)
}

func TestHandshakeDTLSOverlappingFragments2(t *testing.T) {
	f := newTestReassembleFixture(t)

	f.addFragment(f.m0f0, nil)
	f.addFragment(f.m0f1y, nil)
	f.addFragment(f.m0f2, f.m0)
}
