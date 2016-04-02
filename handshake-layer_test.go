package mint

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func recordHeaderHex(data []byte) string {
	dataLen := len(data)
	return hex.EncodeToString([]byte{0x16, 0x03, 0x01, byte(dataLen >> 8), byte(dataLen)})
}

var (
	messageType = handshakeTypeClientHello

	tinyMessageIn = &handshakeMessage{
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

	shortMessageIn = &handshakeMessage{
		msgType: messageType,
		body:    shortMessageBody,
	}
	longMessageIn = &handshakeMessage{
		msgType: messageType,
		body:    longMessageBody,
	}
	tooLongMessageIn = &handshakeMessage{
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

	// Also borrow ClientHello and ServerHello inputs from handshake-messages_test.go
	finishedHex         = "1603010006" + "14000002" + "0000"
	chLen               = len(chValidHex) / 2
	shLen               = len(shValidHex) / 2
	chMessageHeaderHex  = hex.EncodeToString([]byte{0x01, 0x00, 0x00, byte(chLen)})
	shMessageHeaderHex  = hex.EncodeToString([]byte{0x02, 0x00, 0x00, byte(shLen)})
	chRecordLen         = len(chMessageHeaderHex)/2 + chLen
	chRecordLenHex      = hex.EncodeToString([]byte{byte(chRecordLen)})
	chValidMessageHex   = "16030100" + chRecordLenHex + chMessageHeaderHex + chValidHex
	chshRecordLen       = chRecordLen + len(shMessageHeaderHex)/2 + shLen
	chshRecordLenHex    = hex.EncodeToString([]byte{byte(chshRecordLen)})
	chshValidMessageHex = "16030100" + chshRecordLenHex + chMessageHeaderHex + chValidHex +
		shMessageHeaderHex + shValidHex
)

func TestMessageMarshal(t *testing.T) {
	tinyMessage, _ := hex.DecodeString(tinyMessageHex)

	out := tinyMessageIn.Marshal()
	assertByteEquals(t, out, tinyMessage)
}

func TestMessageToBody(t *testing.T) {
	// Borrowing serialized bodies from handshake-messages_test.go
	chValid, _ := hex.DecodeString(chValidHex)
	shValid, _ := hex.DecodeString(shValidHex)
	finValid, _ := hex.DecodeString(finValidHex)
	encExtValid, _ := hex.DecodeString(encExtValidHex)
	certValid, _ := hex.DecodeString(certValidHex)
	certVerifyValid, _ := hex.DecodeString(certVerifyValidHex)
	ticketValid, _ := hex.DecodeString(ticketValidHex)

	// Test successful marshal of ClientHello
	hm := handshakeMessage{handshakeTypeClientHello, chValid}
	_, err := hm.toBody()
	assertNotError(t, err, "Failed to convert ClientHello body")

	// Test successful marshal of ServerHello
	hm = handshakeMessage{handshakeTypeServerHello, shValid}
	_, err = hm.toBody()
	assertNotError(t, err, "Failed to convert ServerHello body")

	// Test successful marshal of EncryptedExtensions
	hm = handshakeMessage{handshakeTypeEncryptedExtensions, encExtValid}
	_, err = hm.toBody()
	assertNotError(t, err, "Failed to convert EncryptedExtensions body")

	// Test successful marshal of Certificate
	hm = handshakeMessage{handshakeTypeCertificate, certValid}
	_, err = hm.toBody()
	assertNotError(t, err, "Failed to convert Certificate body")

	// Test successful marshal of CertificateVerify
	hm = handshakeMessage{handshakeTypeCertificateVerify, certVerifyValid}
	_, err = hm.toBody()
	assertNotError(t, err, "Failed to convert CertificateVerify body")

	// Test successful marshal of Finished
	hm = handshakeMessage{handshakeTypeFinished, finValid}
	_, err = hm.toBody()
	assertNotError(t, err, "Failed to convert Finished body")

	// Test successful marshal of NewSessionTicket
	hm = handshakeMessage{handshakeTypeNewSessionTicket, ticketValid}
	_, err = hm.toBody()
	assertNotError(t, err, "Failed to convert NewSessionTicket body")

	// Test failure on unsupported body type
	hm = handshakeMessage{handshakeTypeHelloRetryRequest, []byte{}}
	_, err = hm.toBody()
	assertError(t, err, "Converted an unsupported message")

	// Test failure on marshal failure
	hm = handshakeMessage{handshakeTypeClientHello, []byte{}}
	_, err = hm.toBody()
	assertError(t, err, "Converted an empty message")

}

func TestMessageFromBody(t *testing.T) {
	chValid, _ := hex.DecodeString(chValidHex)

	// Test successful conversion
	hm, err := handshakeMessageFromBody(&chValidIn)
	assertNotError(t, err, "Failed to convert ClientHello body to message")
	assertEquals(t, hm.msgType, chValidIn.Type())
	assertByteEquals(t, hm.body, chValid)

	// Test conversion failure on marshal failure
	chValidIn.cipherSuites = []cipherSuite{}
	hm, err = handshakeMessageFromBody(&chValidIn)
	assertError(t, err, "Converted a ClientHello that should not have marshaled")
	chValidIn.cipherSuites = chCipherSuites
}

func TestReadHandshakeMessage(t *testing.T) {
	short, _ := hex.DecodeString(shortHex)
	long, _ := hex.DecodeString(longHex)
	shortLongShort, _ := hex.DecodeString(shortLongShortHex)
	insufficientData, _ := hex.DecodeString(insufficientDataHex)
	nonHandshake, _ := hex.DecodeString(nonHandshakeHex)

	// Test successful read of a message in a single record
	b := bytes.NewBuffer(short)
	h := newHandshakeLayer(newRecordLayer(b))
	hm, err := h.ReadMessage()
	assertNotError(t, err, "Failed to read a short handshake message")
	assertDeepEquals(t, hm, shortMessageIn)

	// Test successful read of a message split across records
	b = bytes.NewBuffer(long)
	h = newHandshakeLayer(newRecordLayer(b))
	hm, err = h.ReadMessage()
	assertNotError(t, err, "Failed to read a long handshake message")
	assertDeepEquals(t, hm, longMessageIn)

	// Test successful read of multiple messages sequentially
	b = bytes.NewBuffer(shortLongShort)
	h = newHandshakeLayer(newRecordLayer(b))
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
	h = newHandshakeLayer(newRecordLayer(b))
	hm, err = h.ReadMessage()
	assertError(t, err, "Read handshake message with an incomplete header")

	// Test read failure on inability to read body
	b = bytes.NewBuffer(insufficientData)
	h = newHandshakeLayer(newRecordLayer(b))
	hm, err = h.ReadMessage()
	assertError(t, err, "Read handshake message with an incomplete body")

	// Test read failure on receiving a non-handshake record
	b = bytes.NewBuffer(nonHandshake)
	h = newHandshakeLayer(newRecordLayer(b))
	hm, err = h.ReadMessage()
	assertError(t, err, "Read handshake message from a non-handshake record")
}

func TestReadHandshakeMessageBody(t *testing.T) {
	finished, _ := hex.DecodeString(finishedHex)

	// Test successful read
	fin := finishedBody{verifyDataLen: 2}
	b := bytes.NewBuffer(finished)
	h := newHandshakeLayer(newRecordLayer(b))
	hm, err := h.ReadMessageBody(&fin)
	assertNotError(t, err, "Failed to read a valid finished body")
	assertByteEquals(t, fin.verifyData, []byte{0, 0})
	assertEquals(t, hm.msgType, handshakeTypeFinished)
	assertByteEquals(t, hm.body, []byte{0, 0})

	// Test read failure on underlying failure
	b = bytes.NewBuffer(finished[:len(finished)-1])
	h = newHandshakeLayer(newRecordLayer(b))
	_, err = h.ReadMessageBody(&fin)
	assertError(t, err, "Read message body despite unmarshal failure")

	// Test read failure on wrong body type
	ch := clientHelloBody{}
	b = bytes.NewBuffer(finished)
	h = newHandshakeLayer(newRecordLayer(b))
	_, err = h.ReadMessageBody(&ch)
	assertError(t, err, "Read message body with the wrong type")

	// Test read failure on unmarshal failure
	fin.verifyDataLen = 3
	b = bytes.NewBuffer(finished)
	h = newHandshakeLayer(newRecordLayer(b))
	_, err = h.ReadMessageBody(&fin)
	assertError(t, err, "Read message body despite unmarshal failure")

	// Test read failure on left-over data
	fin.verifyDataLen = 1
	b = bytes.NewBuffer(finished)
	h = newHandshakeLayer(newRecordLayer(b))
	_, err = h.ReadMessageBody(&fin)
	assertError(t, err, "Read message body despite extra data")
}

func TestWriteHandshakeMessage(t *testing.T) {
	short, _ := hex.DecodeString(shortHex)
	long, _ := hex.DecodeString(longHex)
	shortLongShort, _ := hex.DecodeString(shortLongShortHex)

	// Test successful write of single message
	b := bytes.NewBuffer(nil)
	h := newHandshakeLayer(newRecordLayer(b))
	err := h.WriteMessage(shortMessageIn)
	assertNotError(t, err, "Failed to write valid short message")
	assertByteEquals(t, b.Bytes(), short)

	// Test successful write of single long message
	b = bytes.NewBuffer(nil)
	h = newHandshakeLayer(newRecordLayer(b))
	err = h.WriteMessage(longMessageIn)
	assertNotError(t, err, "Failed to write valid long message")
	assertByteEquals(t, b.Bytes(), long)

	// Test successful write of multiple messages sequentially
	b = bytes.NewBuffer(nil)
	h = newHandshakeLayer(newRecordLayer(b))
	err = h.WriteMessages([]*handshakeMessage{shortMessageIn, longMessageIn, shortMessageIn})
	assertNotError(t, err, "Failed to write valid long message")
	assertByteEquals(t, b.Bytes(), shortLongShort)

	// Test write failure on message too large
	b = bytes.NewBuffer(nil)
	h = newHandshakeLayer(newRecordLayer(b))
	err = h.WriteMessage(tooLongMessageIn)
	assertError(t, err, "Wrote a message exceeding the length bound")

	// Test write failure on underlying write failure
	h = newHandshakeLayer(newRecordLayer(errorReadWriter{}))
	err = h.WriteMessage(longMessageIn)
	assertError(t, err, "Write succeeded despite error in full fragment send")
	err = h.WriteMessage(shortMessageIn)
	assertError(t, err, "Write succeeded despite error in last fragment send")
}

func TestWriteHandshakeMessageBody(t *testing.T) {
	chValid, _ := hex.DecodeString(chValidHex)
	shValid, _ := hex.DecodeString(shValidHex)
	chValidMessage, _ := hex.DecodeString(chValidMessageHex)
	chshValidMessage, _ := hex.DecodeString(chshValidMessageHex)

	// Test succesful write
	b := bytes.NewBuffer(nil)
	h := newHandshakeLayer(newRecordLayer(b))
	hm, err := h.WriteMessageBody(&chValidIn)
	assertNotError(t, err, "Failed to write valid short message")
	assertByteEquals(t, b.Bytes(), chValidMessage)
	assertEquals(t, hm.msgType, handshakeTypeClientHello)
	assertByteEquals(t, hm.body, chValid)

	// Test succesful write of multiple messages
	b = bytes.NewBuffer(nil)
	h = newHandshakeLayer(newRecordLayer(b))
	hms, err := h.WriteMessageBodies([]handshakeMessageBody{&chValidIn, &shValidIn})
	assertNotError(t, err, "Failed to write valid short message")
	assertByteEquals(t, b.Bytes(), chshValidMessage)
	assertEquals(t, len(hms), 2)
	assertEquals(t, hms[0].msgType, handshakeTypeClientHello)
	assertByteEquals(t, hms[0].body, chValid)
	assertEquals(t, hms[1].msgType, handshakeTypeServerHello)
	assertByteEquals(t, hms[1].body, shValid)

	// Test write failure on marshal failure
	chValidIn.cipherSuites = []cipherSuite{}
	b = bytes.NewBuffer(nil)
	h = newHandshakeLayer(newRecordLayer(b))
	_, err = h.WriteMessageBody(&chValidIn)
	assertError(t, err, "Wrote a message body despite a marshal failure")
	chValidIn.cipherSuites = chCipherSuites
}
