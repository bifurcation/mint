package mint

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

const (
	plaintextHex = "1503010005F0F1F2F3F4"

	// Random key and IV; hand-encoded ciphertext for the above plaintext
	keyHex         = "45c71e5819170d622a9f4e3a089a0beb"
	ivHex          = "2b7fbbf689f240e3e7aa44a6"
	paddingLength  = 4
	sequenceChange = 17
	ciphertext0Hex = "1703010016621a75932c037ff74d2a9ec7776790e09dcd4811db97"
	ciphertext1Hex = "170301001a621a75932c03076e386b3cebbb8dbf2f37e49ad3e82a70a17833"
	ciphertext2Hex = "170301001a1da650d5da822b7f4eba67f954767fcbbbd4c4bc7f1c61daf701"
)

func TestRekey(t *testing.T) {
	key, _ := hex.DecodeString(keyHex)
	iv, _ := hex.DecodeString(ivHex)

	// Test a succesful rekey
	r := newRecordLayer(bytes.NewBuffer(nil))
	err := r.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)
	assertNotError(t, err, "Failed to rekey")

	// Test rekey failure on wrong-size IV
	r = newRecordLayer(bytes.NewBuffer(nil))
	err = r.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv[:2])
	assertError(t, err, "Allowed rekey with wrong-size IV")

	// Test rekey failure on unknown ciphersuite
	r = newRecordLayer(bytes.NewBuffer(nil))
	err = r.Rekey(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, key, iv)
	assertError(t, err, "Allowed rekey with unknown ciphersuite")
}

func TestSequenceNumberRollover(t *testing.T) {
	defer func() {
		r := recover()
		assert(t, r != nil, "failed to panic on sequence number overflow")
	}()

	key, _ := hex.DecodeString(keyHex)
	iv, _ := hex.DecodeString(ivHex)

	r := newRecordLayer(bytes.NewBuffer(nil))
	r.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)

	for i := 0; i < sequenceNumberLen; i++ {
		r.seq[r.ivLength-i-1] = 0xFF
	}
	r.incrementSequenceNumber()
}

func TestReadRecord(t *testing.T) {
	plaintext, _ := hex.DecodeString(plaintextHex)

	// Test that a known-good frame decodes properly
	r := newRecordLayer(bytes.NewBuffer(plaintext))
	pt, err := r.ReadRecord()
	assertNotError(t, err, "Failed to decode valid plaintext")
	assertEquals(t, pt.contentType, recordTypeAlert)
	assertByteEquals(t, pt.fragment, plaintext[5:])

	// Test failure on unkown record type
	plaintext[0] = 0xFF
	r = newRecordLayer(bytes.NewBuffer(plaintext))
	pt, err = r.ReadRecord()
	assertError(t, err, "Failed to reject record with unknown type")
	plaintext[0] = 0x15

	// Test failure on wrong version
	originalAllowWrongVersionNumber := allowWrongVersionNumber
	allowWrongVersionNumber = false
	plaintext[2] = 0x02
	r = newRecordLayer(bytes.NewBuffer(plaintext))
	pt, err = r.ReadRecord()
	assertError(t, err, "Failed to reject record with incorrect version")
	plaintext[2] = 0x01
	allowWrongVersionNumber = originalAllowWrongVersionNumber

	// Test failure on size too big
	plaintext[3] = 0xFF
	r = newRecordLayer(bytes.NewBuffer(plaintext))
	pt, err = r.ReadRecord()
	assertError(t, err, "Failed to reject record exceeding size limit")
	plaintext[3] = 0x00

	// Test failure on header read failure
	r = newRecordLayer(bytes.NewBuffer(plaintext[:3]))
	pt, err = r.ReadRecord()
	assertError(t, err, "Didn't fail when unable to read header")

	// Test failure on body read failure
	r = newRecordLayer(bytes.NewBuffer(plaintext[:7]))
	pt, err = r.ReadRecord()
	assertError(t, err, "Didn't fail when unable to read fragment")
}

func TestWriteRecord(t *testing.T) {
	plaintext, _ := hex.DecodeString(plaintextHex)

	// Test that plain WriteRecord works
	pt := &tlsPlaintext{
		contentType: recordType(plaintext[0]),
		fragment:    plaintext[5:],
	}
	b := bytes.NewBuffer(nil)
	r := newRecordLayer(b)
	err := r.WriteRecord(pt)
	assertNotError(t, err, "Failed to write valid record")
	assertByteEquals(t, b.Bytes(), plaintext)

	// Test failure on size too big
	pt = &tlsPlaintext{
		contentType: recordType(plaintext[0]),
		fragment:    bytes.Repeat([]byte{0}, maxFragmentLen+1),
	}
	err = r.WriteRecord(pt)
	assertError(t, err, "Allowed a too-large record")

	// Test failure if padding is requested without encryption
	pt = &tlsPlaintext{
		contentType: recordType(plaintext[0]),
		fragment:    bytes.Repeat([]byte{0}, 5),
	}
	err = r.WriteRecordWithPadding(pt, 5)
	assertError(t, err, "Allowed padding without encryption")
}

func TestDecryptRecord(t *testing.T) {
	key, _ := hex.DecodeString(keyHex)
	iv, _ := hex.DecodeString(ivHex)
	plaintext, _ := hex.DecodeString(plaintextHex)
	ciphertext1, _ := hex.DecodeString(ciphertext1Hex)
	ciphertext2, _ := hex.DecodeString(ciphertext2Hex)

	// Test successful decrypt
	r := newRecordLayer(bytes.NewBuffer(ciphertext1))
	r.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)
	pt, err := r.ReadRecord()
	assertNotError(t, err, "Failed to decrypt valid record")
	assertEquals(t, pt.contentType, recordTypeAlert)
	assertByteEquals(t, pt.fragment, plaintext[5:])

	// Test successful decrypt after sequence number change
	r = newRecordLayer(bytes.NewBuffer(ciphertext2))
	r.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)
	for i := 0; i < sequenceChange; i++ {
		r.incrementSequenceNumber()
	}
	pt, err = r.ReadRecord()
	assertNotError(t, err, "Failed to properly handle sequence number change")
	assertEquals(t, pt.contentType, recordTypeAlert)
	assertByteEquals(t, pt.fragment, plaintext[5:])

	// Test failure on decrypt failure
	ciphertext1[7] ^= 0xFF
	r = newRecordLayer(bytes.NewBuffer(ciphertext1))
	r.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)
	pt, err = r.ReadRecord()
	assertError(t, err, "Failed to reject invalid record")
	ciphertext1[7] ^= 0xFF
}

func TestEncryptRecord(t *testing.T) {
	key, _ := hex.DecodeString(keyHex)
	iv, _ := hex.DecodeString(ivHex)
	plaintext, _ := hex.DecodeString(plaintextHex)
	ciphertext0, _ := hex.DecodeString(ciphertext0Hex)
	ciphertext1, _ := hex.DecodeString(ciphertext1Hex)
	ciphertext2, _ := hex.DecodeString(ciphertext2Hex)

	// Test successful encrypt
	b := bytes.NewBuffer(nil)
	r := newRecordLayer(b)
	r.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)
	pt := &tlsPlaintext{
		contentType: recordType(plaintext[0]),
		fragment:    plaintext[5:],
	}
	err := r.WriteRecord(pt)
	assertNotError(t, err, "Failed to encrypt valid record")
	assertByteEquals(t, b.Bytes(), ciphertext0)

	// Test successful encrypt with padding
	b.Truncate(0)
	r = newRecordLayer(b)
	r.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)
	pt = &tlsPlaintext{
		contentType: recordType(plaintext[0]),
		fragment:    plaintext[5:],
	}
	err = r.WriteRecordWithPadding(pt, paddingLength)
	assertNotError(t, err, "Failed to encrypt valid record")
	assertByteEquals(t, b.Bytes(), ciphertext1)

	// Test successful enc after sequence number change
	b.Truncate(0)
	r = newRecordLayer(b)
	r.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)
	for i := 0; i < sequenceChange; i++ {
		r.incrementSequenceNumber()
	}
	pt = &tlsPlaintext{
		contentType: recordType(plaintext[0]),
		fragment:    plaintext[5:],
	}
	err = r.WriteRecordWithPadding(pt, paddingLength)
	assertNotError(t, err, "Failed to properly handle sequence number change")
	assertByteEquals(t, b.Bytes(), ciphertext2)

	// Test failure on size too big after encrypt
	b.Truncate(0)
	r = newRecordLayer(b)
	r.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)
	pt = &tlsPlaintext{
		contentType: recordType(plaintext[0]),
		fragment:    bytes.Repeat([]byte{0}, maxFragmentLen-paddingLength),
	}
	err = r.WriteRecordWithPadding(pt, paddingLength)
	assertError(t, err, "Allowed a too-large record")
}

func TestReadWrite(t *testing.T) {
	key, _ := hex.DecodeString(keyHex)
	iv, _ := hex.DecodeString(ivHex)
	plaintext, _ := hex.DecodeString(plaintextHex)

	b := bytes.NewBuffer(nil)
	out := newRecordLayer(b)
	in := newRecordLayer(b)

	// Unencrypted
	ptIn := &tlsPlaintext{
		contentType: recordType(plaintext[0]),
		fragment:    plaintext[5:],
	}
	err := out.WriteRecord(ptIn)
	assertNotError(t, err, "Failed to write record")
	ptOut, err := in.ReadRecord()
	assertNotError(t, err, "Failed to read record")
	assertEquals(t, ptIn.contentType, ptOut.contentType)
	assertByteEquals(t, ptIn.fragment, ptOut.fragment)

	// Encrypted
	in.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)
	out.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)
	err = out.WriteRecord(ptIn)
	assertNotError(t, err, "Failed to write record")
	ptOut, err = in.ReadRecord()
	assertNotError(t, err, "Failed to read record")
	assertEquals(t, ptIn.contentType, ptOut.contentType)
	assertByteEquals(t, ptIn.fragment, ptOut.fragment)
}

func TestOverSocket(t *testing.T) {
	key, _ := hex.DecodeString(keyHex)
	iv, _ := hex.DecodeString(ivHex)
	plaintext, _ := hex.DecodeString(plaintextHex)

	socketReady := make(chan bool)
	done := make(chan tlsPlaintext, 1)
	port := ":9001"

	ptIn := tlsPlaintext{
		contentType: recordType(plaintext[0]),
		fragment:    plaintext[5:],
	}

	go func() {
		ln, err := net.Listen("tcp", port)
		assertNotError(t, err, "Unable to listen")
		socketReady <- true

		conn, err := ln.Accept()
		assertNotError(t, err, "Unable to accept")
		defer conn.Close()

		in := newRecordLayer(conn)
		in.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)
		pt, err := in.ReadRecord()
		assertNotError(t, err, "Unable to read record")

		done <- *pt
	}()

	<-socketReady
	conn, err := net.Dial("tcp", port)
	assertNotError(t, err, "Unable to dial")

	out := newRecordLayer(conn)
	out.Rekey(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, key, iv)
	err = out.WriteRecord(&ptIn)
	assertNotError(t, err, "Unable to write record")

	ptOut := <-done
	assertEquals(t, ptIn.contentType, ptOut.contentType)
	assertByteEquals(t, ptIn.fragment, ptOut.fragment)
}
