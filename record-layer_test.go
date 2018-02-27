package mint

import (
	"bytes"
	"fmt"
	"io"
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

func newRecordLayerFromBytes(b []byte) *RecordLayer {
	return NewRecordLayerTLS(bytes.NewBuffer(b), directionRead)
}

func TestRekey(t *testing.T) {
	key := unhex(keyHex)
	iv := unhex(ivHex)

	r := NewRecordLayerTLS(bytes.NewBuffer(nil), directionWrite)
	err := r.Rekey(EpochApplicationData, newAESGCM, key, iv)
	assertNotError(t, err, "Failed to rekey")
}

func TestSequenceNumberRollover(t *testing.T) {
	defer func() {
		r := recover()
		assertTrue(t, r != nil, "failed to panic on sequence number overflow")
	}()

	key := unhex(keyHex)
	iv := unhex(ivHex)

	cs, err := newCipherStateAead(EpochApplicationData, newAESGCM, key, iv)
	assertNotError(t, err, "Couldn't create cipher state")
	cs.seq = (1 << 48) - 1
	cs.incrementSequenceNumber()
}

func TestReadRecord(t *testing.T) {
	plaintext := unhex(plaintextHex)

	// Test that a known-good frame decodes properly
	r := newRecordLayerFromBytes(plaintext)
	pt, err := r.ReadRecord()
	assertNotError(t, err, "Failed to decode valid plaintext")
	assertEquals(t, pt.contentType, RecordTypeAlert)
	assertByteEquals(t, pt.fragment, plaintext[5:])

	// Test failure on unkown record type
	plaintext[0] = 0xFF
	r = newRecordLayerFromBytes(plaintext)
	pt, err = r.ReadRecord()
	assertError(t, err, "Failed to reject record with unknown type")
	plaintext[0] = 0x15

	// Test failure on wrong version
	originalAllowWrongVersionNumber := allowWrongVersionNumber
	allowWrongVersionNumber = false
	plaintext[2] = 0x02
	r = newRecordLayerFromBytes(plaintext)
	pt, err = r.ReadRecord()
	assertError(t, err, "Failed to reject record with incorrect version")
	plaintext[2] = 0x01
	allowWrongVersionNumber = originalAllowWrongVersionNumber

	// Test failure on size too big
	plaintext[3] = 0xFF
	r = newRecordLayerFromBytes(plaintext)
	pt, err = r.ReadRecord()
	assertError(t, err, "Failed to reject record exceeding size limit")
	plaintext[3] = 0x00

	// Test failure on header read failure
	r = newRecordLayerFromBytes(plaintext[:3])
	pt, err = r.ReadRecord()
	assertError(t, err, "Didn't fail when unable to read header")

	// Test failure on body read failure
	r = newRecordLayerFromBytes(plaintext[:7])
	pt, err = r.ReadRecord()
	assertError(t, err, "Didn't fail when unable to read fragment")
}

func TestWriteRecord(t *testing.T) {
	plaintext := unhex(plaintextHex)

	// Test that plain WriteRecord works
	pt := &TLSPlaintext{
		contentType: RecordType(plaintext[0]),
		fragment:    plaintext[5:],
	}
	b := bytes.NewBuffer(nil)
	r := NewRecordLayerTLS(b, directionWrite)
	err := r.WriteRecord(pt)
	assertNotError(t, err, "Failed to write valid record")
	assertByteEquals(t, b.Bytes(), plaintext)

	// Test failure on size too big
	pt = &TLSPlaintext{
		contentType: RecordType(plaintext[0]),
		fragment:    bytes.Repeat([]byte{0}, maxFragmentLen+1),
	}
	err = r.WriteRecord(pt)
	assertError(t, err, "Allowed a too-large record")

	// Test failure if padding is requested without encryption
	pt = &TLSPlaintext{
		contentType: RecordType(plaintext[0]),
		fragment:    bytes.Repeat([]byte{0}, 5),
	}
	err = r.WriteRecordWithPadding(pt, 5)
	assertError(t, err, "Allowed padding without encryption")
}

func TestDecryptRecord(t *testing.T) {
	key := unhex(keyHex)
	iv := unhex(ivHex)
	plaintext := unhex(plaintextHex)
	ciphertext1 := unhex(ciphertext1Hex)
	ciphertext2 := unhex(ciphertext2Hex)

	// Test successful decrypt
	r := newRecordLayerFromBytes(ciphertext1)
	r.Rekey(EpochApplicationData, newAESGCM, key, iv)
	pt, err := r.ReadRecord()
	assertNotError(t, err, "Failed to decrypt valid record")
	assertEquals(t, pt.contentType, RecordTypeAlert)
	assertByteEquals(t, pt.fragment, plaintext[5:])

	// Test successful decrypt after sequence number change
	r = newRecordLayerFromBytes(ciphertext2)
	r.Rekey(EpochApplicationData, newAESGCM, key, iv)
	for i := 0; i < sequenceChange; i++ {
		r.cipher.incrementSequenceNumber()
	}
	pt, err = r.ReadRecord()
	assertNotError(t, err, "Failed to properly handle sequence number change")
	assertEquals(t, pt.contentType, RecordTypeAlert)
	assertByteEquals(t, pt.fragment, plaintext[5:])

	// Test failure on decrypt failure
	ciphertext1[7] ^= 0xFF
	r = newRecordLayerFromBytes(ciphertext1)
	r.Rekey(EpochApplicationData, newAESGCM, key, iv)
	pt, err = r.ReadRecord()
	assertError(t, err, "Failed to reject invalid record")
	ciphertext1[7] ^= 0xFF
}

func TestEncryptRecord(t *testing.T) {
	key := unhex(keyHex)
	iv := unhex(ivHex)
	plaintext := unhex(plaintextHex)
	ciphertext0 := unhex(ciphertext0Hex)
	ciphertext1 := unhex(ciphertext1Hex)
	ciphertext2 := unhex(ciphertext2Hex)

	// Test successful encrypt
	b := bytes.NewBuffer(nil)
	r := NewRecordLayerTLS(b, directionWrite)
	r.Rekey(EpochApplicationData, newAESGCM, key, iv)
	pt := &TLSPlaintext{
		contentType: RecordType(plaintext[0]),
		fragment:    plaintext[5:],
	}
	err := r.WriteRecord(pt)
	assertNotError(t, err, "Failed to encrypt valid record")
	assertByteEquals(t, b.Bytes(), ciphertext0)

	// Test successful encrypt with padding
	b.Truncate(0)
	r = NewRecordLayerTLS(b, directionWrite)
	r.Rekey(EpochApplicationData, newAESGCM, key, iv)
	pt = &TLSPlaintext{
		contentType: RecordType(plaintext[0]),
		fragment:    plaintext[5:],
	}
	err = r.WriteRecordWithPadding(pt, paddingLength)
	assertNotError(t, err, "Failed to encrypt valid record")
	assertByteEquals(t, b.Bytes(), ciphertext1)

	// Test successful enc after sequence number change
	b.Truncate(0)
	r = NewRecordLayerTLS(b, directionWrite)
	r.Rekey(EpochApplicationData, newAESGCM, key, iv)
	for i := 0; i < sequenceChange; i++ {
		r.cipher.incrementSequenceNumber()
	}
	pt = &TLSPlaintext{
		contentType: RecordType(plaintext[0]),
		fragment:    plaintext[5:],
	}
	err = r.WriteRecordWithPadding(pt, paddingLength)
	assertNotError(t, err, "Failed to properly handle sequence number change")
	assertByteEquals(t, b.Bytes(), ciphertext2)

	// Test failure on size too big after encrypt
	b.Truncate(0)
	r = NewRecordLayerTLS(b, directionWrite)
	r.Rekey(EpochApplicationData, newAESGCM, key, iv)
	pt = &TLSPlaintext{
		contentType: RecordType(plaintext[0]),
		fragment:    bytes.Repeat([]byte{0}, maxFragmentLen-paddingLength),
	}
	err = r.WriteRecordWithPadding(pt, paddingLength)
	assertError(t, err, "Allowed a too-large record")
}

func TestReadWriteTLS(t *testing.T) {
	key := unhex(keyHex)
	iv := unhex(ivHex)
	plaintext := unhex(plaintextHex)

	b := bytes.NewBuffer(nil)
	out := NewRecordLayerTLS(b, directionWrite)
	in := NewRecordLayerTLS(b, directionRead)

	// Unencrypted
	ptIn := &TLSPlaintext{
		contentType: RecordType(plaintext[0]),
		fragment:    plaintext[5:],
	}
	err := out.WriteRecord(ptIn)
	assertNotError(t, err, "Failed to write record")
	ptOut, err := in.ReadRecord()
	assertNotError(t, err, "Failed to read record")
	assertEquals(t, ptIn.contentType, ptOut.contentType)
	assertByteEquals(t, ptIn.fragment, ptOut.fragment)

	// Encrypted
	in.Rekey(EpochApplicationData, newAESGCM, key, iv)
	out.Rekey(EpochApplicationData, newAESGCM, key, iv)
	err = out.WriteRecord(ptIn)
	assertNotError(t, err, "Failed to write record")
	ptOut, err = in.ReadRecord()
	assertNotError(t, err, "Failed to read record")
	assertEquals(t, ptIn.contentType, ptOut.contentType)
	assertByteEquals(t, ptIn.fragment, ptOut.fragment)
}

func TestReadWriteDTLS(t *testing.T) {
	key := unhex(keyHex)
	iv := unhex(ivHex)
	plaintext := unhex(plaintextHex)

	b := bytes.NewBuffer(nil)
	out := NewRecordLayerDTLS(b, directionWrite)
	out.SetVersion(tls12Version)
	in := NewRecordLayerDTLS(b, directionRead)
	in.SetVersion(tls12Version)

	// Unencrypted
	ptIn := &TLSPlaintext{
		contentType: RecordType(plaintext[0]),
		fragment:    plaintext[5:],
	}
	err := out.WriteRecord(ptIn)
	assertNotError(t, err, "Failed to write record")
	ptOut, err := in.ReadRecord()
	assertNotError(t, err, "Failed to read record")

	assertEquals(t, ptIn.contentType, ptOut.contentType)
	assertByteEquals(t, ptIn.fragment, ptOut.fragment)

	// Encrypted
	in.Rekey(EpochApplicationData, newAESGCM, key, iv)
	out.Rekey(EpochApplicationData, newAESGCM, key, iv)
	err = out.WriteRecord(ptIn)
	assertNotError(t, err, "Failed to write record")
	ptOut, err = in.ReadRecord()
	assertNotError(t, err, "Failed to read record")
	assertEquals(t, ptIn.contentType, ptOut.contentType)
	assertByteEquals(t, ptIn.fragment, ptOut.fragment)
}

func TestOverSocket(t *testing.T) {
	key := unhex(keyHex)
	iv := unhex(ivHex)
	plaintext := unhex(plaintextHex)

	socketReady := make(chan bool)
	done := make(chan TLSPlaintext, 1)
	port := ":9001"

	ptIn := TLSPlaintext{
		contentType: RecordType(plaintext[0]),
		fragment:    plaintext[5:],
	}

	go func() {
		ln, err := net.Listen("tcp", port)
		assertNotError(t, err, "Unable to listen")
		socketReady <- true

		conn, err := ln.Accept()
		assertNotError(t, err, "Unable to accept")
		defer conn.Close()

		in := NewRecordLayerTLS(conn, directionRead)
		in.Rekey(EpochApplicationData, newAESGCM, key, iv)
		pt, err := in.ReadRecord()
		assertNotError(t, err, "Unable to read record")

		done <- *pt
	}()

	<-socketReady
	conn, err := net.Dial("tcp", port)
	assertNotError(t, err, "Unable to dial")

	out := NewRecordLayerTLS(conn, directionWrite)
	out.Rekey(EpochApplicationData, newAESGCM, key, iv)
	err = out.WriteRecord(&ptIn)
	assertNotError(t, err, "Unable to write record")

	ptOut := <-done
	assertEquals(t, ptIn.contentType, ptOut.contentType)
	assertByteEquals(t, ptIn.fragment, ptOut.fragment)
}

type NoEofReader struct {
	r *bytes.Buffer
}

func (p *NoEofReader) Read(data []byte) (n int, err error) {
	n, err = p.r.Read(data)

	// Suppress bytes.Buffer's EOF on an empty buffer
	if err == io.EOF {
		err = nil
	}
	return
}

func (p *NoEofReader) Write(data []byte) (n int, err error) {
	return 0, fmt.Errorf("Not allowed")
}

func TestNonblockingRecord(t *testing.T) {
	key := unhex(keyHex)
	iv := unhex(ivHex)
	plaintext := unhex(plaintextHex)
	ciphertext1 := unhex(ciphertext1Hex)

	// Add the prefix, which should cause blocking.
	b := bytes.NewBuffer(ciphertext1[:1])
	r := NewRecordLayerTLS(&NoEofReader{b}, directionRead)
	r.Rekey(EpochApplicationData, newAESGCM, key, iv)
	pt, err := r.ReadRecord()
	assertEquals(t, err, AlertWouldBlock)

	// Now the rest of the record, which lets us decrypt it
	b.Write(ciphertext1[1:])
	pt, err = r.ReadRecord()
	assertNotError(t, err, "Failed to decrypt valid record")
	assertEquals(t, pt.contentType, RecordTypeAlert)
	assertByteEquals(t, pt.fragment, plaintext[5:])
}
