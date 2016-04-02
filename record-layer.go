package mint

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"sync"
)

const (
	sequenceNumberLen = 8       // sequence number length
	recordHeaderLen   = 5       // record header length
	maxFragmentLen    = 1 << 14 // max number of bytes in a record
)

// struct {
//     ContentType type;
//     ProtocolVersion record_version = { 3, 1 };    /* TLS v1.x */
//     uint16 length;
//     opaque fragment[TLSPlaintext.length];
// } TLSPlaintext;
type tlsPlaintext struct {
	// Omitted: record_version (static)
	// Omitted: length         (computed from fragment)
	contentType recordType
	fragment    []byte
}

type recordLayer struct {
	sync.Mutex

	conn     io.ReadWriter // The underlying connection
	buffer   []byte        // The next record to send
	nextData []byte        // The next record to send

	ivLength int         // Length of the seq and nonce fields
	seq      []byte      // Zero-padded sequence number
	nonce    []byte      // Buffer for per-record nonces
	cipher   cipher.AEAD // AEAD cipher
}

func newRecordLayer(conn io.ReadWriter) *recordLayer {
	r := recordLayer{}
	r.conn = conn
	r.ivLength = 0
	return &r
}

func (r *recordLayer) Rekey(suite cipherSuite, key []byte, iv []byte) error {
	switch suite {
	case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_PSK_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:
		params := cipherSuiteMap[suite]

		if len(key) != params.keyLen || len(iv) != params.ivLen {
			return fmt.Errorf("tls.rekey: Crypto parameters are the wrong size")
		}

		aes, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCMWithNonceSize(aes, len(iv))
		r.cipher = gcm
		r.ivLength = len(iv)
	default:
		return fmt.Errorf("tls.rekey: Unsupported ciphersuite: %x", suite)
	}

	r.seq = bytes.Repeat([]byte{0}, r.ivLength)
	r.nonce = make([]byte, r.ivLength)
	copy(r.nonce, iv)
	return nil
}

func (r *recordLayer) incrementSequenceNumber() {
	if r.ivLength == 0 {
		return
	}

	for i := r.ivLength - 1; i > r.ivLength-sequenceNumberLen; i-- {
		r.seq[i]++
		r.nonce[i] ^= (r.seq[i] - 1) ^ r.seq[i]
		if r.seq[i] != 0 {
			return
		}
	}

	// Not allowed to let sequence number wrap.
	// Instead, must renegotiate before it does.
	// Not likely enough to bother.
	panic("TLS: sequence number wraparound")
}

func (r *recordLayer) encrypt(pt *tlsPlaintext, padLen int) *tlsPlaintext {
	// Expand the fragment to hold contentType, padding, and overhead
	originalLen := len(pt.fragment)
	plaintextLen := originalLen + 1 + padLen
	ciphertextLen := plaintextLen + r.cipher.Overhead()

	// Assemble the revised plaintext
	out := &tlsPlaintext{
		contentType: recordTypeApplicationData,
		fragment:    make([]byte, ciphertextLen),
	}
	copy(out.fragment, pt.fragment)
	out.fragment[originalLen] = byte(pt.contentType)
	for i := 1; i <= padLen; i++ {
		out.fragment[originalLen+i] = 0
	}

	// Encrypt the fragment
	payload := out.fragment[:plaintextLen]
	r.cipher.Seal(payload[:0], r.nonce, payload, nil)
	return out
}

func (r *recordLayer) decrypt(pt *tlsPlaintext) (*tlsPlaintext, int, error) {
	decryptLen := len(pt.fragment) - r.cipher.Overhead()
	out := &tlsPlaintext{
		contentType: pt.contentType,
		fragment:    make([]byte, decryptLen),
	}

	// Decrypt
	_, err := r.cipher.Open(out.fragment[:0], r.nonce, pt.fragment, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("tls.record.decrypt: AEAD decrypt failed")
	}

	// Find the padding boundary
	padLen := 0
	for ; padLen < decryptLen+1 && out.fragment[decryptLen-padLen-1] == 0; padLen++ {
	}

	// Transfer the content type
	newLen := decryptLen - padLen - 1
	out.contentType = recordType(out.fragment[newLen])

	// Truncate the message to remove contentType, padding, overhead
	out.fragment = out.fragment[:newLen]
	return out, padLen, nil
}

func (r *recordLayer) readFullBuffer(data []byte) error {
	buffer := make([]byte, cap(data)+recordHeaderLen)

	var index int
	copy(buffer, r.nextData)
	index = len(r.nextData)

	for {
		m, err := r.conn.Read(buffer[index:])
		if m+index >= cap(data) {
			// TODO(bradfitz,agl): slightly suspicious
			// that we're throwing away r.Read's err here.
			copy(data[:cap(data)], buffer)
			r.nextData = buffer[cap(data) : m+index]
			return nil
		}
		if err != nil {
			return err
		}
		index = index + m
	}
}

func (r *recordLayer) ReadRecord() (*tlsPlaintext, error) {
	pt := &tlsPlaintext{}
	header := make([]byte, recordHeaderLen)
	err := r.readFullBuffer(header)
	if err != nil {
		return nil, err
	}

	// Validate content type
	switch recordType(header[0]) {
	default:
		return nil, fmt.Errorf("tls.record: Unknown content type %02x", header[0])
	case recordTypeAlert, recordTypeHandshake, recordTypeApplicationData:
		pt.contentType = recordType(header[0])
	}

	// Validate version
	if !allowWrongVersionNumber && (header[1] != 0x03 || header[2] != 0x01) {
		return nil, fmt.Errorf("tls.record: Invalid version %02x%02x", header[1], header[2])
	}

	// Validate size < max
	size := (int(header[3]) << 8) + int(header[4])
	if size > maxFragmentLen {
		return nil, fmt.Errorf("tls.record: Record size too big")
	}

	// Attempt to read fragment
	pt.fragment = make([]byte, size)
	err = r.readFullBuffer(pt.fragment[:0])
	if err != nil {
		return nil, err
	}

	// Attempt to decrypt fragment
	if r.cipher != nil {
		pt, _, err = r.decrypt(pt)
		if err != nil {
			return nil, err
		}
	}

	logf(logTypeIO, "recordLayer.ReadRecord [%d] [%x]", pt.contentType, pt.fragment)

	r.incrementSequenceNumber()
	return pt, nil
}

func (r *recordLayer) WriteRecord(pt *tlsPlaintext) error {
	return r.WriteRecordWithPadding(pt, 0)
}

func (r *recordLayer) WriteRecordWithPadding(pt *tlsPlaintext, padLen int) error {
	if r.cipher != nil {
		pt = r.encrypt(pt, padLen)
	} else if padLen > 0 {
		return fmt.Errorf("tls.record: Padding can only be done on encrypted records")
	}

	if len(pt.fragment) > maxFragmentLen {
		return fmt.Errorf("tls.record: Record size too big")
	}

	length := len(pt.fragment)
	header := []byte{byte(pt.contentType), 0x03, 0x01, byte(length >> 8), byte(length)}
	record := append(header, pt.fragment...)

	logf(logTypeIO, "recordLayer.WriteRecord [%d] [%x]", pt.contentType, pt.fragment)

	r.incrementSequenceNumber()
	_, err := r.conn.Write(record)
	return err
}
