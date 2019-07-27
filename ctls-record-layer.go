package mint

import (
	"fmt"
	"io"
	"sync"

	"github.com/bifurcation/mint/syntax"
)

type CTLSRecordLayerFactory struct {
	IsServer    bool
	Compression HandshakeCompression
}

func (f CTLSRecordLayerFactory) NewLayer(conn io.ReadWriter, dir Direction) RecordLayer {
	compression := f.Compression
	if compression == nil {
		compression = NoHandshakeCompression{}
	}

	return &CTLSRecordLayer{
		label:       "",
		direction:   dir,
		conn:        conn,
		cipher:      newCipherStateNull(),
		server:      f.IsServer,
		compression: compression,
	}
}

type HandshakeCompression interface {
	CompressClientHello(ch []byte) ([]byte, error)
	CompressServerHello(sh []byte) ([]byte, error)
	CompressServerFlight(hms []byte) ([]byte, error)
	CompressClientFlight(hms []byte) ([]byte, error)

	ReadClientHello(data []byte) ([]byte, int, error)
	ReadServerHello(data []byte) ([]byte, int, error)
	DecompressServerFlight(hms []byte) ([]byte, error)
	DecompressClientFlight(hms []byte) ([]byte, error)
}

type CTLSRecordLayer struct {
	sync.Mutex
	label     string
	direction Direction
	conn      io.ReadWriter
	cipher    *CipherState

	server      bool
	nextData    []byte
	compression HandshakeCompression
}

func (r *CTLSRecordLayer) Impl() *CTLSRecordLayer {
	return r
}

func (r *CTLSRecordLayer) SetVersion(v uint16) {
}

func (r *CTLSRecordLayer) ResetClear(seq uint64) {
	r.cipher = newCipherStateNull()
	r.cipher.seq = seq
}

func (r *CTLSRecordLayer) Epoch() Epoch {
	return r.cipher.epoch
}

func (r *CTLSRecordLayer) Cipher() *CipherState {
	return r.cipher
}

func (r *CTLSRecordLayer) SetLabel(s string) {
	r.label = s
}

func (r *CTLSRecordLayer) Rekey(epoch Epoch, factory AEADFactory, keys *KeySet) error {
	cipher, err := newCipherStateAead(epoch, factory, keys.Keys[labelForKey], keys.Keys[labelForIV])
	if err != nil {
		return err
	}
	r.cipher = cipher
	return nil
}

func (r *CTLSRecordLayer) DiscardReadKey(epoch Epoch) {
}

func (r *CTLSRecordLayer) PeekRecordType(block bool) (RecordType, error) {
	// The compact record layer only does handshake records
	return RecordTypeHandshake, nil
}

func (r *CTLSRecordLayer) ReadRecord() (*TLSPlaintext, error) {
	if len(r.nextData) == 0 {
		buffer := make([]byte, maxFragmentLen)
		n, err := r.conn.Read(buffer)
		if n == 0 && err == nil {
			return nil, AlertWouldBlock
		}
		if err != nil {
			return nil, err
		}

		r.nextData = buffer[:n]
	}

	var seq = r.cipher.seq
	var fragment []byte
	var consumed int
	var err error
	switch {
	case r.cipher.cipher != nil:
		// If we have a cipher configured, treat the entire remaining
		// buffer as ciphertext and decrypt it

		// Synthesize the header for AEAD
		length := len(r.nextData) + 1
		contentType := RecordTypeApplicationData
		header := []byte{byte(contentType),
			byte(tls10Version >> 8), byte(tls10Version & 0xff),
			byte(length >> 8), byte(length)}

		plaintext, err := r.cipher.cipher.Open(nil, r.cipher.computeNonce(seq), r.nextData, header)
		if err != nil {
			return nil, err
		}

		consumed = len(r.nextData)

		if r.server {
			fragment, err = r.compression.DecompressClientFlight(plaintext)
		} else {
			fragment, err = r.compression.DecompressServerFlight(plaintext)
		}
		if err != nil {
			return nil, err
		}

	case r.server:
		// If we're the server and there's no cipher, must be ClientHello
		fragment, consumed, err = r.compression.ReadClientHello(r.nextData)
		if err != nil {
			return nil, err
		}

	default:
		// If we're the client and there's no cipher, must be ServerHello
		fragment, consumed, err = r.compression.ReadServerHello(r.nextData)
		if err != nil {
			return nil, err
		}
	}

	// Truncate remaining data
	r.nextData = r.nextData[consumed:]

	pt := &TLSPlaintext{
		contentType: RecordTypeHandshake,
		epoch:       r.Epoch(),
		seq:         seq,
		fragment:    fragment,
	}

	logf(logTypeIO, "%s RecordLayer.ReadRecord epoch=[%d] seq=[%x] [%d] plaintext=[%x]", r.label, pt.epoch, pt.seq, pt.contentType, pt.fragment)
	r.cipher.incrementSequenceNumber()
	return pt, nil
}

func (r *CTLSRecordLayer) ReadRecordAnyEpoch() (*TLSPlaintext, error) {
	return r.ReadRecord()
}

func (r *CTLSRecordLayer) WriteRecord(pt *TLSPlaintext) error {
	return r.WriteRecordWithPadding(pt, r.cipher, 0)
}

func (r *CTLSRecordLayer) WriteRecordWithPadding(pt *TLSPlaintext, cipher *CipherState, padLen int) error {
	if pt.contentType != RecordTypeHandshake {
		panic(fmt.Sprintf("non-handshake record [%02x]", pt.contentType)) // XXX
		return fmt.Errorf("tls.record: Only handshake messages allowed with compact record layer")
	}

	if padLen > 0 {
		return fmt.Errorf("tls.record: No padding with compact record layer")
	}

	var err error
	var ciphertext []byte
	if cipher.cipher != nil {
		logf(logTypeIO, "%s CompactRecordLayer.WriteRecord epoch=[%s] seq=[%x] [%d] plaintext=[%x]", r.label, cipher.epoch.label(), cipher.seq, pt.contentType, pt.fragment)

		var compressed []byte
		if r.server {
			compressed, err = r.compression.CompressServerFlight(pt.fragment)
		} else {
			compressed, err = r.compression.CompressClientFlight(pt.fragment)
		}
		if err != nil {
			return err
		}

		seq := cipher.combineSeq(false)
		length := len(compressed) + 1 + cipher.cipher.Overhead()
		contentType := RecordTypeApplicationData

		header := []byte{byte(contentType),
			byte(tls10Version >> 8), byte(tls10Version & 0xff),
			byte(length >> 8), byte(length)}

		ciphertext = r.cipher.cipher.Seal(nil, r.cipher.computeNonce(seq), compressed, header)
	} else {
		if r.server {
			ciphertext, err = r.compression.CompressServerHello(pt.fragment)
		} else {
			ciphertext, err = r.compression.CompressClientHello(pt.fragment)
		}
		if err != nil {
			return err
		}
	}

	logf(logTypeIO, "%s CompactRecordLayer.WriteRecord epoch=[%s] seq=[%x] [%d] ciphertext=[%x]", r.label, cipher.epoch.label(), cipher.seq, pt.contentType, ciphertext)

	cipher.incrementSequenceNumber()
	_, err = r.conn.Write(ciphertext)
	return err
}

type NoHandshakeCompression struct{}

func (c NoHandshakeCompression) CompressClientHello(ch []byte) ([]byte, error) {
	return ch, nil
}

func (c NoHandshakeCompression) CompressServerHello(sh []byte) ([]byte, error) {
	return sh, nil
}

func (c NoHandshakeCompression) CompressServerFlight(hms []byte) ([]byte, error) {
	return hms, nil
}

func (c NoHandshakeCompression) CompressClientFlight(hms []byte) ([]byte, error) {
	return hms, nil
}

func (c NoHandshakeCompression) readGenericHandshake(data []byte) ([]byte, int, error) {
	var hs struct {
		Type HandshakeType
		Body []byte `tls:"head=3"`
	}
	n, err := syntax.Unmarshal(data, &hs)
	if err != nil {
		return nil, 0, err
	}

	out := make([]byte, n)
	copy(out, data[:n])
	return out, n, nil
}

func (c NoHandshakeCompression) ReadClientHello(data []byte) ([]byte, int, error) {
	return c.readGenericHandshake(data)
}

func (c NoHandshakeCompression) ReadServerHello(data []byte) ([]byte, int, error) {
	return c.readGenericHandshake(data)
}

func (c NoHandshakeCompression) DecompressServerFlight(hms []byte) ([]byte, error) {
	return hms, nil
}

func (c NoHandshakeCompression) DecompressClientFlight(hms []byte) ([]byte, error) {
	return hms, nil
}
