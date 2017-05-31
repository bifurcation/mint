package mint

import (
	"bytes"
	"io"
	"testing"
)

var kTestFrame = []byte{0x00, 0x05, 'a', 'b', 'c', 'd', 'e'}
var kTestEmptyFrame = []byte{0x00, 0x00}

// Wrapper around byteBuffer to turn EOF into nil for non-blocking.
type nbReader struct {
	r io.Reader
}

func (p *nbReader) Read(data []byte) (n int, err error) {
	n, err = p.r.Read(data)

	// Suppress bytes.Buffer's EOF on an empty buffer
	if err == io.EOF {
		n = 0
		err = nil
	}
	return n, err
}

type simpleHeader struct{}

func (h simpleHeader) headerLen() int {
	return 2
}

func (h simpleHeader) defaultReadLen() int {
	return 1024
}

func (h simpleHeader) frameLen(hdr []byte) (int, error) {
	if len(hdr) != 2 {
		panic("Assert!")
	}

	return (int(hdr[0]) << 8) | int(hdr[1]), nil
}

func checkFrame(t *testing.T, hdr []byte, body []byte) {
	assertByteEquals(t, hdr, kTestFrame[:2])
	assertByteEquals(t, body, kTestFrame[2:])
}

func TestFrameReaderFullFrame(t *testing.T) {
	b := bytes.NewBuffer(kTestFrame)
	r := newFrameReader(b, simpleHeader{})
	hdr, body, err := r.readChunk()
	assertNotError(t, err, "Couldn't read chunk")
	checkFrame(t, hdr, body)

	b.Write(kTestFrame)
	hdr, body, err = r.readChunk()
	assertNotError(t, err, "Couldn't read chunk")
	checkFrame(t, hdr, body)
}

func TestFrameReaderTwoFrames(t *testing.T) {
	b := bytes.NewBuffer(kTestFrame)
	b.Write(kTestFrame)

	r := newFrameReader(b, simpleHeader{})
	hdr, body, err := r.readChunk()
	assertNotError(t, err, "Couldn't read chunk")
	checkFrame(t, hdr, body)

	hdr, body, err = r.readChunk()
	assertNotError(t, err, "Couldn't read chunk")
	checkFrame(t, hdr, body)
}

func TestFrameReaderTrickle(t *testing.T) {
	b := bytes.NewBuffer(make([]byte, 0))
	nb := nbReader{b}
	r := newFrameReader(&nb, simpleHeader{})

	var hdr, body []byte
	var err error
	for i := 0; i <= len(kTestFrame); i += 1 {
		hdr, body, err = r.readChunk()
		if i < len(kTestFrame) {
			assertEquals(t, err, frameReaderWouldBlock)
			assertEquals(t, 0, len(hdr))
			assertEquals(t, 0, len(body))
			b.WriteByte(kTestFrame[i])
		}
	}
	assertNil(t, err, "Error reading")
	checkFrame(t, hdr, body)
}

func TestFrameReaderEmptyFrame(t *testing.T) {
	b := bytes.NewBuffer(kTestEmptyFrame)
	r := newFrameReader(b, simpleHeader{})
	_, _, err := r.readChunk()
	assertNotError(t, err, "Couldn't read chunk")
}

// Reader that delivers one chunk at a time, and EOF when
// empty.
type chunkReader struct {
	chunks [][]byte
}

func (p *chunkReader) Read(data []byte) (n int, err error) {
	if len(p.chunks) == 0 {
		return 0, io.EOF
	}
	n = copy(data, p.chunks[0])
	p.chunks[0] = p.chunks[0][n:]
	if len(p.chunks[0]) == 0 {
		p.chunks = p.chunks[1:]
	}
	return n, nil
}

func TestFrameReaderTwoPieces(t *testing.T) {
	cr := chunkReader{
		[][]byte{
			kTestFrame[:3],
			kTestFrame[3:],
		},
	}

	r := newFrameReader(&cr, simpleHeader{})
	hdr, body, err := r.readChunk()
	assertNotError(t, err, "Couldn't read chunk")
	checkFrame(t, hdr, body)
}
