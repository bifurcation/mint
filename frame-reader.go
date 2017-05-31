// Read a generic "framed" packet consisting of a header and a
// This is used for both TLS Records and TLS Handshake Messages
package mint

import (
	"fmt"
	"io"
)

type frameDetails interface {
	headerLen() int
	defaultReadLen() int
	frameLen(hdr []byte) (int, error)
}

const (
	kFrameReaderHdr  = 0
	kFrameReaderBody = 1
)

var frameReaderWouldBlock = fmt.Errorf("Would have blocked")

type frameNextAction func(f *frameReader) error

type frameReader struct {
	conn        io.Reader
	details     frameDetails
	state       uint8
	hdr         []byte
	body        []byte
	working     []byte
	writeOffset int
	remainder   []byte
}

func newFrameReader(r io.Reader, d frameDetails) *frameReader {
	hdr := make([]byte, d.headerLen())
	return &frameReader{
		r,
		d,
		kFrameReaderHdr,
		hdr,
		nil,
		hdr,
		0,
		nil,
	}
}

func dup(a []byte) []byte {
	r := make([]byte, len(a))
	copy(r, a)
	return r
}

func (f *frameReader) needed() int {
	tmp := (len(f.working) - f.writeOffset) - len(f.remainder)
	if tmp < 0 {
		return 0
	}
	return tmp
}

func (f *frameReader) readChunk() (hdr []byte, body []byte, err error) {
	var buf []byte

	// Loop until one of three things happens:
	//
	// 1. We process a record
	// 2. We try to read off the socket and get nothing, in which case
	//    return frameReaderWouldBlock
	// 3. We get an error.
	//
	err = frameReaderWouldBlock
	for err != nil {
		if f.needed() > 0 {
			logf(logTypeFrameReader, "Reading from input needed=%v", f.needed())
			buf = make([]byte, f.details.defaultReadLen())
			n, err := f.conn.Read(buf)
			if err != nil {
				logf(logTypeFrameReader, "Error reading, %v", err)
				return nil, nil, err
			}
			// OK, we know the socket is empty, so return frameReaderWouldBlock
			if n == 0 {
				return nil, nil, frameReaderWouldBlock
			}

			logf(logTypeFrameReader, "Read %v bytes", n)
			if n > 0 {
				buf = buf[:n]
				f.addChunk(buf)
			}
		}

		// See if we're ready.
		hdr, body, err = f.process()
		if err != nil && err != frameReaderWouldBlock {
			return nil, nil, err
		}
	}

	// We finally have a frame
	return hdr, body, nil
}

func (f *frameReader) addChunk(in []byte) {
	// Append to the buffer.
	logf(logTypeFrameReader, "Appending %v", len(in))
	f.remainder = append(f.remainder, in...)
}

func (f *frameReader) process() (hdr []byte, body []byte, err error) {
	for f.needed() == 0 {
		logf(logTypeFrameReader, "%v bytes needed for next block", len(f.working)-f.writeOffset)
		// Fill out our working block
		copied := copy(f.working[f.writeOffset:], f.remainder)
		f.remainder = f.remainder[copied:]
		f.writeOffset += copied
		if f.writeOffset < len(f.working) {
			logf(logTypeFrameReader, "Read would have blocked 1")
			return nil, nil, frameReaderWouldBlock
		}
		// Reset the write offset, because we are now full.
		f.writeOffset = 0

		// We have read a full frame
		if f.state == kFrameReaderBody {
			logf(logTypeFrameReader, "Returning frame hdr=%h len=%d buffered=%d", f.hdr, len(f.body), len(f.remainder))
			f.state = kFrameReaderHdr
			f.working = f.hdr
			return dup(f.hdr), dup(f.body), nil
		}

		// We have read the header
		bodyLen, err := f.details.frameLen(f.hdr)
		if err != nil {
			return nil, nil, err
		}
		logf(logTypeFrameReader, "Processed header, body len = %v", bodyLen)

		f.body = make([]byte, bodyLen)
		f.working = f.body
		f.writeOffset = 0
		f.state = kFrameReaderBody
	}

	logf(logTypeFrameReader, "Read would have blocked 2")
	return nil, nil, frameReaderWouldBlock
}
