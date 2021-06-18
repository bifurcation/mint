// Read a generic "framed" packet consisting of a header and a
// This is used for both TLS Records and TLS Handshake Messages
package mint

type framing interface {
	parse(buffer []byte) (headerReady bool, headerLen, bodyLen int)
}

type lastNBytesFraming struct {
	headerSize int
	lengthSize int
}

func (lnb lastNBytesFraming) parse(buffer []byte) (headerReady bool, headerLen, bodyLen int) {
	headerReady = len(buffer) >= lnb.headerSize
	if !headerReady {
		return
	}

	headerLen = lnb.headerSize
	val, _ := decodeUint(buffer[lnb.headerSize-lnb.lengthSize:], lnb.lengthSize)
	bodyLen = int(val)
	return
}

type frameReader struct {
	details   framing
	remainder []byte
}

func newFrameReader(d framing) *frameReader {
	return &frameReader{
		details:   d,
		remainder: make([]byte, 0),
	}
}

func (f *frameReader) ready() bool {
	headerReady, headerLen, bodyLen := f.details.parse(f.remainder)
	//logf(logTypeFrameReader, "header=%v body=(%v > %v)", headerReady, len(f.remainder), headerLen+bodyLen)
	return headerReady && len(f.remainder) >= headerLen+bodyLen
}

func (f *frameReader) addChunk(in []byte) {
	// Append to the buffer
	logf(logTypeFrameReader, "Appending %v", len(in))
	f.remainder = append(f.remainder, in...)
}

func (f *frameReader) next() ([]byte, []byte, error) {
	// Check to see if we have enough data
	headerReady, headerLen, bodyLen := f.details.parse(f.remainder)
	if !headerReady || len(f.remainder) < headerLen+bodyLen {
		logf(logTypeVerbose, "Read would have blocked")
		return nil, nil, AlertWouldBlock
	}

	// Read a record off the front of the buffer
	header, body := make([]byte, headerLen), make([]byte, bodyLen)
	copy(header, f.remainder[:headerLen])
	copy(body, f.remainder[headerLen:headerLen+bodyLen])
	f.remainder = f.remainder[headerLen+bodyLen:]
	return header, body, nil
}
