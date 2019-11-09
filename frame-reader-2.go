// Read a generic "framed" packet consisting of a header and a
// This is used for both TLS Records and TLS Handshake Messages
package mint

type framing2 interface {
	parse(buffer []byte) (headerReady bool, headerLen, bodyLen int)
}

type frameReader2 struct {
	details   framing2
	remainder []byte
}

func newFrameReader2(d framing2) *frameReader2 {
	return &frameReader2{
		details:   d,
		remainder: make([]byte, 0),
	}
}

func (f *frameReader2) ready() bool {
	headerReady, headerLen, bodyLen := f.details.parse(f.remainder)
	return headerReady && len(f.remainder) >= headerLen+bodyLen
}

func (f *frameReader2) addChunk(in []byte) {
	// Append to the buffer
	logf(logTypeFrameReader, "Appending %v", len(in))
	f.remainder = append(f.remainder, in...)
}

func (f *frameReader2) next() ([]byte, []byte, error) {
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
