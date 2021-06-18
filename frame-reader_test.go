package mint

import (
	"strings"
	"testing"

	"github.com/bifurcation/mint/syntax"
)

var (
	fixedFullFrame     = unhex("ff00056162636465")
	fixedEmptyFrame    = unhex("ff0000")
	variableFullFrame  = unhex("40ff" + strings.Repeat("A0", 255))
	variableEmptyFrame = unhex("00")
)

type variableHeader struct{}

func (h variableHeader) parse(buffer []byte) (headerReady bool, headerLen, bodyLen int) {
	if len(buffer) == 0 {
		headerReady = false
		return
	}

	// XXX: Need a way to return parse errors other than "insufficient data"
	length := struct {
		Value uint64 `tls:"varint"`
	}{}
	read, err := syntax.Unmarshal(buffer, &length)

	headerReady = (err == nil)
	if !headerReady {
		return
	}

	headerLen = read
	bodyLen = int(length.Value)
	return
}

type frameReaderTester struct {
	details        framing
	headerLenFull  int
	fullFrame      []byte
	headerLenEmpty int
	emptyFrame     []byte
}

func (frt frameReaderTester) checkFrameFull(t *testing.T, hdr, body []byte) {
	assertByteEquals(t, hdr, frt.fullFrame[:frt.headerLenFull])
	assertByteEquals(t, body, frt.fullFrame[frt.headerLenFull:])
}

func (frt frameReaderTester) checkFrameEmpty(t *testing.T, hdr, body []byte) {
	assertByteEquals(t, hdr, frt.emptyFrame[:frt.headerLenEmpty])
	assertByteEquals(t, body, frt.emptyFrame[frt.headerLenEmpty:])
}

func (frt frameReaderTester) TestFrames(t *testing.T) {
	r := newFrameReader(frt.details)
	r.addChunk(frt.fullFrame)
	hdr, body, err := r.next()
	assertNotError(t, err, "Couldn't read frame 1")
	frt.checkFrameFull(t, hdr, body)

	r.addChunk(frt.emptyFrame)
	hdr, body, err = r.next()
	assertNotError(t, err, "Couldn't read frame 2")
	frt.checkFrameEmpty(t, hdr, body)
}

func (frt frameReaderTester) TestTwoFrames(t *testing.T) {
	r := newFrameReader(frt.details)
	r.addChunk(frt.fullFrame)
	r.addChunk(frt.fullFrame)
	hdr, body, err := r.next()
	assertNotError(t, err, "Couldn't read frame 1")
	frt.checkFrameFull(t, hdr, body)

	hdr, body, err = r.next()
	assertNotError(t, err, "Couldn't read frame 2")
	frt.checkFrameFull(t, hdr, body)
}

func (frt frameReaderTester) TestTrickle(t *testing.T) {
	r := newFrameReader(frt.details)

	var hdr, body []byte
	var err error
	for i := 0; i <= len(frt.fullFrame); i += 1 {
		hdr, body, err = r.next()
		if i < len(frt.fullFrame) {
			assertEquals(t, err, AlertWouldBlock)
			assertEquals(t, 0, len(hdr))
			assertEquals(t, 0, len(body))
			r.addChunk(frt.fullFrame[i : i+1])
		}
	}
	assertNil(t, err, "Error reading")
	frt.checkFrameFull(t, hdr, body)
}

func (frt frameReaderTester) Run(t *testing.T) {
	t.Run("frames", frt.TestFrames)
	t.Run("two-frames", frt.TestTwoFrames)
	t.Run("trickle", frt.TestTrickle)
}

func TestFrameReader(t *testing.T) {
	cases := map[string]frameReaderTester{
		"fixed": frameReaderTester{
			lastNBytesFraming{3, 2},
			3, fixedFullFrame,
			3, fixedEmptyFrame,
		},
		"variable": frameReaderTester{
			variableHeader{},
			2, variableFullFrame,
			1, variableEmptyFrame,
		},
	}

	for label, c := range cases {
		t.Run(label, c.Run)
	}
}
