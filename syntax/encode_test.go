package syntax

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

type CrypticString string

var (
	crypticStringMarshalCalls   = 0
	crypticStringUnmarshalCalls = 0
)

// A CrypticString marshalls as one length octet followed by the
// UTF-8 bytes of the string, XOR'ed with an increasing sequence
// starting with the length plus one (L+1, L+2, ...).
func (cs CrypticString) MarshalTLS() ([]byte, error) {
	crypticStringMarshalCalls += 1

	l := byte(len(cs))
	b := []byte(cs)
	for i := range b {
		b[i] ^= l + byte(i) + 1
	}
	return append([]byte{l}, b...), nil
}

func (cs *CrypticString) UnmarshalTLS(data []byte) (int, error) {
	crypticStringUnmarshalCalls += 1

	if len(data) == 0 {
		return 0, fmt.Errorf("Length of CrypticString must be at least 1")
	}

	l := data[0]
	if len(data) < int(l)+1 {
		return 0, fmt.Errorf("TLS data not long enough for CrypticString")
	}

	b := data[1 : l+1]
	for i := range b {
		b[i] ^= l + byte(i) + 1
	}

	*cs = CrypticString(string(b))

	return int(l + 1), nil
}

// Test cases to use for encode and decode
var (
	x8 uint8 = 0xA0
	z8       = []byte{0xA0}

	x16    uint16 = 0xB0A0
	z16, _        = hex.DecodeString("B0A0")

	x32    uint32 = 0xD0C0B0A0
	z32, _        = hex.DecodeString("D0C0B0A0")

	x64    uint64 = 0xD0C0B0A090807060
	z64, _        = hex.DecodeString("D0C0B0A090807060")

	xa    = [5]uint16{0x1111, 0x2222, 0x3333, 0x4444, 0x5555}
	za, _ = hex.DecodeString("11112222333344445555")

	xv20 = struct {
		V []byte `tls:"head=1"`
	}{V: bytes.Repeat([]byte{0xA0}, 0x20)}
	zv20, _ = hex.DecodeString("20" + strings.Repeat("A0", 0x20))

	xv200 = struct {
		V []byte `tls:"head=2"`
	}{V: bytes.Repeat([]byte{0xA0}, 0x200)}
	zv200, _ = hex.DecodeString("0200" + strings.Repeat("A0", 0x200))

	xv20000 = struct {
		V []byte `tls:"head=3"`
	}{V: bytes.Repeat([]byte{0xA0}, 0x20000)}
	zv20000, _ = hex.DecodeString("020000" + strings.Repeat("A0", 0x20000))

	xvENohead = struct {
		V []byte
	}{V: xv20.V}

	xvEhead = struct {
		V []byte `tls:"head=1"`
	}{V: bytes.Repeat([]byte{0xA0}, 0x100)}

	xvEmax = struct {
		V []byte `tls:"head=1,max=31"`
	}{V: xv20.V}

	xvEmin = struct {
		V []byte `tls:"head=1,min=33"`
	}{V: xv20.V}

	xs1 = struct {
		A uint16
		B []uint8 `tls:"head=2"`
		C [4]uint32
	}{
		A: 0xB0A0,
		B: []uint8{0xA0, 0xA1, 0xA2, 0xA3, 0xA4},
		C: [4]uint32{0x10111213, 0x20212223, 0x30313233, 0x40414243},
	}
	zs1, _ = hex.DecodeString("B0A0" + "0005A0A1A2A3A4" + "10111213202122233031323340414243")

	xm    = CrypticString("hello")
	zm, _ = hex.DecodeString("056e62646565")

	xsm = struct {
		A CrypticString
		B uint16
		C CrypticString
	}{
		A: CrypticString("hello"),
		B: x16,
		C: CrypticString("... world!"),
	}
	zsm, _ = hex.DecodeString("056e62646565" + "B0A0" + "0a2522232e787f637e7735")

	xsp = struct {
		A uint16
		B *CrypticString
	}{
		A: x16,
		B: &xm,
	}
	zsp, _ = hex.DecodeString("B0A0" + "056e62646565")
)

func TestEncodeInvalidCases(t *testing.T) {
	x := struct {
		Strings []string
	}{Strings: []string{"asdf"}}
	_, err := Marshal(x)
	if err == nil {
		t.Fatalf("Agreed to marshal an unsupported type")
	}
}

func TestEncodeBasicTypes(t *testing.T) {
	y8, err := Marshal(x8)
	if err != nil || !bytes.Equal(y8, z8) {
		t.Fatalf("uint8 encode failed [%v] [%x]", err, y8)
	}

	y16, err := Marshal(x16)
	if err != nil || !bytes.Equal(y16, z16) {
		t.Fatalf("uint8 encode failed [%v] [%x]", err, y16)
	}

	y32, err := Marshal(x32)
	if err != nil || !bytes.Equal(y32, z32) {
		t.Fatalf("uint8 encode failed [%v] [%x]", err, y32)
	}

	y64, err := Marshal(x64)
	if err != nil || !bytes.Equal(y64, z64) {
		t.Fatalf("uint8 encode failed [%v] [%x]", err, y64)
	}
}

func TestEncodeArray(t *testing.T) {
	ya, err := Marshal(xa)
	if err != nil || !bytes.Equal(ya, za) {
		t.Fatalf("[5]uint8 encode failed [%v] [%x]", err, ya)
	}
}

func TestEncodeSlice(t *testing.T) {
	yv20, err := Marshal(xv20)
	if err != nil || !bytes.Equal(yv20, zv20) {
		t.Fatalf("[0x20]uint8 encode failed [%v] [%x]", err, yv20)
	}

	yv200, err := Marshal(xv200)
	if err != nil || !bytes.Equal(yv200, zv200) {
		t.Fatalf("[0x200]uint8 encode failed [%v] [%x]", err, yv200)
	}

	yv20000, err := Marshal(xv20000)
	if err != nil || !bytes.Equal(yv20000, zv20000) {
		t.Fatalf("[0x20000]uint8 encode failed [%v] [%x]", err, yv20000)
	}

	yE, err := Marshal(xvENohead)
	if err == nil {
		t.Fatalf("Allowed marshal with no header size [%x]", yE)
	}

	yE, err = Marshal(xvEhead)
	if err == nil {
		t.Fatalf("Allowed marshal exceeding header size [%x]", yE)
	}

	yE, err = Marshal(xvEmax)
	if err == nil {
		t.Fatalf("Allowed marshal exceeding max [%x]", yE)
	}

	yE, err = Marshal(xvEmin)
	if err == nil {
		t.Fatalf("Allowed marshal below min [%x]", yE)
	}
}

func TestEncodeStruct(t *testing.T) {
	ys1, err := Marshal(xs1)
	if err != nil || !bytes.Equal(ys1, zs1) {
		t.Fatalf("struct encode failed [%v] [%x]", err, ys1)
	}
}

func TestEncodeMarshaler(t *testing.T) {
	crypticStringMarshalCalls = 0
	ym, err := Marshal(xm)

	if err != nil || !bytes.Equal(ym, zm) {
		t.Fatalf("Marshaler encode failed [%v] [%x]", err, ym)
	}

	if crypticStringMarshalCalls != 1 {
		t.Fatalf("MarshalTLS() was not called exactly once [%v]", crypticStringMarshalCalls)
	}

	crypticStringMarshalCalls = 0
	ysm, err := Marshal(xsm)

	if err != nil || !bytes.Equal(ysm, zsm) {
		t.Fatalf("Struct-embedded marshaler encode failed [%v] [%x]", err, ysm)
	}

	if crypticStringMarshalCalls != 2 {
		t.Fatalf("MarshalTLS() was not called exactly twice [%v]", crypticStringMarshalCalls)
	}
}

func TestEncodeStructWithPointer(t *testing.T) {
	ysp, err := Marshal(xsp)
	if err != nil || !bytes.Equal(ysp, zsp) {
		t.Fatalf("struct encode failed [%v] [%x]", err, ysp)
	}
}
