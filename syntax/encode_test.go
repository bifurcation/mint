package syntax

import (
	"strings"
	"testing"
)

func TestEncodeErrors(t *testing.T) {
	errorCases := map[string]interface{}{
		"unsupported": float64(0),

		"varint-too-big": struct {
			V uint64 `tls:"varint"`
		}{V: uint64(1) << 63},

		"no-head": struct {
			V []byte
		}{V: buffer(0x20)},

		"head-too-short": struct {
			V []byte `tls:"head=1"`
		}{V: buffer(0x100)},

		"overflow": struct {
			V []byte `tls:"head=1,max=31"`
		}{V: buffer(0x20)},

		"underflow": struct {
			V []byte `tls:"head=1,min=33"`
		}{V: buffer(0x20)},

		"nil": struct{ V *uint8 }{V: nil},

		"invalid-head-tag": struct {
			V int `tls:"head=2"`
		}{V: 0},

		"invalid-varint-tag": struct {
			V struct{} `tls:"varint"`
		}{V: struct{}{}},

		"invalid-optional-tag": struct {
			V int `tls:"optional"`
		}{V: 0},

		"invalid-validator": CrypticString(strings.Repeat("A", 257)),
	}

	for label, badValue := range errorCases {
		encoded, err := Marshal(badValue)
		t.Logf("[%s] -> [%v]", label, err)
		if err == nil {
			t.Fatalf("Incorrectly allowed marshal [%s]: [%x]", label, encoded)
		}
	}
}
