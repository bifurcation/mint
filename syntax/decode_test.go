package syntax

import (
	"reflect"
	"testing"
)

func TestDecodeUnsupported(t *testing.T) {
	dummyBuffer := []byte(nil)

	var yi int
	read, err := Unmarshal(dummyBuffer, yi)
	if err == nil || read != 0 {
		t.Fatalf("Agreed to unmarshal to a non-pointer")
	}

	read, err = Unmarshal(dummyBuffer, nil)
	if err == nil || read != 0 {
		t.Fatalf("Agreed to unmarshal to a nil pointer")
	}
}

func TestDecodeErrors(t *testing.T) {
	vector0x20 := append([]byte{0x20}, buffer(0x20)...)
	errorCases := map[string]struct {
		template interface{}
		encoding []byte
	}{
		"unsupported": {
			template: float64(0),
			encoding: buffer(0),
		},

		"uint-too-small": {
			template: uint32(0),
			encoding: unhex("7fff"),
		},

		"varint-too-big": {
			template: struct {
				V uint8 `tls:"varint"`
			}{},
			encoding: unhex("7fff"),
		},

		// Slice errors
		"no-head": {
			template: struct{ V []byte }{},
			encoding: buffer(0),
		},

		"overflow": {
			template: struct {
				V []byte `tls:"head=1,max=31"`
			}{},
			encoding: vector0x20,
		},

		"overflow-no-head": {
			template: struct {
				V []byte `tls:"head=none,max=31"`
			}{},
			encoding: buffer(32),
		},

		"underflow": {
			template: struct {
				V []byte `tls:"head=1,min=33"`
			}{},
			encoding: vector0x20,
		},

		"underflow-no-head": {
			template: struct {
				V []byte `tls:"head=none,min=33"`
			}{},
			encoding: buffer(32),
		},

		"too-short-for-head": {
			template: struct {
				V []byte `tls:"head=3"`
			}{},
			encoding: vector0x20[:2],
		},

		"too-short-for-value": {
			template: struct {
				V []byte `tls:"head=3"`
			}{},
			encoding: vector0x20,
		},

		"too-short-for-varint-head-length": {
			template: struct {
				V []byte `tls:"head=varint"`
			}{},
			encoding: vector0x20[:0],
		},

		"too-short-for-varint-head": {
			template: struct {
				V []byte `tls:"head=varint"`
			}{},
			encoding: unhex("40"),
		},

		"invalid-head-tag": {
			template: struct {
				V int `tls:"head=2"`
			}{V: 0},
			encoding: unhex(""),
		},

		"invalid-varint-tag": {
			template: struct {
				V struct{} `tls:"varint"`
			}{V: struct{}{}},
			encoding: unhex(""),
		},

		"invalid-optional-tag": {
			template: struct {
				V int `tls:"optional"`
			}{V: 0},
			encoding: unhex(""),
		},

		// Optional errors
		"invalid-optional-flag": {
			template: struct {
				V *uint8 `tls:"optional"`
			}{},
			encoding: unhex("0203"),
		},

		// Validator errors
		"invalid-validator": {
			template: CrypticString(""),
			encoding: unhex("056069677b6e"),
		},
	}

	for label, testCase := range errorCases {
		decodedPointer := reflect.New(reflect.TypeOf(testCase.template))
		read, err := Unmarshal(testCase.encoding, decodedPointer.Interface())
		t.Logf("[%s] -> [%v]", label, err)
		if err == nil || read > 0 {
			t.Fatalf("Incorrectly allowed unmarshal [%s]: %v", label, err)
		}
	}
}
