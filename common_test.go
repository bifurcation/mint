package mint

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

func unhex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func assert(t *testing.T, test bool, msg string) {
	if !test {
		t.Fatalf(msg)
	}
}

func assertError(t *testing.T, err error, msg string) {
	assert(t, err != nil, msg)
}

func assertNotError(t *testing.T, err error, msg string) {
	if err != nil {
		msg += ": " + err.Error()
	}
	assert(t, err == nil, msg)
}

func assertNotNil(t *testing.T, x interface{}, msg string) {
	assert(t, x != nil, msg)
}

func assertEquals(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		assert(t, false, fmt.Sprintf("%+v != %+v", a, b))
	}
}

func assertByteEquals(t *testing.T, a []byte, b []byte) {
	if !bytes.Equal(a, b) {
		assert(t, false, fmt.Sprintf("%+v != %+v", hex.EncodeToString(a), hex.EncodeToString(b)))
	}
}

func assertNotByteEquals(t *testing.T, a []byte, b []byte) {
	if bytes.Equal(a, b) {
		assert(t, false, fmt.Sprintf("%+v == %+v", hex.EncodeToString(a), hex.EncodeToString(b)))
	}
}

func assertDeepEquals(t *testing.T, a interface{}, b interface{}) {
	if !reflect.DeepEqual(a, b) {
		assert(t, false, fmt.Sprintf("%+v != %+v", a, b))
	}
}
