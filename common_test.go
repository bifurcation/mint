package mint

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

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
		assert(t, false, fmt.Sprintf("%v != %v", a, b))
	}
}

func assertByteEquals(t *testing.T, a []byte, b []byte) {
	if !bytes.Equal(a, b) {
		assert(t, false, fmt.Sprintf("%v != %v", hex.EncodeToString(a), hex.EncodeToString(b)))
	}
}

func assertNotByteEquals(t *testing.T, a []byte, b []byte) {
	if bytes.Equal(a, b) {
		assert(t, false, fmt.Sprintf("%v == %v", hex.EncodeToString(a), hex.EncodeToString(b)))
	}
}

func assertDeepEquals(t *testing.T, a interface{}, b interface{}) {
	if !reflect.DeepEqual(a, b) {
		assert(t, false, fmt.Sprintf("%+v != %+v", a, b))
	}
}

type errorReadWriter struct{}

func (e errorReadWriter) Read(p []byte) (n int, err error) {
	return 0, fmt.Errorf("Unknown read error")
}

func (e errorReadWriter) Write(p []byte) (n int, err error) {
	return 0, fmt.Errorf("Unknown write error")
}
