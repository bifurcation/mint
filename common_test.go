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
	t.Helper()
	if !test {
		t.Fatalf(msg)
	}
}

func assertError(t *testing.T, err error, msg string) {
	t.Helper()
	assert(t, err != nil, msg)
}

func assertNotError(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		msg += ": " + err.Error()
	}
	assert(t, err == nil, msg)
}

func assertNil(t *testing.T, x interface{}, msg string) {
	t.Helper()
	assert(t, x == nil, msg)
}

func assertNotNil(t *testing.T, x interface{}, msg string) {
	t.Helper()
	assert(t, x != nil, msg)
}

func assertEquals(t *testing.T, a, b interface{}) {
	t.Helper()
	assert(t, a == b, fmt.Sprintf("%+v != %+v", a, b))
}

func assertByteEquals(t *testing.T, a, b []byte) {
	t.Helper()
	assert(t, bytes.Equal(a, b), fmt.Sprintf("%+v != %+v", hex.EncodeToString(a), hex.EncodeToString(b)))
}

func assertNotByteEquals(t *testing.T, a, b []byte) {
	t.Helper()
	assert(t, !bytes.Equal(a, b), fmt.Sprintf("%+v == %+v", hex.EncodeToString(a), hex.EncodeToString(b)))
}

func assertCipherSuiteParamsEquals(t *testing.T, a, b CipherSuiteParams) {
	t.Helper()
	assertEquals(t, a.Suite, b.Suite)
	// Can't compare aeadFactory values
	assertEquals(t, a.Hash, b.Hash)
	assertEquals(t, a.KeyLen, b.KeyLen)
	assertEquals(t, a.IvLen, b.IvLen)
}

func assertDeepEquals(t *testing.T, a, b interface{}) {
	t.Helper()
	assert(t, reflect.DeepEqual(a, b), fmt.Sprintf("%+v != %+v", a, b))
}

func assertSameType(t *testing.T, a, b interface{}) {
	t.Helper()
	A := reflect.TypeOf(a)
	B := reflect.TypeOf(b)
	assert(t, A == B, fmt.Sprintf("%s != %s", A.Name(), B.Name()))
}
