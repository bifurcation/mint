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

func assertNil(t *testing.T, x interface{}, msg string) {
	assert(t, x == nil, msg)
}

func assertNotNil(t *testing.T, x interface{}, msg string) {
	assert(t, x != nil, msg)
}

func assertEquals(t *testing.T, a, b interface{}) {
	assert(t, a == b, fmt.Sprintf("%+v != %+v", a, b))
}

func assertByteEquals(t *testing.T, a, b []byte) {
	assert(t, bytes.Equal(a, b), fmt.Sprintf("%+v != %+v", hex.EncodeToString(a), hex.EncodeToString(b)))
}

func assertNotByteEquals(t *testing.T, a, b []byte) {
	assert(t, !bytes.Equal(a, b), fmt.Sprintf("%+v == %+v", hex.EncodeToString(a), hex.EncodeToString(b)))
}

func assertCipherSuiteParamsEquals(t *testing.T, a, b cipherSuiteParams) {
	assertEquals(t, a.suite, b.suite)
	// Can't compare aeadFactory values
	assertEquals(t, a.hash, b.hash)
	assertEquals(t, a.keyLen, b.keyLen)
	assertEquals(t, a.ivLen, b.ivLen)
}

func assertDeepEquals(t *testing.T, a, b interface{}) {
	assert(t, reflect.DeepEqual(a, b), fmt.Sprintf("%+v != %+v", a, b))
}

func assertSameType(t *testing.T, a, b interface{}) {
	A := reflect.TypeOf(a)
	B := reflect.TypeOf(b)
	assert(t, A == B, fmt.Sprintf("%s != %s", A.Name(), B.Name()))
}
