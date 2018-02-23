package mint

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"runtime"
	"testing"
)

func unhex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}

func assertTrue(t *testing.T, test bool, msg string) {
	t.Helper()
	prefix := string("")
	for i := 1; ; i++ {
		_, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		prefix = fmt.Sprintf("%v: %d\n", file, line) + prefix
	}
	if !test {
		t.Fatalf(prefix + msg)
	}
}

func assertError(t *testing.T, err error, msg string) {
	t.Helper()
	assertTrue(t, err != nil, msg)
}

func assertNotError(t *testing.T, err error, msg string) {
	t.Helper()
	if err != nil {
		msg += ": " + err.Error()
	}
	assertTrue(t, err == nil, msg)
}

func assertNil(t *testing.T, x interface{}, msg string) {
	t.Helper()
	assertTrue(t, x == nil, msg)
}

func assertNotNil(t *testing.T, x interface{}, msg string) {
	t.Helper()
	assertTrue(t, x != nil, msg)
}

func assertEquals(t *testing.T, a, b interface{}) {
	t.Helper()
	assertTrue(t, a == b, fmt.Sprintf("%+v != %+v", a, b))
}

func assertByteEquals(t *testing.T, a, b []byte) {
	t.Helper()
	assertTrue(t, bytes.Equal(a, b), fmt.Sprintf("%+v != %+v", hex.EncodeToString(a), hex.EncodeToString(b)))
}

func assertNotByteEquals(t *testing.T, a, b []byte) {
	t.Helper()
	assertTrue(t, !bytes.Equal(a, b), fmt.Sprintf("%+v == %+v", hex.EncodeToString(a), hex.EncodeToString(b)))
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
	assertTrue(t, reflect.DeepEqual(a, b), fmt.Sprintf("%+v != %+v", a, b))
}

func assertSameType(t *testing.T, a, b interface{}) {
	t.Helper()
	A := reflect.TypeOf(a)
	B := reflect.TypeOf(b)
	assertTrue(t, A == B, fmt.Sprintf("%s != %s", A.Name(), B.Name()))
}

// Utilities for parametrized tests
// Represents the configuration for a given test instance.
type testInstanceState interface {
	set(string, string)
	get(string) string
}

// This complicated mixin stuff is in case we want to extend this to
// pass other parameters that aren't srings. Arguably YAGNI.
type testInstanceStateMixin struct {
	params map[string]string
}

func (m *testInstanceStateMixin) set(k string, v string) {
	m.params[k] = v
}

func (m *testInstanceStateMixin) get(k string) string {
	return m.params[k]
}

func newTestInstanceStateMixin() testInstanceStateMixin {
	return testInstanceStateMixin{make(map[string]string, 0)}
}

type testInstanceStateBase struct {
	testInstanceStateMixin
}

func newTestInstanceStateBase() testInstanceState {
	return &testInstanceStateBase{newTestInstanceStateMixin()}
}

// Helper function.
func runParametrizedInner(t *testing.T, name string, state testInstanceState, inparams []testParameter, f parametrizedTest) {
	next := inparams[1:]

	param := inparams[0]
	for _, p := range param.vals {
		state.set(param.name, p)
		var n string
		if len(name) > 0 {
			n = name + "/"
		}
		n = n + param.name + "=" + p

		if len(next) == 0 {
			t.Run(n, func(t *testing.T) {
				f(t, n, state)
			})
			continue
		}
		runParametrizedInner(t, n, state, next, f)
	}
}

// Nominally public API.
type testParameter struct {
	name string
	vals []string
}

type parametrizedTest func(t *testing.T, name string, p testInstanceState)

// This is the function you call.
func runParametrizedTest(t *testing.T, inparams []testParameter, f parametrizedTest) {
	runParametrizedInner(t, "", newTestInstanceStateBase(), inparams, f)
}
