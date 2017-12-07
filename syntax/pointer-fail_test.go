package syntax

import (
	"testing"
)

// TODO(rlb@ipv.sx): This module does not currently support
// marshal/unmarshal of structs with embedded pointer types.  (By
// contrast, encoding/json will dereference on marshal / allocate on
// unmarshal.)  These tests just demonstrate that failure.  They can
// be removed once pointer support is added.

type InnerStruct struct {
	A uint8
}

type WithValue struct {
	Inner InnerStruct
}

type WithPointer struct {
	Inner *InnerStruct
}

func TestPtrEncodeFailure(t *testing.T) {
	inner := InnerStruct{0xFF}
	withValue := WithValue{inner}
	withPointer := WithPointer{&inner}

	_, err := Marshal(withValue)
	if err != nil {
		t.Fatalf("Marshal with value should have succeeded: [%v]", err)
	}

	_, err = Marshal(withPointer)
	if err == nil {
		t.Fatalf("Marshal with pointer should have failed: [%v]", err)
	}
}

func TestPtrDecodeFailure(t *testing.T) {
	data := []byte{0xFF}
	var withValue WithValue
	var withPointer WithPointer

	_, err := Unmarshal(data, &withValue)
	if err != nil {
		t.Fatalf("Unmarshal with value should have succeeded: [%v]", err)
	}

	_, err = Unmarshal(data, &withPointer)
	if err == nil {
		t.Fatalf("Unmarshal with pointer should have failed: [%v]", err)
	}
}
