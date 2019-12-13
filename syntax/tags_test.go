package syntax

import (
	"reflect"
	"testing"
)

func TestTagParsing(t *testing.T) {
	opts := parseTag("=x,head=2,min=3,max=60000,unknown,varint,optional")
	if len(opts) != 5 {
		t.Fatalf("Failed to parse all fields")
	}
	if opts["head"] != 2 || opts["min"] != 3 || opts["max"] != 60000 || opts[varintOption] != 1 || opts[optionalOption] != 1 {
		t.Fatalf("Parsed fields incorrectly")
	}
}

func TestTagValidity(t *testing.T) {
	sliceTags := parseTag("head=2")
	uintTags := parseTag("varint")
	ptrTags := parseTag("optional")

	sliceType := reflect.TypeOf([]byte{})
	uintType := reflect.TypeOf(uint8(0))
	ptrType := reflect.TypeOf(new(uint8))

	if !tagsValidForType(sliceTags, sliceType) {
		t.Fatalf("Rejected valid tags for slice")
	}

	if !tagsValidForType(uintTags, uintType) {
		t.Fatalf("Rejected valid tags for uint")
	}

	if !tagsValidForType(ptrTags, ptrType) {
		t.Fatalf("Rejected valid tags for ptr")
	}

	if tagsValidForType(uintTags, sliceType) {
		t.Fatalf("Accepted invalid tags for slice: %v", uintTags)
	}

	if tagsValidForType(ptrTags, uintType) {
		t.Fatalf("Accepted invalid tags for uint: %v", ptrTags)
	}

	if tagsValidForType(sliceTags, ptrType) {
		t.Fatalf("Accepted invalid tags for ptr: %v", sliceTags)
	}
}
