package syntax

import (
	"reflect"
	"runtime"
	"testing"
)

func TestTagParsing(t *testing.T) {
	cases := []struct {
		encoded string
		opts    fieldOptions
	}{
		{
			encoded: "head=2,min=3,max=60000",
			opts: fieldOptions{
				headerSize: 2,
				minSize:    3,
				maxSize:    60000,
			},
		},
		{
			encoded: "head=varint,min=3,max=60000",
			opts: fieldOptions{
				varintHeader: true,
				minSize:      3,
				maxSize:      60000,
			},
		},
		{
			encoded: "head=none,min=3,max=60000",
			opts: fieldOptions{
				omitHeader: true,
				minSize:    3,
				maxSize:    60000,
			},
		},
		{
			encoded: "varint",
			opts:    fieldOptions{varint: true},
		},
		{
			encoded: "optional",
			opts:    fieldOptions{optional: true},
		},
		{
			encoded: "omit",
			opts:    fieldOptions{omit: true},
		},
	}

	for _, c := range cases {
		parsed := parseTag(c.encoded)
		if !reflect.DeepEqual(parsed, c.opts) {
			t.Fatalf("Incorrect options parsing: [%+v] != [%+v]", parsed, c.opts)
		}
	}
}

func TestTagConsistency(t *testing.T) {

	cases := []string{
		"head=3,head=none",
		"head=none,head=varint",
		"head=varint,head=3",
		"min=4,max=2",
		"head=3,varint",
		"varint,optional",
		"optional,head=3",
		"omit,varint",
	}

	tryToParse := func(opts string) (err error) {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(runtime.Error); ok {
					panic(r)
				}
				if s, ok := r.(string); ok {
					panic(s)
				}
				err = r.(error)
			}
		}()
		parseTag(opts)
		return nil
	}

	for _, opts := range cases {
		err := tryToParse(opts)
		if err == nil {
			t.Fatalf("Incorrectly allowed inconsistent options: [%s]", opts)
		}
	}
}

func TestTagValidity(t *testing.T) {
	sliceTags := parseTag("head=2")
	uintTags := parseTag("varint")
	ptrTags := parseTag("optional")

	sliceType := reflect.TypeOf([]byte{})
	uintType := reflect.TypeOf(uint8(0))
	ptrType := reflect.TypeOf(new(uint8))

	if !sliceTags.ValidForType(sliceType) {
		t.Fatalf("Rejected valid tags for slice")
	}

	if !uintTags.ValidForType(uintType) {
		t.Fatalf("Rejected valid tags for uint")
	}

	if !ptrTags.ValidForType(ptrType) {
		t.Fatalf("Rejected valid tags for ptr")
	}

	if uintTags.ValidForType(sliceType) {
		t.Fatalf("Accepted invalid tags for slice: %v", uintTags)
	}

	if ptrTags.ValidForType(uintType) {
		t.Fatalf("Accepted invalid tags for uint: %v", ptrTags)
	}

	if sliceTags.ValidForType(ptrType) {
		t.Fatalf("Accepted invalid tags for ptr: %v", sliceTags)
	}
}
