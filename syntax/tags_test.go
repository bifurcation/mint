package syntax

import (
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
