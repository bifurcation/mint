package syntax

import (
	"reflect"
	"strconv"
	"strings"
)

// `tls:"head=2,min=2,max=255,varint"`

type tagOptions map[string]uint

var (
	varintOption   = "varint"
	optionalOption = "optional"
	omitOption     = "omit"

	headOptionNone   = "none"
	headOptionVarint = "varint"
	headValueNoHead  = uint(255)
	headValueVarint  = uint(254)

	optionalFlagAbsent  uint8 = 0
	optionalFlagPresent uint8 = 1
)

// parseTag parses a struct field's "tls" tag as a comma-separated list of
// name=value pairs, where the values MUST be unsigned integers, or in
// the special case of head, "none" or "varint"
func parseTag(tag string) tagOptions {
	opts := tagOptions{}
	for _, token := range strings.Split(tag, ",") {
		if token == varintOption {
			opts[varintOption] = 1
			continue
		} else if token == optionalOption {
			opts[optionalOption] = 1
			continue
		} else if token == omitOption {
			opts[omitOption] = 1
			continue
		}

		parts := strings.Split(token, "=")
		if len(parts[0]) == 0 {
			continue
		}

		if len(parts) == 1 {
			continue
		}

		if parts[0] == "head" && parts[1] == headOptionNone {
			opts[parts[0]] = headValueNoHead
		} else if parts[0] == "head" && parts[1] == headOptionVarint {
			opts[parts[0]] = headValueVarint
		} else if val, err := strconv.Atoi(parts[1]); err == nil && val >= 0 {
			opts[parts[0]] = uint(val)
		}
	}
	return opts
}

func tagsValidForType(opts tagOptions, t reflect.Type) bool {
	for tag := range opts {
		switch tag {
		case "head", "min", "max":
			// head, min, and max are only valid for slices
			if t.Kind() != reflect.Slice {
				return false
			}

		case "varint":
			// varint is only valid for integers
			switch t.Kind() {
			case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			default:
				return false
			}

		case "optional":
			// optional is only valid for pointers
			if t.Kind() != reflect.Ptr {
				return false
			}
		}
	}
	return true
}
