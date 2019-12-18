package syntax

import (
	"bytes"
	"fmt"
	"reflect"
	"runtime"
)

func Marshal(v interface{}) ([]byte, error) {
	e := &encodeState{}
	err := e.marshal(v, fieldOptions{})
	if err != nil {
		return nil, err
	}
	return e.Bytes(), nil
}

// Marshaler is the interface implemented by types that
// have a defined TLS encoding.
type Marshaler interface {
	MarshalTLS() ([]byte, error)
}

type encodeState struct {
	bytes.Buffer
}

func (e *encodeState) marshal(v interface{}, opts fieldOptions) (err error) {
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
	e.reflectValue(reflect.ValueOf(v), opts)
	return nil
}

func (e *encodeState) reflectValue(v reflect.Value, opts fieldOptions) {
	valueEncoder(v)(e, v, opts)
}

type encoderFunc func(e *encodeState, v reflect.Value, opts fieldOptions)

func valueEncoder(v reflect.Value) encoderFunc {
	if !v.IsValid() {
		panic(fmt.Errorf("Cannot encode an invalid value"))
	}
	return typeEncoder(v.Type())
}

func typeEncoder(t reflect.Type) encoderFunc {
	// Note: Omits the caching / wait-group things that encoding/json uses
	return newTypeEncoder(t)
}

var (
	marshalerType = reflect.TypeOf(new(Marshaler)).Elem()
)

func newTypeEncoder(t reflect.Type) encoderFunc {
	if t.Implements(marshalerType) {
		return marshalerEncoder
	}

	switch t.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return uintEncoder
	case reflect.Array:
		return newArrayEncoder(t)
	case reflect.Slice:
		return newSliceEncoder(t)
	case reflect.Struct:
		return newStructEncoder(t)
	case reflect.Ptr:
		return newPointerEncoder(t)
	default:
		panic(fmt.Errorf("Unsupported type (%s)", t))
	}
}

///// Specific encoders below

func omitEncoder(e *encodeState, v reflect.Value, opts fieldOptions) {
	// This space intentionally left blank
}

//////////

func marshalerEncoder(e *encodeState, v reflect.Value, opts fieldOptions) {
	if v.Kind() == reflect.Ptr && v.IsNil() && !opts.optional {
		panic(fmt.Errorf("Cannot encode nil pointer"))
	}

	if v.Kind() == reflect.Ptr && opts.optional {
		if v.IsNil() {
			writeUint(e, uint64(optionalFlagAbsent), 1)
			return
		}

		writeUint(e, uint64(optionalFlagPresent), 1)
	}

	m, ok := v.Interface().(Marshaler)
	if !ok {
		panic(fmt.Errorf("Non-Marshaler passed to marshalerEncoder"))
	}

	b, err := m.MarshalTLS()
	if err == nil {
		_, err = e.Write(b)
	}

	if err != nil {
		panic(err)
	}
}

//////////

func uintEncoder(e *encodeState, v reflect.Value, opts fieldOptions) {
	if opts.varint {
		varintEncoder(e, v, opts)
		return
	}

	writeUint(e, v.Uint(), int(v.Type().Size()))
}

func varintEncoder(e *encodeState, v reflect.Value, opts fieldOptions) {
	writeVarint(e, v.Uint())
}

func writeVarint(e *encodeState, u uint64) {
	if (u >> 62) > 0 {
		panic(fmt.Errorf("uint value is too big for varint"))
	}

	var varintLen int
	for _, len := range []uint{1, 2, 4, 8} {
		if u < (uint64(1) << (8*len - 2)) {
			varintLen = int(len)
			break
		}
	}

	twoBits := map[int]uint64{1: 0x00, 2: 0x01, 4: 0x02, 8: 0x03}[varintLen]
	shift := uint(8*varintLen - 2)
	writeUint(e, u|(twoBits<<shift), varintLen)
}

func writeUint(e *encodeState, u uint64, len int) {
	data := make([]byte, len)
	for i := 0; i < len; i += 1 {
		data[i] = byte(u >> uint(8*(len-i-1)))
	}
	e.Write(data)
}

//////////

type arrayEncoder struct {
	elemEnc encoderFunc
}

func (ae *arrayEncoder) encode(e *encodeState, v reflect.Value, opts fieldOptions) {
	n := v.Len()
	for i := 0; i < n; i += 1 {
		ae.elemEnc(e, v.Index(i), opts)
	}
}

func newArrayEncoder(t reflect.Type) encoderFunc {
	enc := &arrayEncoder{typeEncoder(t.Elem())}
	return enc.encode
}

//////////

type sliceEncoder struct {
	ae *arrayEncoder
}

func (se *sliceEncoder) encode(e *encodeState, v reflect.Value, opts fieldOptions) {
	arrayState := &encodeState{}
	se.ae.encode(arrayState, v, opts)

	n := arrayState.Len()
	if opts.maxSize > 0 && n > opts.maxSize {
		panic(fmt.Errorf("Encoded length more than max [%d > %d]", n, opts.maxSize))
	}
	if n < opts.minSize {
		panic(fmt.Errorf("Encoded length less than min [%d < %d]", n, opts.minSize))
	}

	switch {
	case opts.omitHeader:
		// None.

	case opts.varintHeader:
		writeVarint(e, uint64(n))

	case opts.headerSize > 0:
		if n>>uint(8*opts.headerSize) > 0 {
			panic(fmt.Errorf("Encoded length too long for header length [%d, %d]", n, opts.headerSize))
		}

		writeUint(e, uint64(n), int(opts.headerSize))

	default:
		panic(fmt.Errorf("Cannot encode a slice without a header length"))
	}

	e.Write(arrayState.Bytes())
}

func newSliceEncoder(t reflect.Type) encoderFunc {
	enc := &sliceEncoder{&arrayEncoder{typeEncoder(t.Elem())}}
	return enc.encode
}

//////////

type structEncoder struct {
	fieldOpts []fieldOptions
	fieldEncs []encoderFunc
}

func (se *structEncoder) encode(e *encodeState, v reflect.Value, opts fieldOptions) {
	for i := range se.fieldEncs {
		se.fieldEncs[i](e, v.Field(i), se.fieldOpts[i])
	}
}

func newStructEncoder(t reflect.Type) encoderFunc {
	n := t.NumField()
	se := structEncoder{
		fieldOpts: make([]fieldOptions, n),
		fieldEncs: make([]encoderFunc, n),
	}

	for i := 0; i < n; i += 1 {
		f := t.Field(i)
		tag := f.Tag.Get("tls")
		opts := parseTag(tag)

		if !opts.ValidForType(f.Type) {
			panic(fmt.Errorf("Tags invalid for field type"))
		}

		se.fieldOpts[i] = opts
		if opts.omit {
			se.fieldEncs[i] = omitEncoder
		} else {
			se.fieldEncs[i] = typeEncoder(f.Type)
		}
	}

	return se.encode
}

//////////

type pointerEncoder struct {
	base encoderFunc
}

func (pe pointerEncoder) encode(e *encodeState, v reflect.Value, opts fieldOptions) {
	if v.IsNil() && !opts.optional {
		panic(fmt.Errorf("Cannot encode nil pointer"))
	}

	if opts.optional {
		if v.IsNil() {
			writeUint(e, uint64(optionalFlagAbsent), 1)
			return
		}

		writeUint(e, uint64(optionalFlagPresent), 1)
	}

	pe.base(e, v.Elem(), opts)
}

func newPointerEncoder(t reflect.Type) encoderFunc {
	baseEncoder := typeEncoder(t.Elem())
	pe := pointerEncoder{base: baseEncoder}
	return pe.encode
}
