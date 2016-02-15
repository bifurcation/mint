package mint

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	// Extension test cases
	extValidIn = extension{
		extensionType: helloExtensionType(0x000a),
		extensionData: []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4},
	}
	extEmptyIn = extension{
		extensionType: helloExtensionType(0x000a),
		extensionData: []byte{},
	}
	extTooLongIn = extension{
		extensionType: helloExtensionType(0x000a),
		extensionData: bytes.Repeat([]byte{0}, maxExtensionDataLen+1),
	}
	extValidHex    = "000a0005f0f1f2f3f4"
	extEmptyHex    = "000a0000"
	extNoHeaderHex = "000a00"
	extNoDataHex   = "000a000af0f1f2"

	// Extension list test cases
	extHalfLengthPlus = extension{
		extensionType: helloExtensionType(0x000a),
		extensionData: bytes.Repeat([]byte{0}, (maxExtensionDataLen/2)+1),
	}
	extListValidIn          = []extension{extValidIn, extEmptyIn}
	extListSingleTooLongIn  = []extension{extTooLongIn, extEmptyIn}
	extListTooLongIn        = []extension{extHalfLengthPlus, extHalfLengthPlus}
	extListValidHex         = "000d000a0005f0f1f2f3f4000a0000"
	extListEmptyHex         = "0000"
	extListNoHeaderHex      = "00"
	extListOverflowOuterHex = "0020000a0005f0f1f2f3f4000a0005f0f1f2f3f4"
	extListOverflowInnerHex = "0012000a0005f0f1f2f3f4000a0010f0f1f2f3f4"

	// ClientHello test cases
	helloRandom = [32]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37}
	chCipherSuites = []cipherSuite{0x0001, 0x0002, 0x0003}
	chValidIn      = clientHelloBody{
		random:       helloRandom,
		cipherSuites: chCipherSuites,
		extensions:   extListValidIn,
	}
	chValidHex = "0304" + hex.EncodeToString(helloRandom[:]) + "00" +
		"0006000100020003" + "0100" + extListValidHex
	chOverflowHex = "0304" + hex.EncodeToString(helloRandom[:]) + "00" +
		"0006000100020003" + "0100" + extListOverflowOuterHex

	// ServerHello test cases
	shValidIn = serverHelloBody{
		random:      helloRandom,
		cipherSuite: cipherSuite(0x0001),
		extensions:  extListValidIn,
	}
	shEmptyIn = serverHelloBody{
		random:      helloRandom,
		cipherSuite: cipherSuite(0x0001),
	}
	shValidHex    = "0304" + hex.EncodeToString(helloRandom[:]) + "0001" + extListValidHex
	shEmptyHex    = "0304" + hex.EncodeToString(helloRandom[:]) + "0001"
	shOverflowHex = "0304" + hex.EncodeToString(helloRandom[:]) + "0001" + extListOverflowOuterHex
)

func TestExtensionMarshalUnmarshal(t *testing.T) {
	extValid, _ := hex.DecodeString(extValidHex)
	extEmpty, _ := hex.DecodeString(extEmptyHex)
	extNoHeader, _ := hex.DecodeString(extNoHeaderHex)
	extNoData, _ := hex.DecodeString(extNoDataHex)

	// Test successful marshal
	out, err := extValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid extension")
	assertByteEquals(t, out, extValid)

	// Test marshal failure on extension data too long
	out, err = extTooLongIn.Marshal()
	assertError(t, err, "Marshaled an extension with too much data")

	// Test successful unmarshal
	var ext extension
	extLen, err := ext.Unmarshal(extValid)
	assertNotError(t, err, "Failed to unmarshal valid extension")
	assertEquals(t, extLen, len(extValid))
	assertEquals(t, ext.extensionType, extValidIn.extensionType)
	assertByteEquals(t, ext.extensionData, extValidIn.extensionData)

	// Test successful unmarshal of the empty extension
	extLen, err = ext.Unmarshal(extEmpty)
	assertNotError(t, err, "Failed to unmarshal valid extension")
	assertEquals(t, extLen, len(extEmpty))
	assertEquals(t, ext.extensionType, extValidIn.extensionType)
	assertEquals(t, len(ext.extensionData), 0)

	// Test unmarshal failure on no header
	extLen, err = ext.Unmarshal(extNoHeader)
	assertError(t, err, "Unmarshaled an extension with no header")
	assertEquals(t, extLen, 0)

	// Test unmarshal failure on too little data
	extLen, err = ext.Unmarshal(extNoData)
	assertError(t, err, "Unmarshaled an extension with insufficient data")
	assertEquals(t, extLen, 0)
}

func TestExtensionListMarshalUnmarshal(t *testing.T) {
	extListValid, _ := hex.DecodeString(extListValidHex)
	extListEmpty, _ := hex.DecodeString(extListEmptyHex)
	extListNoHeader, _ := hex.DecodeString(extListNoHeaderHex)
	extListOverflowOuter, _ := hex.DecodeString(extListOverflowOuterHex)
	extListOverflowInner, _ := hex.DecodeString(extListOverflowInnerHex)

	// Test successful marshal
	out, err := marshalExtensionList(extListValidIn)
	assertNotError(t, err, "Failed to marshal valid extension list")
	assertByteEquals(t, out, extListValid)

	// Test marshal failiure on a single extension too long
	out, err = marshalExtensionList(extListSingleTooLongIn)
	assertError(t, err, "Marshaled an extension list with a too-long extension")

	// Test marshal failure on extensions data too long
	out, err = marshalExtensionList(extListTooLongIn)
	assertError(t, err, "Marshaled an extension list that's too long")

	// Test successful unmarshal
	extList, extLen, err := unmarshalExtensionList(extListValid)
	assertNotError(t, err, "Failed to unmarshal a valid extension list")
	assertEquals(t, extLen, len(extListValid))
	assertDeepEquals(t, extList, extListValidIn)

	// Test successful marshal of the empty list
	extList, extLen, err = unmarshalExtensionList(extListEmpty)
	assertNotError(t, err, "Failed to unmarshal a valid extension list")
	assertEquals(t, extLen, len(extListEmpty))
	assertDeepEquals(t, extList, []extension{})

	// Test unmarshal failure on no header
	extList, extLen, err = unmarshalExtensionList(extListNoHeader)
	assertError(t, err, "Unmarshaled a list with no header")

	// Test unmarshal failure on incorrect outer length
	extList, extLen, err = unmarshalExtensionList(extListOverflowOuter)
	assertError(t, err, "Unmarshaled a list a too-long outer length")

	// Test unmarhsal failure on incorrect inner length
	extList, extLen, err = unmarshalExtensionList(extListOverflowInner)
	assertError(t, err, "Unmarshaled a list a too-long inner length")

}

func TestClientHelloMarshalUnmarshal(t *testing.T) {
	chValid, _ := hex.DecodeString(chValidHex)
	chOverflow, _ := hex.DecodeString(chOverflowHex)

	// Test successful marshal
	out, err := chValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid ClientHello")
	assertByteEquals(t, out, chValid)

	// Test marshal failure on empty ciphersuites
	chValidIn.cipherSuites = []cipherSuite{}
	out, err = chValidIn.Marshal()
	assertError(t, err, "Marshaled a ClientHello with no CipherSuites")
	chValidIn.cipherSuites = chCipherSuites

	// Test marshal failure on too many ciphersuites
	tooManyCipherSuites := make([]cipherSuite, maxCipherSuites+1)
	for i := range tooManyCipherSuites {
		tooManyCipherSuites[i] = cipherSuite(0x0001)
	}
	chValidIn.cipherSuites = tooManyCipherSuites
	out, err = chValidIn.Marshal()
	assertError(t, err, "Marshaled a ClientHello with too many CipherSuites")
	chValidIn.cipherSuites = chCipherSuites

	// Test marshal failure on extension list marshal failure
	chValidIn.extensions = extListTooLongIn
	out, err = chValidIn.Marshal()
	assertError(t, err, "Marshaled a ClientHello with bad extensions")
	chValidIn.extensions = extListValidIn

	// Test successful unmarshal
	var ch clientHelloBody
	chLen, err := ch.Unmarshal(chValid)
	assertNotError(t, err, "Failed to unmarshal a valid ClientHello")
	assertEquals(t, chLen, len(chValid))
	assertDeepEquals(t, ch, chValidIn)

	// Test unmarshal failure on too-short ClientHello
	chLen, err = ch.Unmarshal(chValid[:fixedClientHelloBodyLen-1])
	assertError(t, err, "Unmarshaled a ClientHello below the min length")

	// Test unmarshal failure on wrong version
	chValid[1] -= 1
	chLen, err = ch.Unmarshal(chValid)
	assertError(t, err, "Unmarshaled a ClientHello with the wrong version")
	chValid[1] += 1

	// Test unmarshal failure on non-empty session ID
	chValid[34] = 0x04
	chLen, err = ch.Unmarshal(chValid)
	assertError(t, err, "Unmarshaled a ClientHello with non-empty session ID")
	chValid[34] = 0x00

	// Test unmarshal failure on ciphersuite size overflow
	chValid[35] = 0xFF
	chLen, err = ch.Unmarshal(chValid)
	assertError(t, err, "Unmarshaled a ClientHello an overflowing cipherSuite list")
	chValid[35] = 0x00

	// Test unmarshal failure on odd ciphersuite size
	chValid[36] ^= 0x01
	chLen, err = ch.Unmarshal(chValid)
	assertError(t, err, "Unmarshaled a ClientHello an odd cipherSuite list length")
	chValid[36] ^= 0x01

	// Test unmarshal failure on missing compression methods
	chLen, err = ch.Unmarshal(chValid[:37+6])
	assertError(t, err, "Unmarshaled a ClientHello truncated before the compression methods")

	// Test unmarshal failure on incorrect compression methods
	chValid[37+6] = 0x03
	chLen, err = ch.Unmarshal(chValid)
	assertError(t, err, "Unmarshaled a ClientHello more than one compression method")
	chValid[37+6] = 0x01
	chValid[37+7] = 0x01
	chLen, err = ch.Unmarshal(chValid)
	assertError(t, err, "Unmarshaled a ClientHello the wrong compression method")
	chValid[37+7] = 0x00

	// Test unmarshal failure on extension list unmarshal failure
	chLen, err = ch.Unmarshal(chOverflow)
	assertError(t, err, "Unmarshaled a ClientHello with invalid extensions")
}

func TestServerHelloMarshalUnmarshal(t *testing.T) {
	shValid, _ := hex.DecodeString(shValidHex)
	shEmpty, _ := hex.DecodeString(shEmptyHex)
	shOverflow, _ := hex.DecodeString(shOverflowHex)

	// Test successful marshal
	out, err := shValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid ServerHello")
	assertByteEquals(t, out, shValid)

	// Test successful marshal with no extensions present
	out, err = shEmptyIn.Marshal()
	assertNotError(t, err, "Failed to marshal a valid ServerHello with no extensions")
	assertByteEquals(t, out, shEmpty)

	// Test marshal failure on extension list marshal failure
	shValidIn.extensions = extListTooLongIn
	out, err = shValidIn.Marshal()
	assertError(t, err, "Marshaled a ServerHello with bad extensions")
	shValidIn.extensions = extListValidIn

	// Test successful unmarshal
	var sh serverHelloBody
	shLen, err := sh.Unmarshal(shValid)
	assertNotError(t, err, "Failed to unmarshal a valid ServerHello")
	assertEquals(t, shLen, len(shValid))
	assertDeepEquals(t, sh, shValidIn)

	// Test successful unmarshal with no extensions present
	shLen, err = sh.Unmarshal(shEmpty)
	assertNotError(t, err, "Failed to unmarshal a valid ServerHello")
	assertEquals(t, shLen, len(shEmpty))
	assertByteEquals(t, sh.random[:], shEmptyIn.random[:])
	assertEquals(t, sh.cipherSuite, shEmptyIn.cipherSuite)
	assertEquals(t, len(sh.extensions), 0)

	// Test unmarshal failure on too-short ServerHello
	shLen, err = sh.Unmarshal(shValid[:fixedServerHelloBodyLen-1])
	assertError(t, err, "Unmarshaled a too-short ServerHello")

	// Test unmarshal failure on wrong version
	shValid[1] -= 1
	shLen, err = sh.Unmarshal(shValid)
	assertError(t, err, "Unmarshaled a ServerHello with the wrong version")
	shValid[1] += 1

	// Test unmarshal failure on extension list unmarshal failure
	shLen, err = sh.Unmarshal(shOverflow)
	assertError(t, err, "Unmarshaled a ServerHello with invalid extensions")
}
