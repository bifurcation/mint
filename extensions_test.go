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

	// KeyShare test cases
	keyShareClientIn = &keyShareExtension{
		roleIsServer: false,
		shares: []keyShare{
			keyShare{group: namedGroupP256, keyExchange: []byte{0, 1, 2, 3}},
			keyShare{group: namedGroupP521, keyExchange: []byte{4, 5, 6, 7}},
		},
	}
	keyShareServerIn = &keyShareExtension{
		roleIsServer: true,
		shares: []keyShare{
			keyShare{group: namedGroupP256, keyExchange: []byte{0, 1, 2, 3}},
		},
	}
	keyShareClientHex = "0010" + "0017000400010203" + "0019000404050607"
	keyShareServerHex = "0017000400010203"
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

func TestKeyShareMarshalUnmarshal(t *testing.T) {
	keyShareClient, _ := hex.DecodeString(keyShareClientHex)
	keyShareServer, _ := hex.DecodeString(keyShareServerHex)

	// Test successful marshal (client side)
	out, err := keyShareClientIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid KeyShare (client)")
	assertByteEquals(t, out, keyShareClient)

	// Test successful marshal (server side)
	out, err = keyShareServerIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid KeyShare (server)")
	assertByteEquals(t, out, keyShareServer)

	// Test marshal failure on server trying to send multiple
	keyShareClientIn.roleIsServer = !keyShareClientIn.roleIsServer
	out, err = keyShareClientIn.Marshal()
	assertError(t, err, "Marshaled multiple key shares for server")
	keyShareClientIn.roleIsServer = !keyShareClientIn.roleIsServer

	// Test successful unmarshal (client side)
	ks := keyShareExtension{roleIsServer: false}
	read, err := ks.Unmarshal(keyShareClient)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (client)")
	assertDeepEquals(t, &ks, keyShareClientIn)
	assertEquals(t, read, len(keyShareClient))

	// Test successful unmarshal (server side)
	ks = keyShareExtension{roleIsServer: true}
	read, err = ks.Unmarshal(keyShareServer)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (server)")
	assertDeepEquals(t, &ks, keyShareServerIn)
	assertEquals(t, read, len(keyShareServer))

	// Test marshal failure on truncated length (client)
	ks = keyShareExtension{roleIsServer: false}
	read, err = ks.Unmarshal(keyShareClient[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test marshal failure on truncated keyShare length
	ks = keyShareExtension{roleIsServer: false}
	read, err = ks.Unmarshal(keyShareClient[:5])
	assertError(t, err, "Unmarshaled a KeyShare without a key share length")

	// Test marshal failure on truncated keyShare value
	ks = keyShareExtension{roleIsServer: false}
	read, err = ks.Unmarshal(keyShareClient[:7])
	assertError(t, err, "Unmarshaled a KeyShare without a truncated key share value")
}
