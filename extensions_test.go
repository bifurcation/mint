package mint

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	// Extension test cases
	extValidIn = Extension{
		ExtensionType: ExtensionType(0x000a),
		ExtensionData: []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4},
	}
	extEmptyIn = Extension{
		ExtensionType: ExtensionType(0x000a),
		ExtensionData: []byte{},
	}
	extTooLongIn = Extension{
		ExtensionType: ExtensionType(0x000a),
		ExtensionData: bytes.Repeat([]byte{0}, maxExtensionDataLen+1),
	}
	extValidHex    = "000a0005f0f1f2f3f4"
	extEmptyHex    = "000a0000"
	extNoHeaderHex = "000a00"
	extNoDataHex   = "000a000af0f1f2"

	// Extension list test cases
	extHalfLengthPlus = Extension{
		ExtensionType: ExtensionType(0x000a),
		ExtensionData: bytes.Repeat([]byte{0}, (maxExtensionDataLen/2)+1),
	}
	extListValidIn          = ExtensionList{extValidIn, extEmptyIn}
	extListSingleTooLongIn  = ExtensionList{extTooLongIn, extEmptyIn}
	extListTooLongIn        = ExtensionList{extHalfLengthPlus, extHalfLengthPlus}
	extListValidHex         = "000d000a0005f0f1f2f3f4000a0000" // supported_groups x 2 (not really valid)
	extListEmptyHex         = "0000"
	extListNoHeaderHex      = "00"
	extListOverflowOuterHex = "0020000a0005f0f1f2f3f4000a0005f0f1f2f3f4"
	extListOverflowInnerHex = "0012000a0005f0f1f2f3f4000a0010f0f1f2f3f4"

	// Add/Find test cases
	keyShareServerRaw  = unhex(keyShareServerHex)
	keyShareClientRaw  = unhex(keyShareClientHex)
	keyShareInvalidRaw = unhex(keyShareInvalidHex)
	extListKeyShareIn  = ExtensionList{
		Extension{
			ExtensionType: ExtensionTypeKeyShare,
			ExtensionData: keyShareServerRaw,
		},
	}
	extListKeyShareClientIn = ExtensionList{
		Extension{
			ExtensionType: ExtensionTypeKeyShare,
			ExtensionData: keyShareClientRaw,
		},
	}
	extListInvalidIn = ExtensionList{
		Extension{
			ExtensionType: ExtensionTypeKeyShare,
			ExtensionData: keyShareInvalidRaw,
		},
	}

	// KeyShare test cases
	len256           = keyExchangeSizeFromNamedGroup(P256)
	len521           = keyExchangeSizeFromNamedGroup(P521)
	p256             = bytes.Repeat([]byte{0}, len256)
	p521             = bytes.Repeat([]byte{0}, len521)
	keyShareClientIn = &KeyShareExtension{
		HandshakeType: HandshakeTypeClientHello,
		Shares: []KeyShareEntry{
			{Group: P256, KeyExchange: p256},
			{Group: P521, KeyExchange: p521},
		},
	}
	keyShareHelloRetryIn = &KeyShareExtension{
		HandshakeType: HandshakeTypeHelloRetryRequest,
		SelectedGroup: P256,
	}
	keyShareServerIn = &KeyShareExtension{
		HandshakeType: HandshakeTypeServerHello,
		Shares: []KeyShareEntry{
			{Group: P256, KeyExchange: p256},
		},
	}
	keyShareInvalidIn = &KeyShareExtension{
		HandshakeType: HandshakeTypeServerHello,
		Shares: []KeyShareEntry{
			{Group: P256, KeyExchange: []byte{0}},
		},
	}
	keyShareClientHex = "00ce" + "00170041" + hex.EncodeToString(p256) +
		"00190085" + hex.EncodeToString(p521)
	keyShareHelloRetryHex = "0017"
	keyShareServerHex     = "00170041" + hex.EncodeToString(p256)
	keyShareInvalidHex    = "0006001700020000"

	// PSK test cases
	pskClientHex = "000a" + "00040102030405060708" +
		"0021" + "20" + "A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0"
	pskClientUnbalancedHex = "0014" + "00040102030405060708" + "00040102030405060708" +
		"0021" + "20" + "A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0A0"
	pskServerHex = "0002"
	pskClientIn  = &PreSharedKeyExtension{
		HandshakeType: HandshakeTypeClientHello,
		Identities: []PSKIdentity{
			{
				Identity:            []byte{0x01, 0x02, 0x03, 0x04},
				ObfuscatedTicketAge: 0x05060708,
			},
		},
		Binders: []PSKBinderEntry{
			{
				Binder: bytes.Repeat([]byte{0xA0}, 32),
			},
		},
	}
	pskServerIn = &PreSharedKeyExtension{
		HandshakeType:    HandshakeTypeServerHello,
		SelectedIdentity: 2,
	}
	pskInvalidIn = &PreSharedKeyExtension{
		HandshakeType: HandshakeTypeHelloRetryRequest,
	}

	// SNI test cases (pre-declared so that we can take references in the test case)
	serverNameRaw = "example.com"
	serverNameIn  = ServerNameExtension(serverNameRaw)

	// SupportedVersions text cases
	supportedVersionsClientIn = &SupportedVersionsExtension{
		HandshakeType: HandshakeTypeClientHello,
		Versions:      []uint16{0x0300, 0x0304},
	}
	supportedVersionsServerIn = &SupportedVersionsExtension{
		HandshakeType: HandshakeTypeServerHello,
		Versions:      []uint16{0x0300},
	}

	supportedVersionsClientHex = "0403000304"
	supportedVersionsServerHex = "0300"
)

var validExtensionTestCases = map[ExtensionType]struct {
	blank        ExtensionBody
	unmarshaled  ExtensionBody
	marshaledHex string
}{
	// ServerName
	ExtensionTypeServerName: {
		blank:        new(ServerNameExtension),
		unmarshaled:  &serverNameIn,
		marshaledHex: "000e00000b6578616d706c652e636f6d",
	},

	// SupportedGroups
	ExtensionTypeSupportedGroups: {
		blank: &SupportedGroupsExtension{},
		unmarshaled: &SupportedGroupsExtension{
			Groups: []NamedGroup{P256, P384},
		},
		marshaledHex: "000400170018",
	},

	// SignatureAlgorithms
	ExtensionTypeSignatureAlgorithms: {
		blank: &SignatureAlgorithmsExtension{},
		unmarshaled: &SignatureAlgorithmsExtension{
			Algorithms: []SignatureScheme{
				RSA_PSS_SHA256,
				ECDSA_P256_SHA256,
			},
		},
		marshaledHex: "000408040403",
	},

	// ALPN
	ExtensionTypeALPN: {
		blank: &ALPNExtension{},
		unmarshaled: &ALPNExtension{
			Protocols: []string{"http/1.1", "h2"},
		},
		marshaledHex: "000c08687474702f312e31026832",
	},

	// Omitted: KeyShare (depends on HandshakeType)
	// Omitted: PreSharedKey (depends on HandshakeType)
	// Omitted: SupportedVersions (depends on HandshakeType)
	// EarlyData
	ExtensionTypeEarlyData: {
		blank:        &EarlyDataExtension{},
		unmarshaled:  &EarlyDataExtension{},
		marshaledHex: "",
	},

	// Cookie
	ExtensionTypeCookie: {
		blank: &CookieExtension{},
		unmarshaled: &CookieExtension{
			Cookie: []byte{0x01, 0x02, 0x03, 0x04},
		},
		marshaledHex: "000401020304",
	},

	// PskKeyExchangeModes
	ExtensionTypePSKKeyExchangeModes: {
		blank: &PSKKeyExchangeModesExtension{},
		unmarshaled: &PSKKeyExchangeModesExtension{
			KEModes: []PSKKeyExchangeMode{
				PSKModeKE,
				PSKModeDHEKE,
			},
		},
		marshaledHex: "020001",
	},

	// TicketEarlyDataInfo
	ExtensionTypeTicketEarlyDataInfo: {
		blank: &TicketEarlyDataInfoExtension{},
		unmarshaled: &TicketEarlyDataInfoExtension{
			MaxEarlyDataSize: 0x01020304,
		},
		marshaledHex: "01020304",
	},
}

func TestExtensionBodyMarshalUnmarshal(t *testing.T) {
	for extType, test := range validExtensionTestCases {
		marshaled := unhex(test.marshaledHex)

		// Test extension type
		assertEquals(t, test.unmarshaled.Type(), extType)

		// Test successful marshal
		out, err := test.unmarshaled.Marshal()
		assertNotError(t, err, "Failed to marshal valid extension")
		assertByteEquals(t, out, marshaled)

		// Test successful unmarshal
		read, err := test.blank.Unmarshal(marshaled)
		assertNotError(t, err, "Failed to unmarshal valid extension")
		assertDeepEquals(t, test.blank, test.unmarshaled)
		assertEquals(t, read, len(marshaled))
	}
}

func TestExtensionMarshalUnmarshal(t *testing.T) {
	extValid := unhex(extValidHex)
	extEmpty := unhex(extEmptyHex)
	extNoHeader := unhex(extNoHeaderHex)
	extNoData := unhex(extNoDataHex)

	// Test successful marshal
	out, err := extValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid extension")
	assertByteEquals(t, out, extValid)

	// Test marshal failure on extension data too long
	out, err = extTooLongIn.Marshal()
	assertError(t, err, "Marshaled an extension with too much data")

	// Test successful unmarshal
	var ext Extension
	extLen, err := ext.Unmarshal(extValid)
	assertNotError(t, err, "Failed to unmarshal valid extension")
	assertEquals(t, extLen, len(extValid))
	assertEquals(t, ext.ExtensionType, extValidIn.ExtensionType)
	assertByteEquals(t, ext.ExtensionData, extValidIn.ExtensionData)

	// Test successful unmarshal of the empty extension
	extLen, err = ext.Unmarshal(extEmpty)
	assertNotError(t, err, "Failed to unmarshal valid extension")
	assertEquals(t, extLen, len(extEmpty))
	assertEquals(t, ext.ExtensionType, extValidIn.ExtensionType)
	assertEquals(t, len(ext.ExtensionData), 0)

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
	extListValid := unhex(extListValidHex)
	extListEmpty := unhex(extListEmptyHex)
	extListNoHeader := unhex(extListNoHeaderHex)
	extListOverflowOuter := unhex(extListOverflowOuterHex)
	extListOverflowInner := unhex(extListOverflowInnerHex)

	// Test successful marshal
	out, err := extListValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid extension list")
	assertByteEquals(t, out, extListValid)

	// Test marshal failiure on a single extension too long
	out, err = extListSingleTooLongIn.Marshal()
	assertError(t, err, "Marshaled an extension list with a too-long extension")

	// Test marshal failure on extensions data too long
	out, err = extListTooLongIn.Marshal()
	assertError(t, err, "Marshaled an extension list that's too long")

	// Test successful unmarshal
	var extList ExtensionList
	extLen, err := extList.Unmarshal(extListValid)
	assertNotError(t, err, "Failed to unmarshal a valid extension list")
	assertEquals(t, extLen, len(extListValid))
	assertDeepEquals(t, extList, extListValidIn)

	// Test successful marshal of the empty list
	extLen, err = extList.Unmarshal(extListEmpty)
	assertNotError(t, err, "Failed to unmarshal a valid extension list")
	assertEquals(t, extLen, len(extListEmpty))
	assertDeepEquals(t, extList, ExtensionList{})

	// Test unmarshal failure on no header
	extLen, err = extList.Unmarshal(extListNoHeader)
	assertError(t, err, "Unmarshaled a list with no header")

	// Test unmarshal failure on incorrect outer length
	extLen, err = extList.Unmarshal(extListOverflowOuter)
	assertError(t, err, "Unmarshaled a list a too-long outer length")

	// Test unmarhsal failure on incorrect inner length
	extLen, err = extList.Unmarshal(extListOverflowInner)
	assertError(t, err, "Unmarshaled a list a too-long inner length")
}

func TestExtensionAdd(t *testing.T) {
	// Test successful add
	el := ExtensionList{}
	err := el.Add(keyShareServerIn)
	assertNotError(t, err, "Failed to add valid extension")
	assertDeepEquals(t, el, extListKeyShareIn)

	// Test successful add to a nil list
	var elp *ExtensionList
	err = elp.Add(keyShareServerIn)
	assertNotError(t, err, "Failed to add valid extension")

	// Test successful replace
	err = el.Add(keyShareClientIn)
	assertNotError(t, err, "Failed to replace extension")
	assertDeepEquals(t, el, extListKeyShareClientIn)

	// Test add failure on marshal failure
	el = ExtensionList{}
	err = el.Add(keyShareInvalidIn)
	assertError(t, err, "Added an invalid extension")
}

func TestExtensionFind(t *testing.T) {
	// Test successful find
	ks := KeyShareExtension{HandshakeType: HandshakeTypeServerHello}
	found, err := extListKeyShareIn.Find(&ks)
	assertNotError(t, err, "Failed to parse valid extension")
	assertTrue(t, found, "Failed to find a valid extension")

	// Test find failure on absent extension
	var sg SupportedGroupsExtension
	found, err = extListKeyShareIn.Find(&sg)
	assertNotError(t, err, "Error on missing extension")
	assertTrue(t, !found, "Found an extension that's not present")

	// Test find failure on unmarshal failure
	found, err = extListInvalidIn.Find(&ks)
	assertTrue(t, found, "Didn't found an extension that's not valid")
	assertError(t, err, "Parsed an invalid extension")
}

func TestExtensionParse(t *testing.T) {
	// Parse cases
	validExtensions := ExtensionList{
		Extension{
			ExtensionType: ExtensionTypeKeyShare,
			ExtensionData: keyShareClientRaw,
		},
		Extension{
			ExtensionType: ExtensionTypeSupportedVersions,
			ExtensionData: unhex(supportedVersionsClientHex),
		},
	}

	// In template
	ks := &KeyShareExtension{HandshakeType: HandshakeTypeClientHello}
	sv := &SupportedVersionsExtension{HandshakeType: HandshakeTypeClientHello}
	extensionsIn := []ExtensionBody{ks, sv}

	found, err := validExtensions.Parse(extensionsIn)
	assertNotError(t, err, "Failed to parse valid extensions")
	assertTrue(t, found[ExtensionTypeKeyShare], "Failed to find key share")
	assertTrue(t, found[ExtensionTypeSupportedVersions], "Failed to find supported versions")

	// Now a version with an error
	sv.HandshakeType = HandshakeTypeServerHello
	found, err = validExtensions.Parse(extensionsIn)
	assertError(t, err, "Parsed bogus extension")
	assertEquals(t, len(found), 0)
	sv.HandshakeType = HandshakeTypeClientHello

	// Two copies.
	dupExtensions := append(validExtensions,
		Extension{
			ExtensionType: ExtensionTypeSupportedVersions,
			ExtensionData: unhex(supportedVersionsClientHex),
		},
	)
	found, err = dupExtensions.Parse(extensionsIn)
	assertError(t, err, "Parsed duplicate extension")
	assertEquals(t, len(found), 0)
}

func TestServerNameMarshalUnmarshal(t *testing.T) {
	serverNameHex := validExtensionTestCases[ExtensionTypeServerName].marshaledHex
	serverName := unhex(serverNameHex)

	// Test unmarshal failure on underlying unmarshal failure
	var sni ServerNameExtension
	_, err := sni.Unmarshal(serverName[:1])
	assertError(t, err, "Unmarshaled a truncated ServerName")

	// Test unmarshal failure on a name that is not a host_name
	serverName[2]++
	_, err = sni.Unmarshal(serverName)
	assertError(t, err, "Unmarshaled a ServerName that was not a host_name")
	serverName[2]--
}

func TestSupportedVersionsMarshalUnmarshal(t *testing.T) {
	supportedVersionsClient := unhex(supportedVersionsClientHex)
	supportedVersionsServer := unhex(supportedVersionsServerHex)

	// Test extension type
	assertEquals(t, SupportedVersionsExtension{}.Type(), ExtensionTypeSupportedVersions)

	// Test successful marshal (client side)
	out, err := supportedVersionsClientIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid SupportedVersions (client)")
	assertByteEquals(t, out, supportedVersionsClient)

	// Test successful marshal (server side)
	out, err = supportedVersionsServerIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid SupportedVersions (server)")
	assertByteEquals(t, out, supportedVersionsServer)

	// Test marshal failure on an unsupported handshake type
	supportedVersionsServerIn.HandshakeType = HandshakeTypeCertificate
	out, err = supportedVersionsServerIn.Marshal()
	assertError(t, err, "Marshaled key an unsupported handshake type")
	supportedVersionsServerIn.HandshakeType = HandshakeTypeServerHello

	// Test successful unmarshal (client)
	sv := SupportedVersionsExtension{HandshakeType: HandshakeTypeClientHello}
	read, err := sv.Unmarshal(supportedVersionsClient)
	assertNotError(t, err, "Failed to unmarshal valid SupportedVersions (client)")
	assertDeepEquals(t, &sv, supportedVersionsClientIn)
	assertEquals(t, read, len(supportedVersionsClient))

	// Test successful unmarshal (server)
	sv = SupportedVersionsExtension{HandshakeType: HandshakeTypeServerHello}
	read, err = sv.Unmarshal(supportedVersionsServer)
	assertNotError(t, err, "Failed to unmarshal valid SupportedVersions (server)")
	assertDeepEquals(t, &sv, supportedVersionsServerIn)
	assertEquals(t, read, len(supportedVersionsServer))

	// Test unmarshal failure on underlying unmarshal failure (client)
	sv = SupportedVersionsExtension{HandshakeType: HandshakeTypeClientHello}
	read, err = sv.Unmarshal(supportedVersionsClient[:1])
	assertError(t, err, "Unmarshaled a SupportedVersions without a length")

	// Test unmarshal failure on underlying unmarshal failure (server)
	sv = SupportedVersionsExtension{HandshakeType: HandshakeTypeServerHello}
	read, err = sv.Unmarshal(supportedVersionsServer[:1])
	assertError(t, err, "Unmarshaled a SupportedVersions that's too short")
}

func TestKeyShareMarshalUnmarshal(t *testing.T) {
	keyShareClient := unhex(keyShareClientHex)
	keyShareHelloRetry := unhex(keyShareHelloRetryHex)
	keyShareServer := unhex(keyShareServerHex)
	keyShareInvalid := unhex(keyShareInvalidHex)

	// Test extension type
	assertEquals(t, KeyShareExtension{}.Type(), ExtensionTypeKeyShare)

	// Test successful marshal (client side)
	out, err := keyShareClientIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid KeyShare (client)")
	assertByteEquals(t, out, keyShareClient)

	// Test successful marshal (hello retry)
	out, err = keyShareHelloRetryIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid KeyShare (hello retry)")
	assertByteEquals(t, out, keyShareHelloRetry)

	// Test successful marshal (server side)
	out, err = keyShareServerIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid KeyShare (server)")
	assertByteEquals(t, out, keyShareServer)

	// Test marshal failure on HRR trying to send shares
	keyShareClientIn.HandshakeType = HandshakeTypeHelloRetryRequest
	out, err = keyShareClientIn.Marshal()
	assertError(t, err, "Marshaled key shares for hello retry request")
	keyShareClientIn.HandshakeType = HandshakeTypeClientHello

	// Test marshal failure on server trying to send multiple
	keyShareClientIn.HandshakeType = HandshakeTypeServerHello
	out, err = keyShareClientIn.Marshal()
	assertError(t, err, "Marshaled multiple key shares for server")
	keyShareClientIn.HandshakeType = HandshakeTypeClientHello

	// Test marshal failure on an incorrect key share size (server)
	out, err = keyShareInvalidIn.Marshal()
	assertError(t, err, "Marshaled a server key share with a wrong-size key")

	// Test marshal failure on an incorrect key share size (client)
	keyShareInvalidIn.HandshakeType = HandshakeTypeClientHello
	out, err = keyShareInvalidIn.Marshal()
	assertError(t, err, "Marshaled key shares for hello retry request")
	keyShareInvalidIn.HandshakeType = HandshakeTypeServerHello

	// Test marshal failure on an unsupported handshake type
	keyShareInvalidIn.HandshakeType = HandshakeTypeCertificate
	out, err = keyShareInvalidIn.Marshal()
	assertError(t, err, "Marshaled key an unsupported handshake type")
	keyShareInvalidIn.HandshakeType = HandshakeTypeServerHello

	// Test successful unmarshal (client)
	ks := KeyShareExtension{HandshakeType: HandshakeTypeClientHello}
	read, err := ks.Unmarshal(keyShareClient)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (client)")
	assertDeepEquals(t, &ks, keyShareClientIn)
	assertEquals(t, read, len(keyShareClient))

	// Test successful unmarshal (hello retry)
	ks = KeyShareExtension{HandshakeType: HandshakeTypeHelloRetryRequest}
	read, err = ks.Unmarshal(keyShareHelloRetry)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (hello retry)")
	assertDeepEquals(t, &ks, keyShareHelloRetryIn)
	assertEquals(t, read, len(keyShareHelloRetry))

	// Test successful unmarshal (server)
	ks = KeyShareExtension{HandshakeType: HandshakeTypeServerHello}
	read, err = ks.Unmarshal(keyShareServer)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (server)")
	assertDeepEquals(t, &ks, keyShareServerIn)
	assertEquals(t, read, len(keyShareServer))

	// Test unmarshal failure on underlying unmarshal failure (client)
	ks = KeyShareExtension{HandshakeType: HandshakeTypeClientHello}
	read, err = ks.Unmarshal(keyShareClient[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test unmarshal failure on underlying unmarshal failure (hello retry)
	ks = KeyShareExtension{HandshakeType: HandshakeTypeHelloRetryRequest}
	read, err = ks.Unmarshal(keyShareHelloRetry[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test unmarshal failure on underlying unmarshal failure (server)
	ks = KeyShareExtension{HandshakeType: HandshakeTypeServerHello}
	read, err = ks.Unmarshal(keyShareServer[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test unmarshal failure on an incorrect key share size
	ks = KeyShareExtension{HandshakeType: HandshakeTypeClientHello}
	read, err = ks.Unmarshal(keyShareInvalid)
	assertError(t, err, "Unmarshaled a key share with a wrong-size key")

	// Test unmarshal failure on an unsupported handshake type
	ks = KeyShareExtension{HandshakeType: HandshakeTypeCertificate}
	read, err = ks.Unmarshal(keyShareInvalid)
	assertError(t, err, "Unmarshaled a key share with an unsupported handshake type")
}

func TestPreSharedKeyMarshalUnmarshal(t *testing.T) {
	pskClient := unhex(pskClientHex)
	pskClientUnbalanced := unhex(pskClientUnbalancedHex)
	pskServer := unhex(pskServerHex)

	// Test extension type
	assertEquals(t, PreSharedKeyExtension{}.Type(), ExtensionTypePreSharedKey)

	// Test successful marshal (client side)
	out, err := pskClientIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid KeyShare (client)")
	assertByteEquals(t, out, pskClient)

	// Test successful marshal (server side)
	out, err = pskServerIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid KeyShare (server)")
	assertByteEquals(t, out, pskServer)

	// Test marshal failure on server trying to send multiple
	pskServerIn.Identities = pskClientIn.Identities
	out, err = pskServerIn.Marshal()
	assertError(t, err, "Marshaled multiple key shares for server")
	pskServerIn.Identities = nil

	// Test marshal failure on unsupported handshake type
	out, err = pskInvalidIn.Marshal()
	assertError(t, err, "Marshaled PSK for unsupported handshake type")

	// Test successful unmarshal (client side)
	psk := PreSharedKeyExtension{HandshakeType: HandshakeTypeClientHello}
	read, err := psk.Unmarshal(pskClient)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (client)")
	assertDeepEquals(t, &psk, pskClientIn)
	assertEquals(t, read, len(pskClient))

	// Test successful unmarshal (server side)
	psk = PreSharedKeyExtension{HandshakeType: HandshakeTypeServerHello}
	read, err = psk.Unmarshal(pskServer)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (server)")
	assertDeepEquals(t, &psk, pskServerIn)
	assertEquals(t, read, len(pskServer))

	// Test unmarshal failure on underlying unmarshal failure (client)
	psk = PreSharedKeyExtension{HandshakeType: HandshakeTypeClientHello}
	read, err = psk.Unmarshal(pskClient[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test unmarshal failure on underlying unmarshal failure (server)
	psk = PreSharedKeyExtension{HandshakeType: HandshakeTypeServerHello}
	read, err = psk.Unmarshal(pskClient[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test unmarshal failure on unsupported handshake type
	psk = PreSharedKeyExtension{HandshakeType: HandshakeTypeCertificate}
	read, err = psk.Unmarshal(pskClient)
	assertError(t, err, "Unmarshaled a KeyShare with an unsupported handshake type")

	// Test unmarshal failure on unbalanced identities/binders lengths (client)
	psk = PreSharedKeyExtension{HandshakeType: HandshakeTypeClientHello}
	read, err = psk.Unmarshal(pskClientUnbalanced)
	assertError(t, err, "Unmarshaled a KeyShare unbalanced lengths")

	// Test finding an identity that is present
	id := []byte{1, 2, 3, 4}
	binder, found := pskClientIn.HasIdentity(id)
	assertTrue(t, found, "Failed to find present identity")
	assertByteEquals(t, binder, bytes.Repeat([]byte{0xA0}, 32))

	// Test finding an identity that is not present
	id = []byte{1, 2, 4, 3}
	_, found = pskClientIn.HasIdentity(id)
	assertTrue(t, !found, "Found a not-present identity")
}

func TestALPNMarshalUnmarshal(t *testing.T) {
	alpnHex := validExtensionTestCases[ExtensionTypeALPN].marshaledHex
	alpn := unhex(alpnHex)

	// Test unmarshal failure on underlying unmarshal failure
	ext := &ALPNExtension{}
	_, err := ext.Unmarshal(alpn[:1])
	assertError(t, err, "Unmarshaled a ALPN extension with a too-long interior length")
}
