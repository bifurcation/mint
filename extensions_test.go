package mint

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	// Extension test cases
	extValidIn = extension{
		ExtensionType: extensionType(0x000a),
		ExtensionData: []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4},
	}
	extEmptyIn = extension{
		ExtensionType: extensionType(0x000a),
		ExtensionData: []byte{},
	}
	extTooLongIn = extension{
		ExtensionType: extensionType(0x000a),
		ExtensionData: bytes.Repeat([]byte{0}, maxExtensionDataLen+1),
	}
	extValidHex    = "000a0005f0f1f2f3f4"
	extEmptyHex    = "000a0000"
	extNoHeaderHex = "000a00"
	extNoDataHex   = "000a000af0f1f2"

	// Extension list test cases
	extHalfLengthPlus = extension{
		ExtensionType: extensionType(0x000a),
		ExtensionData: bytes.Repeat([]byte{0}, (maxExtensionDataLen/2)+1),
	}
	extListValidIn          = extensionList{extValidIn, extEmptyIn}
	extListSingleTooLongIn  = extensionList{extTooLongIn, extEmptyIn}
	extListTooLongIn        = extensionList{extHalfLengthPlus, extHalfLengthPlus}
	extListValidHex         = "000d000a0005f0f1f2f3f4000a0000"
	extListEmptyHex         = "0000"
	extListNoHeaderHex      = "00"
	extListOverflowOuterHex = "0020000a0005f0f1f2f3f4000a0005f0f1f2f3f4"
	extListOverflowInnerHex = "0012000a0005f0f1f2f3f4000a0010f0f1f2f3f4"

	// Add/Find test cases
	keyShareServerRaw, _  = hex.DecodeString(keyShareServerHex)
	keyShareClientRaw, _  = hex.DecodeString(keyShareClientHex)
	keyShareInvalidRaw, _ = hex.DecodeString(keyShareInvalidHex)
	extListKeyShareIn     = extensionList{
		extension{
			ExtensionType: extensionTypeKeyShare,
			ExtensionData: keyShareServerRaw,
		},
	}
	extListKeyShareClientIn = extensionList{
		extension{
			ExtensionType: extensionTypeKeyShare,
			ExtensionData: keyShareClientRaw,
		},
	}
	extListInvalidIn = extensionList{
		extension{
			ExtensionType: extensionTypeKeyShare,
			ExtensionData: keyShareInvalidRaw,
		},
	}

	// KeyShare test cases
	len256           = keyExchangeSizeFromNamedGroup(namedGroupP256)
	len521           = keyExchangeSizeFromNamedGroup(namedGroupP521)
	p256             = bytes.Repeat([]byte{0}, len256)
	p521             = bytes.Repeat([]byte{0}, len521)
	keyShareClientIn = &keyShareExtension{
		handshakeType: handshakeTypeClientHello,
		shares: []keyShareEntry{
			keyShareEntry{Group: namedGroupP256, KeyExchange: p256},
			keyShareEntry{Group: namedGroupP521, KeyExchange: p521},
		},
	}
	keyShareHelloRetryIn = &keyShareExtension{
		handshakeType: handshakeTypeHelloRetryRequest,
		selectedGroup: namedGroupP256,
	}
	keyShareServerIn = &keyShareExtension{
		handshakeType: handshakeTypeServerHello,
		shares: []keyShareEntry{
			keyShareEntry{Group: namedGroupP256, KeyExchange: p256},
		},
	}
	keyShareInvalidIn = &keyShareExtension{
		handshakeType: handshakeTypeServerHello,
		shares: []keyShareEntry{
			keyShareEntry{Group: namedGroupP256, KeyExchange: []byte{0}},
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
	pskClientIn  = &preSharedKeyExtension{
		handshakeType: handshakeTypeClientHello,
		identities: []pskIdentity{
			pskIdentity{
				Identity:            []byte{0x01, 0x02, 0x03, 0x04},
				ObfuscatedTicketAge: 0x05060708,
			},
		},
		binders: []pskBinderEntry{
			pskBinderEntry{
				Binder: bytes.Repeat([]byte{0xA0}, 32),
			},
		},
	}
	pskServerIn = &preSharedKeyExtension{
		handshakeType:    handshakeTypeServerHello,
		selectedIdentity: 2,
	}
	pskInvalidIn = &preSharedKeyExtension{
		handshakeType: handshakeTypeHelloRetryRequest,
	}

	// SNI test cases (pre-declared so that we can take references in the test case)
	serverNameRaw = "example.com"
	serverNameIn  = serverNameExtension(serverNameRaw)
)

var validExtensionTestCases = map[extensionType]struct {
	blank        extensionBody
	unmarshaled  extensionBody
	marshaledHex string
}{
	// ServerName
	extensionTypeServerName: {
		blank:        new(serverNameExtension),
		unmarshaled:  &serverNameIn,
		marshaledHex: "000e00000b6578616d706c652e636f6d",
	},

	// SupportedGroups
	extensionTypeSupportedGroups: {
		blank: &supportedGroupsExtension{},
		unmarshaled: &supportedGroupsExtension{
			Groups: []namedGroup{namedGroupP256, namedGroupP384},
		},
		marshaledHex: "000400170018",
	},

	// SignatureAlgorithms
	extensionTypeSignatureAlgorithms: {
		blank: &signatureAlgorithmsExtension{},
		unmarshaled: &signatureAlgorithmsExtension{
			Algorithms: []signatureScheme{
				signatureSchemeRSA_PSS_SHA256,
				signatureSchemeECDSA_P256_SHA256,
			},
		},
		marshaledHex: "000408040403",
	},

	// ALPN
	extensionTypeALPN: {
		blank: &alpnExtension{},
		unmarshaled: &alpnExtension{
			protocols: []string{"http/1.1", "h2"},
		},
		marshaledHex: "000c08687474702f312e31026832",
	},

	// Omitted: KeyShare (depends on handshakeType)
	// Omitted: PreSharedKey (depends on handshakeType)

	// EarlyData
	extensionTypeEarlyData: {
		blank:        &earlyDataExtension{},
		unmarshaled:  &earlyDataExtension{},
		marshaledHex: "",
	},

	// SupportedVersions
	extensionTypeSupportedVersions: {
		blank: &supportedVersionsExtension{},
		unmarshaled: &supportedVersionsExtension{
			Versions: []uint16{0x0300, 0x0304},
		},
		marshaledHex: "0403000304",
	},

	// Cookie
	extensionTypeCookie: {
		blank: &cookieExtension{},
		unmarshaled: &cookieExtension{
			Cookie: []byte{0x01, 0x02, 0x03, 0x04},
		},
		marshaledHex: "000401020304",
	},

	// PskKeyExchangeModes
	extensionTypePSKKeyExchangeModes: {
		blank: &pskKeyExchangeModesExtension{},
		unmarshaled: &pskKeyExchangeModesExtension{
			KEModes: []pskKeyExchangeMode{
				pskModeKE,
				pskModeDHEKE,
			},
		},
		marshaledHex: "020001",
	},

	// TicketEarlyDataInfo
	extensionTypeTicketEarlyDataInfo: {
		blank: &ticketEarlyDataInfoExtension{},
		unmarshaled: &ticketEarlyDataInfoExtension{
			MaxEarlyDataSize: 0x01020304,
		},
		marshaledHex: "01020304",
	},
}

func TestExtensionBodyMarshalUnmarshal(t *testing.T) {
	for extType, test := range validExtensionTestCases {
		marshaled, err := hex.DecodeString(test.marshaledHex)
		assertNotError(t, err, "Malformed test case for extension type")

		// Test extension type
		assertEquals(t, test.unmarshaled.Type(), extType)

		// Test successful marshal
		out, err := test.unmarshaled.Marshal()
		assertNotError(t, err, "Failed to marshal valid Cookie")
		assertByteEquals(t, out, marshaled)

		// Test successful unmarshal
		read, err := test.blank.Unmarshal(marshaled)
		assertNotError(t, err, "Failed to unmarshal valid Cookie")
		assertDeepEquals(t, test.blank, test.unmarshaled)
		assertEquals(t, read, len(marshaled))
	}
}

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
	extListValid, _ := hex.DecodeString(extListValidHex)
	extListEmpty, _ := hex.DecodeString(extListEmptyHex)
	extListNoHeader, _ := hex.DecodeString(extListNoHeaderHex)
	extListOverflowOuter, _ := hex.DecodeString(extListOverflowOuterHex)
	extListOverflowInner, _ := hex.DecodeString(extListOverflowInnerHex)

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
	var extList extensionList
	extLen, err := extList.Unmarshal(extListValid)
	assertNotError(t, err, "Failed to unmarshal a valid extension list")
	assertEquals(t, extLen, len(extListValid))
	assertDeepEquals(t, extList, extListValidIn)

	// Test successful marshal of the empty list
	extLen, err = extList.Unmarshal(extListEmpty)
	assertNotError(t, err, "Failed to unmarshal a valid extension list")
	assertEquals(t, extLen, len(extListEmpty))
	assertDeepEquals(t, extList, extensionList{})

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
	el := extensionList{}
	err := el.Add(keyShareServerIn)
	assertNotError(t, err, "Failed to add valid extension")
	assertDeepEquals(t, el, extListKeyShareIn)

	// Test successful add to a nil list
	var elp *extensionList
	t.Logf("%v", elp == nil)
	err = elp.Add(keyShareServerIn)
	assertNotError(t, err, "Failed to add valid extension")

	// Test successful replace
	err = el.Add(keyShareClientIn)
	assertNotError(t, err, "Failed to replace extension")
	assertDeepEquals(t, el, extListKeyShareClientIn)

	// Test add failure on marshal failure
	el = extensionList{}
	err = el.Add(keyShareInvalidIn)
	assertError(t, err, "Added an invalid extension")
}

func TestExtensionFind(t *testing.T) {
	// Test successful find
	ks := keyShareExtension{handshakeType: handshakeTypeServerHello}
	found := extListKeyShareIn.Find(&ks)
	assert(t, found, "Failed to find a valid extension")

	// Test find failure on absent extension
	var sg supportedGroupsExtension
	found = extListKeyShareIn.Find(&sg)
	assert(t, !found, "Found an extension that's not present")

	// Test find failure on unmarshal failure
	found = extListInvalidIn.Find(&ks)
	assert(t, !found, "Found an extension that's not valid")
}

func TestServerNameMarshalUnmarshal(t *testing.T) {
	serverNameHex := validExtensionTestCases[extensionTypeServerName].marshaledHex
	serverName, _ := hex.DecodeString(serverNameHex)

	// Test unmarshal failure on underlying unmarshal failure
	var sni serverNameExtension
	_, err := sni.Unmarshal(serverName[:1])
	assertError(t, err, "Unmarshaled a truncated ServerName")

	// Test unmarshal failure on a name that is not a host_name
	serverName[2]++
	_, err = sni.Unmarshal(serverName)
	assertError(t, err, "Unmarshaled a ServerName that was not a host_name")
	serverName[2]--
}

func TestKeyShareMarshalUnmarshal(t *testing.T) {
	keyShareClient, _ := hex.DecodeString(keyShareClientHex)
	keyShareHelloRetry, _ := hex.DecodeString(keyShareHelloRetryHex)
	keyShareServer, _ := hex.DecodeString(keyShareServerHex)
	keyShareInvalid, _ := hex.DecodeString(keyShareInvalidHex)

	// Test extension type
	assertEquals(t, keyShareExtension{}.Type(), extensionTypeKeyShare)

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
	keyShareClientIn.handshakeType = handshakeTypeHelloRetryRequest
	out, err = keyShareClientIn.Marshal()
	assertError(t, err, "Marshaled key shares for hello retry request")
	keyShareClientIn.handshakeType = handshakeTypeClientHello

	// Test marshal failure on server trying to send multiple
	keyShareClientIn.handshakeType = handshakeTypeServerHello
	out, err = keyShareClientIn.Marshal()
	assertError(t, err, "Marshaled multiple key shares for server")
	keyShareClientIn.handshakeType = handshakeTypeClientHello

	// Test marshal failure on an incorrect key share size (server)
	out, err = keyShareInvalidIn.Marshal()
	assertError(t, err, "Marshaled a server key share with a wrong-size key")

	// Test marshal failure on an incorrect key share size (client)
	keyShareInvalidIn.handshakeType = handshakeTypeClientHello
	out, err = keyShareInvalidIn.Marshal()
	assertError(t, err, "Marshaled key shares for hello retry request")
	keyShareInvalidIn.handshakeType = handshakeTypeServerHello

	// Test marshal failure on an unsupported handshake type
	keyShareInvalidIn.handshakeType = handshakeTypeCertificate
	out, err = keyShareInvalidIn.Marshal()
	assertError(t, err, "Marshaled key an unsupported handshake type")
	keyShareInvalidIn.handshakeType = handshakeTypeServerHello

	// Test successful unmarshal (client)
	ks := keyShareExtension{handshakeType: handshakeTypeClientHello}
	read, err := ks.Unmarshal(keyShareClient)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (client)")
	assertDeepEquals(t, &ks, keyShareClientIn)
	assertEquals(t, read, len(keyShareClient))

	// Test successful unmarshal (hello retry)
	ks = keyShareExtension{handshakeType: handshakeTypeHelloRetryRequest}
	read, err = ks.Unmarshal(keyShareHelloRetry)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (hello retry)")
	assertDeepEquals(t, &ks, keyShareHelloRetryIn)
	assertEquals(t, read, len(keyShareHelloRetry))

	// Test successful unmarshal (server)
	ks = keyShareExtension{handshakeType: handshakeTypeServerHello}
	read, err = ks.Unmarshal(keyShareServer)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (server)")
	assertDeepEquals(t, &ks, keyShareServerIn)
	assertEquals(t, read, len(keyShareServer))

	// Test unmarshal failure on underlying unmarshal failure (client)
	ks = keyShareExtension{handshakeType: handshakeTypeClientHello}
	read, err = ks.Unmarshal(keyShareClient[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test unmarshal failure on underlying unmarshal failure (hello retry)
	ks = keyShareExtension{handshakeType: handshakeTypeHelloRetryRequest}
	read, err = ks.Unmarshal(keyShareHelloRetry[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test unmarshal failure on underlying unmarshal failure (server)
	ks = keyShareExtension{handshakeType: handshakeTypeServerHello}
	read, err = ks.Unmarshal(keyShareServer[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test unmarshal failure on an incorrect key share size
	ks = keyShareExtension{handshakeType: handshakeTypeClientHello}
	read, err = ks.Unmarshal(keyShareInvalid)
	assertError(t, err, "Unmarshaled a key share with a wrong-size key")

	// Test unmarshal failure on an unsupported handshake type
	ks = keyShareExtension{handshakeType: handshakeTypeCertificate}
	read, err = ks.Unmarshal(keyShareInvalid)
	assertError(t, err, "Unmarshaled a key share with an unsupported handshake type")
}

func TestPreSharedKeyMarshalUnmarshal(t *testing.T) {
	pskClient, _ := hex.DecodeString(pskClientHex)
	pskClientUnbalanced, _ := hex.DecodeString(pskClientUnbalancedHex)
	pskServer, _ := hex.DecodeString(pskServerHex)

	// Test extension type
	assertEquals(t, preSharedKeyExtension{}.Type(), extensionTypePreSharedKey)

	// Test successful marshal (client side)
	out, err := pskClientIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid KeyShare (client)")
	assertByteEquals(t, out, pskClient)

	// Test successful marshal (server side)
	out, err = pskServerIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid KeyShare (server)")
	assertByteEquals(t, out, pskServer)

	// Test marshal failure on server trying to send multiple
	pskServerIn.identities = pskClientIn.identities
	out, err = pskServerIn.Marshal()
	assertError(t, err, "Marshaled multiple key shares for server")
	pskServerIn.identities = nil

	// Test marshal failure on unsupported handshake type
	out, err = pskInvalidIn.Marshal()
	assertError(t, err, "Marshaled PSK for unsupported handshake type")

	// Test successful unmarshal (client side)
	psk := preSharedKeyExtension{handshakeType: handshakeTypeClientHello}
	read, err := psk.Unmarshal(pskClient)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (client)")
	assertDeepEquals(t, &psk, pskClientIn)
	assertEquals(t, read, len(pskClient))

	// Test successful unmarshal (server side)
	psk = preSharedKeyExtension{handshakeType: handshakeTypeServerHello}
	read, err = psk.Unmarshal(pskServer)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (server)")
	assertDeepEquals(t, &psk, pskServerIn)
	assertEquals(t, read, len(pskServer))

	// Test unmarshal failure on underlying unmarshal failure (client)
	psk = preSharedKeyExtension{handshakeType: handshakeTypeClientHello}
	read, err = psk.Unmarshal(pskClient[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test unmarshal failure on underlying unmarshal failure (server)
	psk = preSharedKeyExtension{handshakeType: handshakeTypeServerHello}
	read, err = psk.Unmarshal(pskClient[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test unmarshal failure on unsupported handshake type
	psk = preSharedKeyExtension{handshakeType: handshakeTypeCertificate}
	read, err = psk.Unmarshal(pskClient)
	assertError(t, err, "Unmarshaled a KeyShare with an unsupported handshake type")

	// Test unmarshal failure on unbalanced identities/binders lengths (client)
	psk = preSharedKeyExtension{handshakeType: handshakeTypeClientHello}
	read, err = psk.Unmarshal(pskClientUnbalanced)
	assertError(t, err, "Unmarshaled a KeyShare unbalanced lengths")

	// Test finding an identity that is present
	id := []byte{1, 2, 3, 4}
	binder, found := pskClientIn.HasIdentity(id)
	assert(t, found, "Failed to find present identity")
	assertByteEquals(t, binder, bytes.Repeat([]byte{0xA0}, 32))

	// Test finding an identity that is not present
	id = []byte{1, 2, 4, 3}
	_, found = pskClientIn.HasIdentity(id)
	assert(t, !found, "Found a not-present identity")
}

func TestALPNMarshalUnmarshal(t *testing.T) {
	alpnHex := validExtensionTestCases[extensionTypeALPN].marshaledHex
	alpn, _ := hex.DecodeString(alpnHex)

	// Test unmarshal failure on underlying unmarshal failure
	ext := &alpnExtension{}
	_, err := ext.Unmarshal(alpn[:1])
	assertError(t, err, "Unmarshaled a ALPN extension with a too-long interior length")
}
