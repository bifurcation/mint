package mint

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var (
	// Extension test cases
	extValidIn = extension{
		ExtensionType: helloExtensionType(0x000a),
		ExtensionData: []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4},
	}
	extEmptyIn = extension{
		ExtensionType: helloExtensionType(0x000a),
		ExtensionData: []byte{},
	}
	extTooLongIn = extension{
		ExtensionType: helloExtensionType(0x000a),
		ExtensionData: bytes.Repeat([]byte{0}, maxExtensionDataLen+1),
	}
	extValidHex    = "000a0005f0f1f2f3f4"
	extEmptyHex    = "000a0000"
	extNoHeaderHex = "000a00"
	extNoDataHex   = "000a000af0f1f2"

	// Extension list test cases
	extHalfLengthPlus = extension{
		ExtensionType: helloExtensionType(0x000a),
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
	keyShareInvalidHex    = "0017000100"

	// Add/Find test cases
	keyShareServerRaw, _  = hex.DecodeString(keyShareServerHex)
	keyShareInvalidRaw, _ = hex.DecodeString(keyShareInvalidHex)
	extListKeyShareIn     = extensionList{
		extension{
			ExtensionType: extensionTypeKeyShare,
			ExtensionData: keyShareServerRaw,
		},
	}
	extListInvalidIn = extensionList{
		extension{
			ExtensionType: extensionTypeKeyShare,
			ExtensionData: keyShareInvalidRaw,
		},
	}

	// SupportedGroups test cases
	supportedGroupsIn = supportedGroupsExtension{
		Groups: []namedGroup{namedGroupP256, namedGroupP384},
	}
	supportedGroupsHex = "000400170018"

	// SignatureAlgorithms test cases
	signatureAlgorithmsIn = signatureAlgorithmsExtension{
		Algorithms: []signatureScheme{
			signatureSchemeRSA_PSS_SHA256,
			signatureSchemeECDSA_P256_SHA256,
		},
	}
	signatureAlgorithmsHex = "000408040403"

	// SNI test cases
	serverNameRaw = "example.com"
	serverNameIn  = serverNameExtension(serverNameRaw)
	serverNameHex = "000e00000b" + hex.EncodeToString([]byte(serverNameRaw))

	// PSK test cases
	pskClientHex = "000a" + "00040102030405060708" +
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

	// ALPN test cases
	alpnValidHex    = "000c08687474702f312e31026832"
	alpnTooShortHex = "0003046874"
	alpnValidIn     = &alpnExtension{
		protocols: []string{"http/1.1", "h2"},
	}

	// SupportedVersions test cases
	supportedVersionsIn = supportedVersionsExtension{
		Versions: []uint16{0x0300, 0x0304},
	}
	supportedVersionsHex = "0403000304"
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
	serverName, _ := hex.DecodeString(serverNameHex)

	// Test extension type
	assertEquals(t, serverNameExtension("").Type(), extensionTypeServerName)

	// Test successful marshal
	out, err := serverNameIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid ServerName")
	assertByteEquals(t, out, serverName)

	// Test successful unmarshal
	var sni serverNameExtension
	_, err = sni.Unmarshal(serverName)
	assertNotError(t, err, "Failed to unmarshal valid ServerName")
	assertDeepEquals(t, sni, serverNameIn)

	// Test unmarshal failure on truncated header
	_, err = sni.Unmarshal(serverName[:4])
	assertError(t, err, "Unmarshaled a ServerName without a header")

	// Test unmarshal failure on truncated name
	_, err = sni.Unmarshal(serverName[:7])
	assertError(t, err, "Unmarshaled a ServerName without a full name")

	// Test unmarshal failure on length mismatch
	serverName[4]++
	_, err = sni.Unmarshal(serverName)
	assertError(t, err, "Unmarshaled a ServerName with inconsistent lengths")
	serverName[4]--

	// Test unmarshal failure on odd list length
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

	// Test successful unmarshal (client side)
	ks := keyShareExtension{handshakeType: handshakeTypeClientHello}
	read, err := ks.Unmarshal(keyShareClient)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (client)")
	assertDeepEquals(t, &ks, keyShareClientIn)
	assertEquals(t, read, len(keyShareClient))

	// Test successful unmarshal (server side)
	ks = keyShareExtension{handshakeType: handshakeTypeServerHello}
	read, err = ks.Unmarshal(keyShareServer)
	assertNotError(t, err, "Failed to unmarshal valid KeyShare (server)")
	assertDeepEquals(t, &ks, keyShareServerIn)
	assertEquals(t, read, len(keyShareServer))

	// Test unmarshal failure on truncated length (client)
	ks = keyShareExtension{handshakeType: handshakeTypeClientHello}
	read, err = ks.Unmarshal(keyShareClient[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test unmarshal failure on truncated keyShare length
	ks = keyShareExtension{handshakeType: handshakeTypeClientHello}
	read, err = ks.Unmarshal(keyShareClient[:5])
	assertError(t, err, "Unmarshaled a KeyShare without a key share length")

	// Test unmarshal failure on truncated keyShare value
	ks = keyShareExtension{handshakeType: handshakeTypeClientHello}
	read, err = ks.Unmarshal(keyShareClient[:7])
	assertError(t, err, "Unmarshaled a KeyShare without a truncated key share value")

	// Test unmarshal failure on an incorrect key share size
	ks = keyShareExtension{handshakeType: handshakeTypeServerHello}
	read, err = ks.Unmarshal(keyShareInvalid)
	assertError(t, err, "Unmarshaled a key share with a wrong-size key")
}

func TestSupportedGroupsMarshalUnmarshal(t *testing.T) {
	supportedGroups, _ := hex.DecodeString(supportedGroupsHex)

	// Test extension type
	assertEquals(t, supportedGroupsExtension{}.Type(), extensionTypeSupportedGroups)

	// Test successful marshal
	out, err := supportedGroupsIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid SupportedGroups")
	assertByteEquals(t, out, supportedGroups)

	// Test successful unmarshal
	sg := supportedGroupsExtension{}
	read, err := sg.Unmarshal(supportedGroups)
	assertNotError(t, err, "Failed to unmarshal valid SupportedGroups")
	assertDeepEquals(t, sg, supportedGroupsIn)
	assertEquals(t, read, len(supportedGroups))

	// Test unmarshal failure on truncated length
	sg = supportedGroupsExtension{}
	read, err = sg.Unmarshal(supportedGroups[:1])
	assertError(t, err, "Unmarshaled a SupportedGroups without a length")

	// Test unmarshal failure on truncated list
	sg = supportedGroupsExtension{}
	read, err = sg.Unmarshal(supportedGroups[:3])
	assertError(t, err, "Unmarshaled a SupportedGroups without a key share length")

	// Test unmarshal failure on odd list length
	supportedGroups[1]--
	sg = supportedGroupsExtension{}
	read, err = sg.Unmarshal(supportedGroups)
	assertError(t, err, "Unmarshaled a SupportedGroups with an odd-length list")
	supportedGroups[1]++
}

func TestSignatureAlgorithmsMarshalUnmarshal(t *testing.T) {
	signatureAlgorithms, _ := hex.DecodeString(signatureAlgorithmsHex)

	// Test extension type
	assertEquals(t, signatureAlgorithmsExtension{}.Type(), extensionTypeSignatureAlgorithms)

	// Test successful marshal
	out, err := signatureAlgorithmsIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid SignatureAlgorithms")
	assertByteEquals(t, out, signatureAlgorithms)

	// Test successful unmarshal
	sg := signatureAlgorithmsExtension{}
	read, err := sg.Unmarshal(signatureAlgorithms)
	assertNotError(t, err, "Failed to unmarshal valid SignatureAlgorithms")
	assertDeepEquals(t, sg, signatureAlgorithmsIn)
	assertEquals(t, read, len(signatureAlgorithms))

	// Test unmarshal failure on truncated length
	sg = signatureAlgorithmsExtension{}
	read, err = sg.Unmarshal(signatureAlgorithms[:1])
	assertError(t, err, "Unmarshaled a SignatureAlgorithms without a length")

	// Test unmarshal failure on truncated list
	sg = signatureAlgorithmsExtension{}
	read, err = sg.Unmarshal(signatureAlgorithms[:3])
	assertError(t, err, "Unmarshaled a SignatureAlgorithms without a key share length")

	// Test unmarshal failure on odd list length
	signatureAlgorithms[1]--
	sg = signatureAlgorithmsExtension{}
	read, err = sg.Unmarshal(signatureAlgorithms)
	assertError(t, err, "Unmarshaled a SignatureAlgorithms with an odd-length list")
	signatureAlgorithms[1]++
}

func TestPreSharedKeyMarshalUnmarshal(t *testing.T) {
	pskClient, _ := hex.DecodeString(pskClientHex)
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

	// Test finding an identity that is present
	id := []byte{1, 2, 3, 4}
	found := pskClientIn.HasIdentity(id)
	assert(t, found, "Failed to find present identity")

	// Test finding an identity that is not present
	id = []byte{1, 2, 4, 3}
	found = pskClientIn.HasIdentity(id)
	assert(t, !found, "Found a not-present identity")
}

func TestALPNMarshalUnmarshal(t *testing.T) {
	alpnValid, _ := hex.DecodeString(alpnValidHex)
	alpnTooShort, _ := hex.DecodeString(alpnTooShortHex)

	// Test extension type
	assertEquals(t, alpnExtension{}.Type(), extensionTypeALPN)

	// Test successful marshal
	out, err := alpnValidIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid ALPN extension")
	assertByteEquals(t, out, alpnValid)

	// Test successful unmarshal
	alpn := &alpnExtension{}
	read, err := alpn.Unmarshal(alpnValid)
	assertNotError(t, err, "Failed to unmarshal valid ALPN extension")
	assertDeepEquals(t, alpn, alpnValidIn)
	assertEquals(t, read, len(alpnValid))

	// Test unmarshal failure on data too short for the length
	alpn = &alpnExtension{}
	read, err = alpn.Unmarshal(alpnValid[:1])
	assertError(t, err, "Unmarshaled a ALPN extension that's too short for the length")

	// Test unmarshal failure on data shorter than the stated length
	alpn = &alpnExtension{}
	read, err = alpn.Unmarshal(alpnValid[:4])
	assertError(t, err, "Unmarshaled a ALPN extension that's shorter than the stated length")

	// Test unmarshal failure on data too short
	alpn = &alpnExtension{}
	read, err = alpn.Unmarshal(alpnTooShort)
	assertError(t, err, "Unmarshaled a ALPN extension with a too-long interior length")
}

func TestSupportedVersionsMarshalUnmarshal(t *testing.T) {
	supportedVersions, _ := hex.DecodeString(supportedVersionsHex)

	// Test extension type
	assertEquals(t, supportedVersionsExtension{}.Type(), extensionTypeSupportedVersions)

	// Test successful marshal
	out, err := supportedVersionsIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid SupportedVersions")
	assertByteEquals(t, out, supportedVersions)

	// Test successful unmarshal
	sv := supportedVersionsExtension{}
	read, err := sv.Unmarshal(supportedVersions)
	assertNotError(t, err, "Failed to unmarshal valid SupportedVersions")
	assertDeepEquals(t, sv, supportedVersionsIn)
	assertEquals(t, read, len(supportedVersions))

	// Test unmarshal failure on truncated length
	sv = supportedVersionsExtension{}
	read, err = sv.Unmarshal(supportedVersions[:1])
	assertError(t, err, "Unmarshaled a SupportedVersions without a length")

	// Test unmarshal failure on truncated list
	sv = supportedVersionsExtension{}
	read, err = sv.Unmarshal(supportedVersions[:3])
	assertError(t, err, "Unmarshaled a SupportedVersions without a key share length")

	// Test unmarshal failure on odd list length
	supportedVersions[0]--
	sv = supportedVersionsExtension{}
	read, err = sv.Unmarshal(supportedVersions)
	assertError(t, err, "Unmarshaled a SupportedVersions with an odd-length list")
	supportedVersions[0]++
}
