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
	p256             = append([]byte{byte(len256 - 1)}, bytes.Repeat([]byte{0}, len256-1)...)
	p521             = append([]byte{byte(len521 - 1)}, bytes.Repeat([]byte{0}, len521-1)...)
	keyShareClientIn = &keyShareExtension{
		roleIsServer: false,
		shares: []keyShare{
			keyShare{group: namedGroupP256, keyExchange: p256},
			keyShare{group: namedGroupP521, keyExchange: p521},
		},
	}
	keyShareServerIn = &keyShareExtension{
		roleIsServer: true,
		shares: []keyShare{
			keyShare{group: namedGroupP256, keyExchange: p256},
		},
	}
	keyShareInvalidIn = &keyShareExtension{
		roleIsServer: true,
		shares: []keyShare{
			keyShare{group: namedGroupP256, keyExchange: []byte{0}},
		},
	}
	keyShareClientHex = "00d0" + "00170042" + hex.EncodeToString(p256) +
		"00190086" + hex.EncodeToString(p521)
	keyShareServerHex  = "00170042" + hex.EncodeToString(p256)
	keyShareInvalidHex = "0017000100"

	// Add/Find test cases
	keyShareServerRaw, _  = hex.DecodeString(keyShareServerHex)
	keyShareInvalidRaw, _ = hex.DecodeString(keyShareInvalidHex)
	extListKeyShareIn     = extensionList{
		extension{
			extensionType: extensionTypeKeyShare,
			extensionData: keyShareServerRaw,
		},
	}
	extListInvalidIn = extensionList{
		extension{
			extensionType: extensionTypeKeyShare,
			extensionData: keyShareInvalidRaw,
		},
	}

	// SupportedGroups test cases
	supportedGroupsIn = supportedGroupsExtension{
		groups: []namedGroup{namedGroupP256, namedGroupP384},
	}
	supportedGroupsHex = "000400170018"

	// SignatureAlgorithms test cases
	signatureAlgorithmsIn = signatureAlgorithmsExtension{
		algorithms: []signatureAndHashAlgorithm{
			signatureAndHashAlgorithm{
				hash:      hashAlgorithmSHA256,
				signature: signatureAlgorithmRSAPSS,
			},
			signatureAndHashAlgorithm{
				hash:      hashAlgorithmSHA512,
				signature: signatureAlgorithmECDSA,
			},
		},
	}
	signatureAlgorithmsHex = "000404040603"

	// SNI test cases
	serverNameRaw = "example.com"
	serverNameIn  = serverNameExtension(serverNameRaw)
	serverNameHex = "000e00000b" + hex.EncodeToString([]byte(serverNameRaw))

	// DraftVersion test cases
	draftVersionIn  = draftVersionExtension{0x2030}
	draftVersionHex = "2030"
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
	ks := keyShareExtension{roleIsServer: true}
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
	read, err := sni.Unmarshal(serverName)
	assertNotError(t, err, "Failed to unmarshal valid ServerName")
	assertDeepEquals(t, sni, serverNameIn)
	assertEquals(t, read, len(serverName))

	// Test unmarshal failure on truncated header
	read, err = sni.Unmarshal(serverName[:4])
	assertError(t, err, "Unmarshaled a ServerName without a header")

	// Test unmarshal failure on truncated name
	read, err = sni.Unmarshal(serverName[:7])
	assertError(t, err, "Unmarshaled a ServerName without a full name")

	// Test unmarshal failure on length mismatch
	serverName[4]++
	read, err = sni.Unmarshal(serverName)
	assertError(t, err, "Unmarshaled a ServerName with inconsistent lengths")
	serverName[4]--

	// Test unmarshal failure on odd list length
	serverName[2]++
	read, err = sni.Unmarshal(serverName)
	assertError(t, err, "Unmarshaled a ServerName that was not a host_name")
	serverName[2]--
}

func TestKeyShareMarshalUnmarshal(t *testing.T) {
	keyShareClient, _ := hex.DecodeString(keyShareClientHex)
	keyShareServer, _ := hex.DecodeString(keyShareServerHex)
	keyShareInvalid, _ := hex.DecodeString(keyShareInvalidHex)

	// Test extension type
	assertEquals(t, keyShareExtension{}.Type(), extensionTypeKeyShare)

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

	// Test marshal failure on an incorrect key share size
	out, err = keyShareInvalidIn.Marshal()
	assertError(t, err, "Marshaled a key share with a wrong-size key")

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

	// Test unmarshal failure on truncated length (client)
	ks = keyShareExtension{roleIsServer: false}
	read, err = ks.Unmarshal(keyShareClient[:1])
	assertError(t, err, "Unmarshaled a KeyShare without a length")

	// Test unmarshal failure on truncated keyShare length
	ks = keyShareExtension{roleIsServer: false}
	read, err = ks.Unmarshal(keyShareClient[:5])
	assertError(t, err, "Unmarshaled a KeyShare without a key share length")

	// Test unmarshal failure on truncated keyShare value
	ks = keyShareExtension{roleIsServer: false}
	read, err = ks.Unmarshal(keyShareClient[:7])
	assertError(t, err, "Unmarshaled a KeyShare without a truncated key share value")

	// Test unmarshal failure on an incorrect key share size
	ks = keyShareExtension{roleIsServer: true}
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

func TestDraftVersionMarshalUnmarshal(t *testing.T) {
	draftVersion, _ := hex.DecodeString(draftVersionHex)

	// Test extension type
	assertEquals(t, draftVersionExtension{}.Type(), extensionTypeDraftVersion)

	// Test successful marshal
	out, err := draftVersionIn.Marshal()
	assertNotError(t, err, "Failed to marshal valid DraftVersion")
	assertByteEquals(t, out, draftVersion)

	// Test successful unmarshal
	dv := draftVersionExtension{}
	read, err := dv.Unmarshal(draftVersion)
	assertNotError(t, err, "Failed to unmarshal valid DraftVersion")
	assertDeepEquals(t, dv, draftVersionIn)
	assertEquals(t, read, len(draftVersion))

	// Test unmarshal failure on wrong data length
	dv = draftVersionExtension{}
	read, err = dv.Unmarshal(draftVersion[:1])
	assertError(t, err, "Unmarshaled a DraftVersion with the wrong length")
}
