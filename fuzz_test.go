package mint

import (
	"encoding/hex"
	"math/rand"
	"testing"
)

var structs = []interface{}{
	// Handshake messages
	&clientHelloBody{},
	&serverHelloBody{},
	&finishedBody{verifyDataLen: 32},
	&encryptedExtensionsBody{},
	&certificateBody{},
	&certificateVerifyBody{},

	// Extensions
	&extension{},
	&extensionList{},
	new(serverNameExtension),
	&alpnExtension{},
	&keyShareExtension{HandshakeType: HandshakeTypeClientHello},
	&keyShareExtension{HandshakeType: HandshakeTypeHelloRetryRequest},
	&keyShareExtension{HandshakeType: HandshakeTypeServerHello},
	&supportedGroupsExtension{},
	&signatureAlgorithmsExtension{},
	&preSharedKeyExtension{HandshakeType: HandshakeTypeClientHello},
	&preSharedKeyExtension{HandshakeType: HandshakeTypeServerHello},
	&supportedVersionsExtension{},
}

var validHex = []string{
	// Handshake messages
	chValidHex,
	shValidHex,
	finValidHex,
	encExtValidHex,
	certValidHex,
	certVerifyValidHex,

	// Extensions
	extValidHex,
	extListValidHex,
	validExtensionTestCases[extensionTypeServerName].marshaledHex,
	validExtensionTestCases[extensionTypeALPN].marshaledHex,
	keyShareClientHex,
	keyShareHelloRetryHex,
	keyShareServerHex,
	validExtensionTestCases[extensionTypeSupportedGroups].marshaledHex,
	validExtensionTestCases[extensionTypeSignatureAlgorithms].marshaledHex,
	pskClientHex,
	pskServerHex,
	validExtensionTestCases[extensionTypeSupportedVersions].marshaledHex,
}

func randomBytes(n int, rand *rand.Rand) []byte {
	r := make([]byte, n)
	for i := 0; i < n; i++ {
		r[i] = byte(rand.Int31())
	}
	return r
}

// This just looks for crashes due to bounds errors etc.
func TestFuzz(t *testing.T) {
	rand := rand.New(rand.NewSource(0))
	for i, iface := range structs {
		m := iface.(unmarshaler)

		// Provide random data
		for j := 0; j < 100; j++ {
			len := rand.Intn(1024)
			bytes := randomBytes(len, rand)
			m.Unmarshal(bytes)
		}

		// Provide partially valid data
		valid, _ := hex.DecodeString(validHex[i])
		random := randomBytes(10*len(valid), rand)
		for cut := 0; cut < len(valid)-1; cut++ {
			testCase := append(valid[:cut], random...)
			m.Unmarshal(testCase)
		}
	}
}
