package mint

import (
	"math/rand"
	"testing"
)

var structs = []interface{}{
	// Handshake messages
	&ClientHelloBody{},
	&ServerHelloBody{},
	&FinishedBody{VerifyDataLen: 32},
	&EncryptedExtensionsBody{},
	&CertificateBody{},
	&CertificateVerifyBody{},

	// Extensions
	&Extension{},
	&ExtensionList{},
	new(ServerNameExtension),
	&ALPNExtension{},
	&KeyShareExtension{HandshakeType: HandshakeTypeClientHello},
	&KeyShareExtension{HandshakeType: HandshakeTypeHelloRetryRequest},
	&KeyShareExtension{HandshakeType: HandshakeTypeServerHello},
	&SupportedGroupsExtension{},
	&SignatureAlgorithmsExtension{},
	&PreSharedKeyExtension{HandshakeType: HandshakeTypeClientHello},
	&PreSharedKeyExtension{HandshakeType: HandshakeTypeServerHello},
	&SupportedVersionsExtension{},
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
	validExtensionTestCases[ExtensionTypeServerName].marshaledHex,
	validExtensionTestCases[ExtensionTypeALPN].marshaledHex,
	keyShareClientHex,
	keyShareHelloRetryHex,
	keyShareServerHex,
	validExtensionTestCases[ExtensionTypeSupportedGroups].marshaledHex,
	validExtensionTestCases[ExtensionTypeSignatureAlgorithms].marshaledHex,
	pskClientHex,
	pskServerHex,
	validExtensionTestCases[ExtensionTypeSupportedVersions].marshaledHex,
}

func randomBytes(n int, rand *rand.Rand) []byte {
	r := make([]byte, n)
	for i := 0; i < n; i++ {
		r[i] = byte(rand.Int31())
	}
	return r
}

type unmarshaler interface {
	Unmarshal([]byte) (int, error)
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
		valid := unhex(validHex[i])
		random := randomBytes(10*len(valid), rand)
		for cut := 0; cut < len(valid)-1; cut++ {
			testCase := append(valid[:cut], random...)
			m.Unmarshal(testCase)
		}
	}
}
