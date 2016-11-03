package mint

var (
	supportedVersion uint16 = 0x7f12 // draft-18

	// Flags for some minor compat issues
	allowEmptyEncryptedExtensions = false
	allowWrongVersionNumber       = true
	allowPKCS1                    = true
)

// enum {...} ContentType;
type recordType byte

const (
	recordTypeAlert           recordType = 21
	recordTypeHandshake       recordType = 22
	recordTypeApplicationData recordType = 23
)

// enum {...} HandshakeType;
type handshakeType byte

const (
	// Omitted: *_RESERVED
	handshakeTypeClientHello         handshakeType = 1
	handshakeTypeServerHello         handshakeType = 2
	handshakeTypeNewSessionTicket    handshakeType = 4
	handshakeTypeHelloRetryRequest   handshakeType = 6
	handshakeTypeEncryptedExtensions handshakeType = 8
	handshakeTypeCertificate         handshakeType = 11
	handshakeTypeCertificateRequest  handshakeType = 13
	handshakeTypeCertificateVerify   handshakeType = 15
	handshakeTypeServerConfiguration handshakeType = 17
	handshakeTypeFinished            handshakeType = 20
	handshakeTypeKeyUpdate           handshakeType = 24
)

// uint8 CipherSuite[2];
type cipherSuite uint16

const (
	TLS_AES_128_GCM_SHA256       cipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384       cipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 cipherSuite = 0x1303
	TLS_AES_128_CCM_SHA256       cipherSuite = 0x1304
	TLS_AES_256_CCM_8_SHA256     cipherSuite = 0x1305
)

// enum {...} HashAlgorithm
type hashAlgorithm uint8

const (
	// Omitted: *_RESERVED
	hashAlgorithmSHA1   hashAlgorithm = 2
	hashAlgorithmSHA256 hashAlgorithm = 4
	hashAlgorithmSHA384 hashAlgorithm = 5
	hashAlgorithmSHA512 hashAlgorithm = 6
)

// enum {...} SignatureAlgorithm
type signatureAlgorithm uint8

const (
	// Omitted: *_RESERVED
	signatureAlgorithmRSA    signatureAlgorithm = 1
	signatureAlgorithmDSA    signatureAlgorithm = 2
	signatureAlgorithmECDSA  signatureAlgorithm = 3
	signatureAlgorithmRSAPSS signatureAlgorithm = 4
	signatureAlgorithmEdDSA  signatureAlgorithm = 5
)

// struct {
//     HashAlgorithm hash;
//     SignatureAlgorithm signature;
// } SignatureAndHashAlgorithm;
//
type signatureAndHashAlgorithm struct {
	hash      hashAlgorithm
	signature signatureAlgorithm
}

// enum {...} ExtensionType
type helloExtensionType uint16

const (
	extensionTypeUnknown             helloExtensionType = 0xffff
	extensionTypeServerName          helloExtensionType = 0
	extensionTypeSupportedGroups     helloExtensionType = 10
	extensionTypeSignatureAlgorithms helloExtensionType = 13
	extensionTypeALPN                helloExtensionType = 16
	extensionTypeKeyShare            helloExtensionType = 40
	extensionTypePreSharedKey        helloExtensionType = 41
	extensionTypeEarlyData           helloExtensionType = 42
	extensionTypeSupportedVersions   helloExtensionType = 43
	extensionTypeDraftVersion        helloExtensionType = 0xff02 // Required for NSS
)

// enum {...} NamedGroup
type namedGroup uint16

const (
	namedGroupUnknown namedGroup = 0
	// Elliptic Curve Groups.
	namedGroupP256 namedGroup = 23
	namedGroupP384 namedGroup = 24
	namedGroupP521 namedGroup = 25
	// ECDH functions.
	namedGroupX25519 namedGroup = 29
	namedGroupX448   namedGroup = 30
	// Signature-only curves.
	namedGroupEd25519 namedGroup = 31
	namedGroupEd448   namedGroup = 32
	// Finite field groups.
	namedGroupFF2048 namedGroup = 256
	namedGroupFF3072 namedGroup = 257
	namedGroupFF4096 namedGroup = 258
	namedGroupFF6144 namedGroup = 259
	namedGroupFF8192 namedGroup = 250
)

type marshaler interface {
	Marshal() ([]byte, error)
}

type unmarshaler interface {
	Unmarshal([]byte) (int, error)
}
