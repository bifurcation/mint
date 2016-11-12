package mint

var (
	supportedVersion uint16 = 0x7f12 // draft-18

	// Flags for some minor compat issues
	allowWrongVersionNumber = true
	allowPKCS1              = true
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
type CipherSuite uint16

const (
	TLS_AES_128_GCM_SHA256       CipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384       CipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 CipherSuite = 0x1303
	TLS_AES_128_CCM_SHA256       CipherSuite = 0x1304
	TLS_AES_256_CCM_8_SHA256     CipherSuite = 0x1305
)

// enum {...} SignatureScheme
type signatureScheme uint16

const (
	// RSASSA-PKCS1-v1_5 algorithms
	signatureSchemeRSA_PKCS1_SHA1   signatureScheme = 0x0201
	signatureSchemeRSA_PKCS1_SHA256 signatureScheme = 0x0401
	signatureSchemeRSA_PKCS1_SHA384 signatureScheme = 0x0501
	signatureSchemeRSA_PKCS1_SHA512 signatureScheme = 0x0601
	// ECDSA algorithms
	signatureSchemeECDSA_P256_SHA256 signatureScheme = 0x0403
	signatureSchemeECDSA_P384_SHA384 signatureScheme = 0x0503
	signatureSchemeECDSA_P521_SHA512 signatureScheme = 0x0603
	// RSASSA-PSS algorithms
	signatureSchemeRSA_PSS_SHA256 signatureScheme = 0x0804
	signatureSchemeRSA_PSS_SHA384 signatureScheme = 0x0805
	signatureSchemeRSA_PSS_SHA512 signatureScheme = 0x0806
	// EdDSA algorithms
	signatureSchemeEd25519 signatureScheme = 0x0807
	signatureSchemeEd448   signatureScheme = 0x0808
)

// enum {...} ExtensionType
type extensionType uint16

const (
	extensionTypeUnknown             extensionType = 0xffff
	extensionTypeServerName          extensionType = 0
	extensionTypeSupportedGroups     extensionType = 10
	extensionTypeSignatureAlgorithms extensionType = 13
	extensionTypeALPN                extensionType = 16
	extensionTypeKeyShare            extensionType = 40
	extensionTypePreSharedKey        extensionType = 41
	extensionTypeEarlyData           extensionType = 42
	extensionTypeSupportedVersions   extensionType = 43
	extensionTypeCookie              extensionType = 44
	extensionTypePSKKeyExchangeModes extensionType = 45
	extensionTypeTicketEarlyDataInfo extensionType = 46
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

// enum {...} PskKeyExchangeMode;
type pskKeyExchangeMode uint8

const (
	pskModeKE    pskKeyExchangeMode = 0
	pskModeDHEKE pskKeyExchangeMode = 1
)

type marshaler interface {
	Marshal() ([]byte, error)
}

type unmarshaler interface {
	Unmarshal([]byte) (int, error)
}
