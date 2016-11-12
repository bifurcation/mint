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
type SignatureScheme uint16

const (
	// RSASSA-PKCS1-v1_5 algorithms
	RSA_PKCS1_SHA1   SignatureScheme = 0x0201
	RSA_PKCS1_SHA256 SignatureScheme = 0x0401
	RSA_PKCS1_SHA384 SignatureScheme = 0x0501
	RSA_PKCS1_SHA512 SignatureScheme = 0x0601
	// ECDSA algorithms
	ECDSA_P256_SHA256 SignatureScheme = 0x0403
	ECDSA_P384_SHA384 SignatureScheme = 0x0503
	ECDSA_P521_SHA512 SignatureScheme = 0x0603
	// RSASSA-PSS algorithms
	RSA_PSS_SHA256 SignatureScheme = 0x0804
	RSA_PSS_SHA384 SignatureScheme = 0x0805
	RSA_PSS_SHA512 SignatureScheme = 0x0806
	// EdDSA algorithms
	Ed25519 SignatureScheme = 0x0807
	Ed448   SignatureScheme = 0x0808
)

// enum {...} ExtensionType
type extensionType uint16

const (
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
type NamedGroup uint16

const (
	// Elliptic Curve Groups.
	P256 NamedGroup = 23
	P384 NamedGroup = 24
	P521 NamedGroup = 25
	// ECDH functions.
	X25519 NamedGroup = 29
	X448   NamedGroup = 30
	// Finite field groups.
	FFDHE2048 NamedGroup = 256
	FFDHE3072 NamedGroup = 257
	FFDHE4096 NamedGroup = 258
	FFDHE6144 NamedGroup = 259
	FFDHE8192 NamedGroup = 250
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
