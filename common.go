package mint

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
	handshakeTypeSessionTicket       handshakeType = 4
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
// TODO
)

// enum {...} ExtensionType
type helloExtensionType uint16

const (
// TODO
)

// enum {...} NamedGroup
type namedGroup uint16

const (
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
