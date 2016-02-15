package mint

//   enum {...} ContentType;
type recordType byte

const (
	recordTypeAlert           recordType = 21
	recordTypeHandshake       recordType = 22
	recordTypeApplicationData recordType = 23
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
