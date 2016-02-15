package mint

import (
	"fmt"
)

const (
	fixedHelloBodyLength = 39
	maxCipherSuites      = 1 << 15
	extensionHeaderLen   = 4
	maxExtensionDataLen  = (1 << 16) - 1
	maxExtensionsLen     = (1 << 16) - 1
)

type Marshaler interface {
	Marshal() ([]byte, error)
}

type Unmarshaler interface {
	Unmarshal([]byte) (int, error)
}

// struct {
//     ExtensionType extension_type;
//     opaque extension_data<0..2^16-1>;
// } Extension;
type extension struct {
	extensionType helloExtensionType
	extensionData []byte
}

func (ext extension) Marshal() ([]byte, error) {
	if len(ext.extensionData) > maxExtensionDataLen {
		return nil, fmt.Errorf("tls.extension: Extension data too long")
	}

	extLen := len(ext.extensionData)
	base := []byte{byte(ext.extensionType >> 8), byte(ext.extensionType),
		byte(extLen >> 8), byte(extLen)}
	return append(base, ext.extensionData...), nil
}

func (ext *extension) Unmarshal(data []byte) (int, error) {
	if len(data) < extensionHeaderLen {
		return 0, fmt.Errorf("tls.extension: Malformed extension; too short")
	}

	extDataLen := (int(data[2]) << 8) + int(data[3])
	if len(data) < extensionHeaderLen+extDataLen {
		return 0, fmt.Errorf("tls.extension: Malformed extension; incorrect length")
	}

	ext.extensionType = (helloExtensionType(data[0]) << 8) + helloExtensionType(data[1])
	ext.extensionData = data[extensionHeaderLen : extDataLen+extensionHeaderLen]
	return extensionHeaderLen + extDataLen, nil
}

// NB: Can't be generic, but use this as a pattern for marshaling
// vectors of things as required.
func marshalExtensionList(extensions []extension) ([]byte, error) {
	data := []byte{0x00, 0x00}

	for _, ext := range extensions {
		extBytes, err := ext.Marshal()
		if err != nil {
			return nil, err
		}

		data = append(data, extBytes...)
	}

	extensionsLen := len(data) - 2
	if extensionsLen > maxExtensionsLen {
		return nil, fmt.Errorf("tls.extensionlist: Extensions too long")
	}
	data[0] = byte(extensionsLen >> 8)
	data[1] = byte(extensionsLen)

	return data, nil
}

// NB: Can't be generic, but use this as a pattern for unmarshaling
// vectors of things as required.
func unmarshalExtensionList(data []byte) ([]extension, int, error) {
	if len(data) < 2 {
		return nil, 0, fmt.Errorf("tls.extensionlist: Malformed extension list; too short")
	}
	extLen := (int(data[0]) << 8) + int(data[1])

	if len(data) < 2+extLen {
		return nil, 0, fmt.Errorf("tls.extensionlist: Malformed extension list; incorrect extensions length")
	}
	extData := data[2 : extLen+2]

	var ext extension
	extensions := []extension{}
	read := 0
	for read < extLen {
		n, err := ext.Unmarshal(extData[read:])
		if err != nil {
			return nil, 0, err
		}

		extensions = append(extensions, ext)
		read += n
	}

	return extensions, 2 + extLen, nil
}

// struct {
//     ProtocolVersion client_version = { 3, 4 };    /* TLS v1.3 */
//     Random random;
//     opaque legacy_session_id<0..32>;              /* MUST be [] */
//     CipherSuite cipher_suites<2..2^16-2>;
//     opaque legacy_compression_methods<1..2^8-1>;  /* MUST be [0] */
//     Extension extensions<0..2^16-1>;
// } ClientHello;
type clientHelloBody struct {
	// Omitted: clientVersion
	// Omitted: legacySessionID
	// Omitted: legacyCompressionMethods
	random       [32]byte
	cipherSuites []cipherSuite
	extensions   []extension
}

func (ch clientHelloBody) Marshal() ([]byte, error) {
	baseBodyLength := fixedHelloBodyLength + 2*len(ch.cipherSuites)
	body := make([]byte, baseBodyLength)
	for i := range body {
		body[i] = 0
	}

	// Write base fields that are non-zero
	body[0] = 0x03
	body[1] = 0x04
	copy(body[2:34], ch.random[:])

	if len(ch.cipherSuites) == 0 {
		return nil, fmt.Errorf("tls.clienthello: No ciphersuites provided")
	}
	if len(ch.cipherSuites) > maxCipherSuites {
		return nil, fmt.Errorf("tls.clienthello: Too many ciphersuites")
	}
	cipherSuitesLen := 2 * len(ch.cipherSuites)
	body[35] = byte(cipherSuitesLen >> 8)
	body[36] = byte(cipherSuitesLen)
	for i, suite := range ch.cipherSuites {
		body[2*i+37] = byte(suite >> 8)
		body[2*i+38] = byte(suite)
	}
	body[37+cipherSuitesLen] = 0x01

	extensions, err := marshalExtensionList(ch.extensions)
	if err != nil {
		return nil, err
	}

	return append(body, extensions...), nil
}

func (ch *clientHelloBody) Unmarshal(data []byte) (int, error) {
	if len(data) < fixedHelloBodyLength {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; too short")
	}

	if data[0] != 0x03 || data[1] != 0x04 {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; unsupported version")
	}

	copy(ch.random[:], data[2:34])

	// Since we only do 1.3, we can enforce that the session ID MUST be empty
	if data[34] != 0x00 {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; non-empty session ID")
	}

	cipherSuitesLen := (int(data[35]) << 8) + int(data[36])
	if len(data) < 37+cipherSuitesLen {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; too many ciphersuites")
	}
	if cipherSuitesLen%2 != 0 {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; odd ciphersuites size")
	}
	ch.cipherSuites = make([]cipherSuite, cipherSuitesLen/2)
	for i := 0; i < cipherSuitesLen/2; i++ {
		ch.cipherSuites[i] = (cipherSuite(data[2*i+37]) << 8) + cipherSuite(data[2*i+38])
	}

	// Since we only do 1.3, we can enforce that the compression methods
	if len(data) < 37+cipherSuitesLen+2 {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; no compression methods")
	}
	if data[37+cipherSuitesLen] != 0x01 || data[37+cipherSuitesLen+1] != 0x00 {
		return 0, fmt.Errorf("tls.clienthello: Malformed ClientHello; incorrect compression methods")
	}

	extensions, extLen, err := unmarshalExtensionList(data[37+cipherSuitesLen+2:])
	if err != nil {
		return 0, err
	}
	ch.extensions = extensions

	return 37 + cipherSuitesLen + 2 + extLen, nil
}
