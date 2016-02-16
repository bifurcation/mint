package mint

import (
	"fmt"
)

const (
	fixedClientHelloBodyLen = 39
	fixedServerHelloBodyLen = 36
	maxCipherSuites         = 1 << 15
	extensionHeaderLen      = 4
	maxExtensionDataLen     = (1 << 16) - 1
	maxExtensionsLen        = (1 << 16) - 1
)

type handshakeMessageBody interface {
	Type() handshakeType
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (int, error)
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

func (ch clientHelloBody) Type() handshakeType {
	return handshakeTypeClientHello
}

func (ch clientHelloBody) Marshal() ([]byte, error) {
	baseBodyLen := fixedClientHelloBodyLen + 2*len(ch.cipherSuites)
	body := make([]byte, baseBodyLen)
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
	if len(data) < fixedClientHelloBodyLen {
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

// struct {
//     ProtocolVersion server_version;
//     Random random;
//     CipherSuite cipher_suite;
//     select (extensions_present) {
//         case false:
//             struct {};
//         case true:
//             Extension extensions<0..2^16-1>;
//     };
// } ServerHello;
type serverHelloBody struct {
	// Omitted: server_version
	random      [32]byte
	cipherSuite cipherSuite
	extensions  []extension
}

func (sh serverHelloBody) Type() handshakeType {
	return handshakeTypeServerHello
}

func (sh serverHelloBody) Marshal() ([]byte, error) {
	body := make([]byte, fixedServerHelloBodyLen)

	body[0] = 0x03
	body[1] = 0x04

	copy(body[2:34], sh.random[:])

	body[34] = byte(sh.cipherSuite >> 8)
	body[35] = byte(sh.cipherSuite)

	if len(sh.extensions) > 0 {
		extensions, err := marshalExtensionList(sh.extensions)
		if err != nil {
			return nil, err
		}
		body = append(body, extensions...)
	}

	return body, nil
}

func (sh *serverHelloBody) Unmarshal(data []byte) (int, error) {
	if len(data) < fixedServerHelloBodyLen {
		return 0, fmt.Errorf("tls.serverhello: Malformed ServerHello; too short")
	}

	if data[0] != 0x03 || data[1] != 0x04 {
		return 0, fmt.Errorf("tls.serverhello: Malformed ServerHello; unsupported version")
	}

	copy(sh.random[:], data[2:34])
	sh.cipherSuite = (cipherSuite(data[34]) << 8) + cipherSuite(data[35])

	read := fixedServerHelloBodyLen
	if len(data) > fixedServerHelloBodyLen {
		extensions, extLen, err := unmarshalExtensionList(data[fixedServerHelloBodyLen:])
		if err != nil {
			return 0, err
		}

		sh.extensions = extensions
		read += extLen
	} else {
		sh.extensions = []extension{}
	}

	return read, nil
}

// struct {
//     opaque verify_data[verify_data_length];
// } Finished;
//
// verifyDataLen is not a field in the TLS struct, but we add it here so
// that calling code can tell us how much data to expect when we marshal /
// unmarshal.  (We could add this to the marshal/unmarshal methods, but let's
// try to keep the signature consistent for now.)
type finishedBody struct {
	verifyDataLen int
	verifyData    []byte
}

func (fin finishedBody) Type() handshakeType {
	return handshakeTypeFinished
}

func (fin finishedBody) Marshal() ([]byte, error) {
	if len(fin.verifyData) != fin.verifyDataLen {
		return nil, fmt.Errorf("tls.finished: data length mismatch")
	}

	body := make([]byte, len(fin.verifyData))
	copy(body, fin.verifyData)
	return body, nil
}

func (fin *finishedBody) Unmarshal(data []byte) (int, error) {
	if len(data) < fin.verifyDataLen {
		return 0, fmt.Errorf("tls.finished: Malformed finished; too short")
	}

	fin.verifyData = make([]byte, fin.verifyDataLen)
	copy(fin.verifyData, data[:fin.verifyDataLen])
	return fin.verifyDataLen, nil
}
