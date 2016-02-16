package mint

import (
	"fmt"
)

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

type extensionList []extension

// NB: Can't be generic, but use this as a pattern for marshaling
// vectors of things as required.
func (el extensionList) Marshal() ([]byte, error) {
	data := []byte{0x00, 0x00}

	for _, ext := range el {
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
func (el *extensionList) Unmarshal(data []byte) (int, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("tls.extensionlist: Malformed extension list; too short")
	}
	extLen := (int(data[0]) << 8) + int(data[1])

	if len(data) < 2+extLen {
		return 0, fmt.Errorf("tls.extensionlist: Malformed extension list; incorrect extensions length")
	}
	extData := data[2 : extLen+2]

	var ext extension
	*el = []extension{}
	read := 0
	for read < extLen {
		n, err := ext.Unmarshal(extData[read:])
		if err != nil {
			return 0, err
		}

		*el = append(*el, ext)
		read += n
	}

	return 2 + extLen, nil
}

func (el *extensionList) Add(extType helloExtensionType, src marshaler) error {
	data, err := src.Marshal()
	if err != nil {
		return err
	}

	*el = append(*el, extension{
		extensionType: extType,
		extensionData: data,
	})
	return nil
}

func (el extensionList) Find(target helloExtensionType, dst unmarshaler) bool {
	for _, ext := range el {
		if ext.extensionType == target {
			_, err := dst.Unmarshal(ext.extensionData)
			return err == nil
		}
	}
	return false
}

// struct {
//     NamedGroup group;
//     opaque key_exchange<1..2^16-1>;
// } KeyShareEntry;
type keyShare struct {
	group       namedGroup
	keyExchange []byte
}

// struct {
//     select (role) {
//         case client:
//             KeyShareEntry client_shares<4..2^16-1>;
//
//         case server:
//             KeyShareEntry server_share;
//     }
// } KeyShare;
type keyShareExtension struct {
	roleIsServer bool
	shares       []keyShare
}

const (
	fixedKeyShareLen = 4
)

func (ks keyShareExtension) Marshal() ([]byte, error) {
	if ks.roleIsServer && len(ks.shares) > 1 {
		return nil, fmt.Errorf("tls.keyshare: Server can only send one key share")
	}

	shares := []byte{}
	for _, share := range ks.shares {
		keyLen := len(share.keyExchange)
		keyLenForGroup := keyExchangeSizeFromNamedGroup(share.group)
		if keyLenForGroup > 0 && keyLen != keyLenForGroup {
			return nil, fmt.Errorf("tls.keyshare: Key exchange value has the wrong size")
		}

		header := []byte{byte(share.group >> 8), byte(share.group), byte(keyLen >> 8), byte(keyLen)}
		shares = append(shares, header...)
		shares = append(shares, share.keyExchange...)
	}

	if !ks.roleIsServer {
		dataLen := len(shares)
		header := []byte{byte(dataLen >> 8), byte(dataLen)}
		shares = append(header, shares...)
	}

	return shares, nil
}

func (ks *keyShareExtension) Unmarshal(data []byte) (int, error) {
	read := 0
	totalLen := len(data)
	if !ks.roleIsServer {
		if len(data) < 2 {
			return 0, fmt.Errorf("tls.keyshare: Client key share extension too short")
		}
		read = 2
		totalLen = (int(data[0]) << 8) + int(data[1])
	}

	for read < totalLen {
		if len(data[read:]) < fixedKeyShareLen {
			return 0, fmt.Errorf("tls.keyshare: Key share extension too short")
		}

		share := keyShare{}
		share.group = (namedGroup(data[read]) << 8) + namedGroup(data[read+1])
		keyLen := (int(data[read+2]) << 8) + int(data[read+3])
		if len(data[read+4:]) < keyLen {
			return 0, fmt.Errorf("tls.keyshare: Key share extension too short for key")
		}

		keyLenForGroup := keyExchangeSizeFromNamedGroup(share.group)
		if keyLenForGroup > 0 && keyLen != keyLenForGroup {
			return 0, fmt.Errorf("tls.keyshare: Key exchange value has the wrong size")
		}

		share.keyExchange = make([]byte, keyLen)
		copy(share.keyExchange, data[read+4:read+4+keyLen])
		ks.shares = append(ks.shares, share)

		read += 4 + keyLen

		if ks.roleIsServer {
			break
		}
	}

	return read, nil
}
