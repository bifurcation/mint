package mint

import (
	"bytes"
	"fmt"

	"github.com/bifurcation/mint/syntax"
)

type extensionBody interface {
	Type() helloExtensionType
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (int, error)
}

// struct {
//     ExtensionType extension_type;
//     opaque extension_data<0..2^16-1>;
// } Extension;
type extension struct {
	ExtensionType helloExtensionType
	ExtensionData []byte `tls:"head=2"`
}

func (ext extension) Marshal() ([]byte, error) {
	return syntax.Marshal(ext)
}

func (ext *extension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, ext)
}

type extensionList []extension

type extensionListInner struct {
	List []extension `tls:"head=2"`
}

func (el extensionList) Marshal() ([]byte, error) {
	return syntax.Marshal(extensionListInner{el})
}

func (el *extensionList) Unmarshal(data []byte) (int, error) {
	var list extensionListInner
	read, err := syntax.Unmarshal(data, &list)
	if err != nil {
		return 0, err
	}

	*el = list.List
	return read, nil
}

func (el *extensionList) Add(src extensionBody) error {
	data, err := src.Marshal()
	if err != nil {
		return err
	}

	*el = append(*el, extension{
		ExtensionType: src.Type(),
		ExtensionData: data,
	})
	return nil
}

func (el extensionList) Find(dst extensionBody) bool {
	for _, ext := range el {
		if ext.ExtensionType == dst.Type() {
			_, err := dst.Unmarshal(ext.ExtensionData)
			return err == nil
		}
	}
	return false
}

// struct {
//     NameType name_type;
//     select (name_type) {
//         case host_name: HostName;
//     } name;
// } ServerName;
//
// enum {
//     host_name(0), (255)
// } NameType;
//
// opaque HostName<1..2^16-1>;
//
// struct {
//     ServerName server_name_list<1..2^16-1>
// } ServerNameList;
//
// But we only care about the case where there's a single DNS hostname.  We
// will never create anything else, and throw if we receive something else
//
//      2         1          2
// | listLen | NameType | nameLen | name |
type serverNameExtension string

type serverNameInner struct {
	NameType uint8
	HostName []byte `tls:"head=2,min=1"`
}

type serverNameListInner struct {
	ServerNameList []serverNameInner `tls:"head=2,min=1"`
}

func (sni serverNameExtension) Type() helloExtensionType {
	return extensionTypeServerName
}

func (sni serverNameExtension) Marshal() ([]byte, error) {
	list := serverNameListInner{
		ServerNameList: []serverNameInner{{
			NameType: 0x00, // host_name
			HostName: []byte(sni),
		}},
	}

	return syntax.Marshal(list)
}

func (sni *serverNameExtension) Unmarshal(data []byte) (int, error) {
	var list serverNameListInner
	read, err := syntax.Unmarshal(data, &list)
	if err != nil {
		return 0, err
	}

	if len(list.ServerNameList) == 0 {
		return 0, fmt.Errorf("tls.servername: No name provided")
	}

	if nameType := list.ServerNameList[0].NameType; nameType != 0x00 {
		return 0, fmt.Errorf("tls.servername: Unsupported name type [%x]", nameType)
	}

	*sni = serverNameExtension(list.ServerNameList[0].HostName)
	return read, nil
}

// struct {
//     NamedGroup group;
//     opaque key_exchange<1..2^16-1>;
// } KeyShareEntry;
//
// struct {
//     select (Handshake.msg_type) {
//         case client_hello:
//             KeyShareEntry client_shares<0..2^16-1>;
//
//         case hello_retry_request:
//             NamedGroup selected_group;
//
//         case server_hello:
//             KeyShareEntry server_share;
//     };
// } KeyShare;
type keyShareEntry struct {
	Group       namedGroup
	KeyExchange []byte `tls:"head=2,min=1"`
}

func (kse keyShareEntry) sizeValid() bool {
	return len(kse.KeyExchange) == keyExchangeSizeFromNamedGroup(kse.Group)
}

type keyShareExtension struct {
	handshakeType handshakeType
	selectedGroup namedGroup
	shares        []keyShareEntry
}

type keyShareClientHelloInner struct {
	ClientShares []keyShareEntry `tls:"head=2,min=0"`
}
type keyShareHelloRetryInner struct {
	SelectedGroup namedGroup
}
type keyShareServerHelloInner struct {
	ServerShare keyShareEntry
}

func (ks keyShareExtension) Type() helloExtensionType {
	return extensionTypeKeyShare
}

func (ks keyShareExtension) Marshal() ([]byte, error) {
	switch ks.handshakeType {
	case handshakeTypeClientHello:
		for _, share := range ks.shares {
			if !share.sizeValid() {
				return nil, fmt.Errorf("tls.keyshare: Key share has wrong size for group")
			}
		}
		return syntax.Marshal(keyShareClientHelloInner{ks.shares})

	case handshakeTypeHelloRetryRequest:
		if len(ks.shares) > 0 {
			return nil, fmt.Errorf("tls.keyshare: Key shares not allowed for HelloRetryRequest")
		}

		return syntax.Marshal(keyShareHelloRetryInner{ks.selectedGroup})

	case handshakeTypeServerHello:
		if len(ks.shares) > 1 {
			return nil, fmt.Errorf("tls.keyshare: Server can only send one key share")
		}

		if !ks.shares[0].sizeValid() {
			return nil, fmt.Errorf("tls.keyshare: Key share has wrong size for group")
		}

		return syntax.Marshal(keyShareServerHelloInner{ks.shares[0]})

	default:
		return nil, fmt.Errorf("tls.keyshare: Handshake type not allowed")
	}
}

func (ks *keyShareExtension) Unmarshal(data []byte) (int, error) {
	switch ks.handshakeType {
	case handshakeTypeClientHello:
		var inner keyShareClientHelloInner
		read, err := syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}

		for _, share := range inner.ClientShares {
			if !share.sizeValid() {
				return 0, fmt.Errorf("tls.keyshare: Key share has wrong size for group")
			}
		}

		ks.shares = inner.ClientShares
		return read, nil

	case handshakeTypeHelloRetryRequest:
		var inner keyShareHelloRetryInner
		read, err := syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}

		ks.selectedGroup = inner.SelectedGroup
		return read, nil

	case handshakeTypeServerHello:
		var inner keyShareServerHelloInner
		read, err := syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}

		if !inner.ServerShare.sizeValid() {
			return 0, fmt.Errorf("tls.keyshare: Key share has wrong size for group")
		}

		ks.shares = []keyShareEntry{inner.ServerShare}
		return read, nil

	default:
		return 0, fmt.Errorf("tls.keyshare: Handshake type not allowed")
	}
}

// struct {
//     NamedGroup named_group_list<2..2^16-1>;
// } NamedGroupList;
type supportedGroupsExtension struct {
	Groups []namedGroup `tls:"head=2,min=2"`
}

func (sg supportedGroupsExtension) Type() helloExtensionType {
	return extensionTypeSupportedGroups
}

func (sg supportedGroupsExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(sg)
}

func (sg *supportedGroupsExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, sg)
}

// struct {
//   SignatureScheme supported_signature_algorithms<2..2^16-2>;
// } SignatureSchemeList
type signatureAlgorithmsExtension struct {
	Algorithms []signatureScheme `tls:"head=2,min=2"`
}

func (sa signatureAlgorithmsExtension) Type() helloExtensionType {
	return extensionTypeSignatureAlgorithms
}

func (sa signatureAlgorithmsExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(sa)
}

func (sa *signatureAlgorithmsExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, sa)
}

// opaque psk_identity<0..2^16-1>;
//
// struct {
//     select (Role) {
//         case client:
//             psk_identity identities<2..2^16-1>;
//
//         case server:
//             uint16 selected_identity;
//     }
// } PreSharedKeyExtension;

type preSharedKeyExtension struct {
	roleIsServer     bool
	identities       [][]byte
	selectedIdentity uint16
}

func (psk preSharedKeyExtension) Type() helloExtensionType {
	return extensionTypePreSharedKey
}

func (psk preSharedKeyExtension) Marshal() ([]byte, error) {
	if psk.roleIsServer && len(psk.identities) > 0 {
		return nil, fmt.Errorf("tls.presharedkey: Server can only provide an index")
	}

	if psk.roleIsServer {
		id := psk.selectedIdentity
		return []byte{byte(id >> 8), byte(id)}, nil
	} else {
		identities := []byte{}
		for _, id := range psk.identities {
			idLen := len(id)
			header := []byte{byte(idLen >> 8), byte(idLen)}
			identities = append(identities, header...)
			identities = append(identities, id...)
		}
		dataLen := len(identities)
		header := []byte{byte(dataLen >> 8), byte(dataLen)}
		identities = append(header, identities...)
		return identities, nil
	}
}

func (psk *preSharedKeyExtension) Unmarshal(data []byte) (int, error) {
	read := 0
	if psk.roleIsServer {
		if len(data) != 2 {
			return 0, fmt.Errorf("tls.presharedkey: Server PSK has incorrect length")
		}

		psk.selectedIdentity = (uint16(data[0]) << 8) + uint16(data[1])
		read = 2
	} else {
		totalLen := len(data)
		if len(data) < 2 {
			return 0, fmt.Errorf("tls.presharedkey: Client PSK extension too short")
		}
		read = 2
		totalLen = (int(data[0]) << 8) + int(data[1])

		for read < 2+totalLen {
			if len(data[read:]) < 2 {
				return 0, fmt.Errorf("tls.presharedkey: PSK extension too short for identity header")
			}

			idLen := (int(data[read]) << 8) + int(data[read+1])
			if len(data[read+2:]) < idLen {
				return 0, fmt.Errorf("tls.presharedkey: PSK extension too short for identity")
			}

			id := make([]byte, idLen)
			copy(id, data[read+2:read+2+idLen])
			psk.identities = append(psk.identities, id)

			read += 2 + idLen

			if psk.roleIsServer {
				break
			}
		}
	}
	return read, nil
}

func (psk preSharedKeyExtension) HasIdentity(id []byte) bool {
	for _, localID := range psk.identities {
		if bytes.Equal(localID, id) {
			return true
		}
	}
	return false
}

//   struct {
//       select (Role) {
//           case client:
//               opaque configuration_id<1..2^16-1>;
//               CipherSuite cipher_suite;
//               Extension extensions<0..2^16-1>;
//               opaque context<0..255>;
//
//           case server:
//              struct {};
//       }
//   } EarlyDataIndication;
//
//   | 2 | opaque | 2 | 2 | extList | 1 | opaque |

type earlyDataExtension struct {
	roleIsServer    bool
	configurationID []byte
	cipherSuite     cipherSuite
	extensions      extensionList
	context         []byte
	version         int
}

func (ed earlyDataExtension) Type() helloExtensionType {
	return extensionTypeEarlyData
}

func (ed earlyDataExtension) Marshal() ([]byte, error) {
	if ed.roleIsServer {
		return []byte{}, nil
	}

	extData, err := ed.extensions.Marshal()
	if err != nil {
		return nil, err
	}

	configLen := len(ed.configurationID)
	extLen := len(extData)
	contextLen := len(ed.context)

	if configLen > 0xFFFF {
		return nil, fmt.Errorf("tls.earlydata: ConfigurationID too large to marshal")
	}

	if contextLen > 0xFF {
		return nil, fmt.Errorf("tls.earlydata: Context too large to marshal")
	}

	data := make([]byte, 2+configLen+2+extLen+1+contextLen)
	data[0] = byte(configLen >> 8)
	data[1] = byte(configLen)
	copy(data[2:], ed.configurationID)
	data[2+configLen] = byte(ed.cipherSuite >> 8)
	data[2+configLen+1] = byte(ed.cipherSuite)
	copy(data[2+configLen+2:], extData)
	data[2+configLen+2+extLen] = byte(contextLen)
	copy(data[2+configLen+2+extLen+1:], ed.context)

	return data, nil
}

func (ed *earlyDataExtension) Unmarshal(data []byte) (int, error) {
	if ed.roleIsServer {
		return 0, nil
	}

	if len(data) < 2 {
		return 0, fmt.Errorf("tls.earlydata: Too short for config header")
	}

	configLen := (int(data[0]) << 8) + int(data[1])
	if len(data) < 2+configLen+2 {
		return 0, fmt.Errorf("tls.earlydata: Too short for config")
	}

	ed.configurationID = make([]byte, configLen)
	copy(ed.configurationID, data[2:])

	ed.cipherSuite = (cipherSuite(data[2+configLen]) << 8) + cipherSuite(data[2+configLen+1])

	extLen, err := ed.extensions.Unmarshal(data[2+configLen+2:])
	if err != nil {
		return 0, fmt.Errorf("tls.earlydata: Error unmarshaling extensions")
	}
	if len(data) < 2+configLen+2+extLen+1 {
		return 0, fmt.Errorf("tls.earlydata: Too short for context header")
	}

	contextLen := int(data[2+configLen+2+extLen])
	if len(data) < 2+configLen+2+extLen+1+contextLen {
		return 0, fmt.Errorf("tls.earlydata: Too short for context")
	}

	ed.context = make([]byte, contextLen)
	copy(ed.context, data[2+configLen+2+extLen+1:])

	return 2 + configLen + 2 + extLen + 1 + contextLen, nil
}

// opaque ProtocolName<1..2^8-1>;
//
// struct {
//     ProtocolName protocol_name_list<2..2^16-1>
// } ProtocolNameList;
type alpnExtension struct {
	protocols []string
}

func (alpn alpnExtension) Type() helloExtensionType {
	return extensionTypeALPN
}

func (alpn alpnExtension) Marshal() ([]byte, error) {
	listData := []byte{}
	for _, proto := range alpn.protocols {
		listData = append(listData, byte(len(proto)))
		listData = append(listData, []byte(proto)...)
	}

	listLen := len(listData)
	lenData := []byte{byte(listLen >> 8), byte(listLen)}
	return append(lenData, listData...), nil
}

func (alpn *alpnExtension) Unmarshal(data []byte) (int, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("tls.alpn: Too short for list length")
	}

	listLen := (int(data[0]) << 8) + int(data[1])
	if len(data) < 2+listLen {
		return 0, fmt.Errorf("tls.alpn: Too short for proto list")
	}

	read := 2
	alpn.protocols = []string{}
	for read < listLen+2 {
		itemLen := int(data[read])
		read += 1 + itemLen
		if 2+listLen < read {
			return 0, fmt.Errorf("tls.alpn: List element length exceeds list length")
		}

		alpn.protocols = append(alpn.protocols, string(data[read-itemLen:read]))
	}

	return read, nil
}

// struct {
//     ProtocolVersion versions<2..254>;
// } SupportedVersions;
type supportedVersionsExtension struct {
	versions []uint16
}

func (sv supportedVersionsExtension) Type() helloExtensionType {
	return extensionTypeSupportedVersions
}

func (sv supportedVersionsExtension) Marshal() ([]byte, error) {
	listLen := 2 * len(sv.versions)

	data := make([]byte, 1+listLen)
	data[0] = byte(listLen)
	for i, version := range sv.versions {
		data[2*i+1] = byte(version >> 8)
		data[2*i+2] = byte(version)
	}

	return data, nil
}

func (sv *supportedVersionsExtension) Unmarshal(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("tls.supportedversions: Too short for length")
	}

	listLen := int(data[0])
	if len(data) < 1+listLen {
		return 0, fmt.Errorf("tls.supportedversions: Too short for list")
	}
	if listLen%2 == 1 {
		return 0, fmt.Errorf("tls.supportedversions: Odd list length")
	}

	sv.versions = make([]uint16, listLen/2)
	for i := range sv.versions {
		sv.versions[i] = (uint16(data[2*i+1]) << 8) + uint16(data[2*i+2])
	}

	return 1 + listLen, nil
}
