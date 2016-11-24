package mint

import (
	"bytes"
	"fmt"

	"github.com/bifurcation/mint/syntax"
)

type extensionBody interface {
	Type() extensionType
	Marshal() ([]byte, error)
	Unmarshal(data []byte) (int, error)
}

// struct {
//     ExtensionType extension_type;
//     opaque extension_data<0..2^16-1>;
// } Extension;
type extension struct {
	ExtensionType extensionType
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

	if el == nil {
		el = new(extensionList)
	}

	// If one already exists with this type, replace it
	for i := range *el {
		if (*el)[i].ExtensionType == src.Type() {
			(*el)[i].ExtensionData = data
			return nil
		}
	}

	// Otherwise append
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

func (sni serverNameExtension) Type() extensionType {
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

	// Syntax requires at least one entry
	// Entries beyond the first are ignored
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
	Group       NamedGroup
	KeyExchange []byte `tls:"head=2,min=1"`
}

func (kse keyShareEntry) sizeValid() bool {
	return len(kse.KeyExchange) == keyExchangeSizeFromNamedGroup(kse.Group)
}

type keyShareExtension struct {
	handshakeType handshakeType
	selectedGroup NamedGroup
	shares        []keyShareEntry
}

type keyShareClientHelloInner struct {
	ClientShares []keyShareEntry `tls:"head=2,min=0"`
}
type keyShareHelloRetryInner struct {
	SelectedGroup NamedGroup
}
type keyShareServerHelloInner struct {
	ServerShare keyShareEntry
}

func (ks keyShareExtension) Type() extensionType {
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
	Groups []NamedGroup `tls:"head=2,min=2"`
}

func (sg supportedGroupsExtension) Type() extensionType {
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
	Algorithms []SignatureScheme `tls:"head=2,min=2"`
}

func (sa signatureAlgorithmsExtension) Type() extensionType {
	return extensionTypeSignatureAlgorithms
}

func (sa signatureAlgorithmsExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(sa)
}

func (sa *signatureAlgorithmsExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, sa)
}

// struct {
//     opaque identity<1..2^16-1>;
//     uint32 obfuscated_ticket_age;
// } PskIdentity;
//
// opaque PskBinderEntry<32..255>;
//
// struct {
//     select (Handshake.msg_type) {
//         case client_hello:
//             PskIdentity identities<7..2^16-1>;
//             PskBinderEntry binders<33..2^16-1>;
//
//         case server_hello:
//             uint16 selected_identity;
//     };
//
// } PreSharedKeyExtension;
type pskIdentity struct {
	Identity            []byte `tls:"head=2,min=1"`
	ObfuscatedTicketAge uint32
}

type pskBinderEntry struct {
	Binder []byte `tls:"head=1,min=32"`
}

type preSharedKeyExtension struct {
	handshakeType    handshakeType
	identities       []pskIdentity
	binders          []pskBinderEntry
	selectedIdentity uint16
}

type preSharedKeyClientInner struct {
	Identities []pskIdentity    `tls:"head=2,min=7"`
	Binders    []pskBinderEntry `tls:"head=2,min=33"`
}

type preSharedKeyServerInner struct {
	SelectedIdentity uint16
}

func (psk preSharedKeyExtension) Type() extensionType {
	return extensionTypePreSharedKey
}

func (psk preSharedKeyExtension) Marshal() ([]byte, error) {
	switch psk.handshakeType {
	case handshakeTypeClientHello:
		return syntax.Marshal(preSharedKeyClientInner{
			Identities: psk.identities,
			Binders:    psk.binders,
		})

	case handshakeTypeServerHello:
		if len(psk.identities) > 0 || len(psk.binders) > 0 {
			return nil, fmt.Errorf("tls.presharedkey: Server can only provide an index")
		}
		return syntax.Marshal(preSharedKeyServerInner{psk.selectedIdentity})

	default:
		return nil, fmt.Errorf("tls.presharedkey: Handshake type not supported")
	}
}

func (psk *preSharedKeyExtension) Unmarshal(data []byte) (int, error) {
	switch psk.handshakeType {
	case handshakeTypeClientHello:
		var inner preSharedKeyClientInner
		read, err := syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}

		if len(inner.Identities) != len(inner.Binders) {
			return 0, fmt.Errorf("Lengths of identities and binders not equal")
		}

		psk.identities = inner.Identities
		psk.binders = inner.Binders
		return read, nil

	case handshakeTypeServerHello:
		var inner preSharedKeyServerInner
		read, err := syntax.Unmarshal(data, &inner)
		if err != nil {
			return 0, err
		}

		psk.selectedIdentity = inner.SelectedIdentity
		return read, nil

	default:
		return 0, fmt.Errorf("tls.presharedkey: Handshake type not supported")
	}
}

func (psk preSharedKeyExtension) HasIdentity(id []byte) ([]byte, bool) {
	for i, localID := range psk.identities {
		if bytes.Equal(localID.Identity, id) {
			return psk.binders[i].Binder, true
		}
	}
	return nil, false
}

// enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode;
//
// struct {
//     PskKeyExchangeMode ke_modes<1..255>;
// } PskKeyExchangeModes;
type pskKeyExchangeModesExtension struct {
	KEModes []PSKKeyExchangeMode `tls:"head=1,min=1"`
}

func (pkem pskKeyExchangeModesExtension) Type() extensionType {
	return extensionTypePSKKeyExchangeModes
}

func (pkem pskKeyExchangeModesExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(pkem)
}

func (pkem *pskKeyExchangeModesExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, pkem)
}

// struct {
// } EarlyDataIndication;

type earlyDataExtension struct{}

func (ed earlyDataExtension) Type() extensionType {
	return extensionTypeEarlyData
}

func (ed earlyDataExtension) Marshal() ([]byte, error) {
	return []byte{}, nil
}

func (ed *earlyDataExtension) Unmarshal(data []byte) (int, error) {
	return 0, nil
}

// struct {
//     uint32 max_early_data_size;
// } TicketEarlyDataInfo;

type ticketEarlyDataInfoExtension struct {
	MaxEarlyDataSize uint32
}

func (tedi ticketEarlyDataInfoExtension) Type() extensionType {
	return extensionTypeTicketEarlyDataInfo
}

func (tedi ticketEarlyDataInfoExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(tedi)
}

func (tedi *ticketEarlyDataInfoExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, tedi)
}

// opaque ProtocolName<1..2^8-1>;
//
// struct {
//     ProtocolName protocol_name_list<2..2^16-1>
// } ProtocolNameList;
type alpnExtension struct {
	protocols []string
}

type protocolName struct {
	Name []byte `tls:"head=1,min=1"`
}

type alpnExtensionInner struct {
	Protocols []protocolName `tls:"head=2,min=2"`
}

func (alpn alpnExtension) Type() extensionType {
	return extensionTypeALPN
}

func (alpn alpnExtension) Marshal() ([]byte, error) {
	protocols := make([]protocolName, len(alpn.protocols))
	for i, protocol := range alpn.protocols {
		protocols[i] = protocolName{[]byte(protocol)}
	}
	return syntax.Marshal(alpnExtensionInner{protocols})
}

func (alpn *alpnExtension) Unmarshal(data []byte) (int, error) {
	var inner alpnExtensionInner
	read, err := syntax.Unmarshal(data, &inner)

	if err != nil {
		return 0, err
	}

	alpn.protocols = make([]string, len(inner.Protocols))
	for i, protocol := range inner.Protocols {
		alpn.protocols[i] = string(protocol.Name)
	}
	return read, nil
}

// struct {
//     ProtocolVersion versions<2..254>;
// } SupportedVersions;
type supportedVersionsExtension struct {
	Versions []uint16 `tls:"head=1,min=2,max=254"`
}

func (sv supportedVersionsExtension) Type() extensionType {
	return extensionTypeSupportedVersions
}

func (sv supportedVersionsExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(sv)
}

func (sv *supportedVersionsExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, sv)
}

// struct {
//     opaque cookie<1..2^16-1>;
// } Cookie;
type cookieExtension struct {
	Cookie []byte `tls:"head=2,min=1"`
}

func (c cookieExtension) Type() extensionType {
	return extensionTypeCookie
}

func (c cookieExtension) Marshal() ([]byte, error) {
	return syntax.Marshal(c)
}

func (c *cookieExtension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, c)
}
