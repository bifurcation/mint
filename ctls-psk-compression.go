package mint

import (
	"fmt"

	"github.com/bifurcation/mint/syntax"
)

type PSKCompression struct {
	// Compression attributes
	ServerName       string
	CipherSuite      CipherSuite
	SupportedVersion uint16
	SupportedGroup   NamedGroup
	SignatureScheme  SignatureScheme
	PSKMode          PSKKeyExchangeMode

	// TLS tweaks
	RandomSize   int
	FinishedSize int
}

func (c PSKCompression) unmarshalOne(msgType HandshakeType, data []byte) (HandshakeMessageBody, error) {
	hms, err := c.unmarshalMessages(data)
	if err != nil {
		return nil, err
	}

	if len(hms) != 1 || hms[0].msgType != msgType {
		logf(logTypeCompression, "Unexpected message: [%d] | [%v] != [%v]", len(hms), hms[0].msgType, msgType)
		return nil, AlertUnexpectedMessage
	}

	return hms[0].ToBody()
}

func (c PSKCompression) marshalOne(body HandshakeMessageBody) ([]byte, error) {
	data, err := body.Marshal()
	if err != nil {
		return nil, err
	}

	hm := HandshakeMessage{
		msgType: body.Type(),
		body:    data,
		length:  uint32(len(data)),
	}
	return hm.Marshal(), nil
}

func (c PSKCompression) unmarshalMessages(data []byte) ([]*HandshakeMessage, error) {
	hms := []*HandshakeMessage{}
	for len(data) > 0 {
		newhm := new(HandshakeMessage)
		n, err := newhm.Unmarshal(data)
		if err != nil {
			return nil, err
		}
		newhm.length = uint32(len(newhm.body))

		hms = append(hms, newhm)
		data = data[n:]
	}

	return hms, nil
}

func (c PSKCompression) marshalMessages(hms []HandshakeMessageBody) ([]byte, error) {
	data := []byte{}
	for _, hm := range hms {
		hmData, err := c.marshalOne(hm)
		if err != nil {
			return nil, err
		}

		data = append(data, hmData...)
	}
	return data, nil
}

// struct {
//   opaque random[RAND_SIZE];
//   opaque identity<1..255>;
//   uint32 obfuscated_ticket_age;
//   opaque binder<1..255>;
//   opaque key_share<*>;
// } PSKClientHello;
type pskClientHello struct {
	// Fixed-length Random value handled separately
	Identity            []byte `tls:"head=1"`
	ObfuscatedTicketAge uint32
	Binder              []byte `tls:"head=1"`
	KeyShare            []byte `tls:"head=none"`
}

func (c PSKCompression) CompressClientHello(chm []byte) ([]byte, error) {
	logf(logTypeCompression, "Compression.ClientHello.In: [%d] [%x]", len(chm), chm)
	body, err := c.unmarshalOne(HandshakeTypeClientHello, chm)
	if err != nil {
		return nil, err
	}
	ch := body.(*ClientHelloBody)

	// TODO verify that the ClientHello is compressible

	// Find the key share
	ks := &KeyShareExtension{HandshakeType: HandshakeTypeClientHello}
	found, err := ch.Extensions.Find(ks)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("No KeyShares extension")
	}

	// Find the PSK binder
	psk := &PreSharedKeyExtension{HandshakeType: HandshakeTypeClientHello}
	found, err = ch.Extensions.Find(psk)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("No PreSharedKey extension")
	}

	cch := pskClientHello{
		Identity:            psk.Identities[0].Identity,
		ObfuscatedTicketAge: psk.Identities[0].ObfuscatedTicketAge,
		Binder:              psk.Binders[0].Binder,
		KeyShare:            ks.Shares[0].KeyExchange,
	}
	cchData, err := syntax.Marshal(cch)
	if err != nil {
		return nil, err
	}

	random := ch.Random[:c.RandomSize]
	cchData = append(random, cchData...)

	logf(logTypeCompression, "Compression.ClientHello.Out: [%d] [%x]", len(cchData), cchData)
	return cchData, nil
}

func (c PSKCompression) ReadClientHello(cchData []byte) ([]byte, int, error) {
	logf(logTypeCompression, "Decompression.ClientHello.In: [%d] [%x]", len(cchData), cchData)

	if len(cchData) < c.RandomSize {
		return nil, 0, fmt.Errorf("To little CCH data")
	}

	var random [32]byte
	var cch pskClientHello

	copy(random[:], cchData[:c.RandomSize])
	_, err := syntax.Unmarshal(cchData[c.RandomSize:], &cch)
	if err != nil {
		return nil, 0, err
	}

	// TODO Read PSK binder

	ch := &ClientHelloBody{
		LegacyVersion: tls12Version,
		Random:        random,
		CipherSuites:  []CipherSuite{c.CipherSuite},
	}

	sni := ServerNameExtension(c.ServerName)
	sv := SupportedVersionsExtension{HandshakeType: HandshakeTypeClientHello, Versions: []uint16{tls13Version}}
	sg := SupportedGroupsExtension{Groups: []NamedGroup{c.SupportedGroup}}
	sa := SignatureAlgorithmsExtension{Algorithms: []SignatureScheme{c.SignatureScheme}}
	ks := KeyShareExtension{
		HandshakeType: HandshakeTypeClientHello,
		Shares: []KeyShareEntry{
			{c.SupportedGroup, cch.KeyShare},
		},
	}
	kem := PSKKeyExchangeModesExtension{KEModes: []PSKKeyExchangeMode{c.PSKMode}}
	psk := PreSharedKeyExtension{
		HandshakeType: HandshakeTypeClientHello,
		Identities: []PSKIdentity{
			{cch.Identity, cch.ObfuscatedTicketAge},
		},
		Binders: []PSKBinderEntry{{cch.Binder}},
	}
	for _, ext := range []ExtensionBody{&sni, &sv, &sg, &sa, &ks, &kem, &psk} {
		err = ch.Extensions.Add(ext)
		if err != nil {
			return nil, 0, err
		}
	}

	chm, err := c.marshalOne(ch)
	if err != nil {
		return nil, 0, err
	}

	logf(logTypeCompression, "Decompression.ClientHello.Out: [%d] [%x]", len(chm), chm)
	return chm, len(cchData), nil
}

// struct {
//   opaque random[RAND_SIZE];
//   opaque key_share<*>;
// } PSKServerHello;
func (c PSKCompression) CompressServerHello(shm []byte) ([]byte, error) {
	var err error
	logErr := func() {
		logf(logTypeCompression, "shError: %v", err)
	}
	defer logErr()

	logf(logTypeCompression, "Compression.ServerHello.In: [%d] [%x]", len(shm), shm)
	body, err := c.unmarshalOne(HandshakeTypeServerHello, shm)
	if err != nil {
		return nil, err
	}
	sh := body.(*ServerHelloBody)

	// TODO verify that the ServerHello is compressible

	ks := &KeyShareExtension{HandshakeType: HandshakeTypeServerHello}
	found, err := sh.Extensions.Find(ks)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("No KeyShares extension")
	}

	psk := &PreSharedKeyExtension{HandshakeType: HandshakeTypeServerHello}
	found, err = sh.Extensions.Find(psk)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("No PreSharedKey extension")
	}

	cshData := sh.Random[:c.RandomSize]
	cshData = append(cshData, ks.Shares[0].KeyExchange...)

	logf(logTypeCompression, "Compression.ServerHello.Out: [%d] [%x]", len(cshData), cshData)
	return cshData, nil
}

func (c PSKCompression) ReadServerHello(cshData []byte) ([]byte, int, error) {
	logf(logTypeCompression, "Decompression.ServerHello.In: [%d] [%x]", len(cshData), cshData)

	var err error

	var random [32]byte
	copy(random[:], cshData[:c.RandomSize])
	keyShare := cshData[c.RandomSize:]

	sh := &ServerHelloBody{
		Version:     tls12Version,
		Random:      random,
		CipherSuite: c.CipherSuite,
	}

	sv := SupportedVersionsExtension{HandshakeType: HandshakeTypeServerHello, Versions: []uint16{tls13Version}}
	ks := KeyShareExtension{
		HandshakeType: HandshakeTypeServerHello,
		Shares: []KeyShareEntry{
			{c.SupportedGroup, keyShare},
		},
	}
	psk := PreSharedKeyExtension{
		HandshakeType:    HandshakeTypeServerHello,
		SelectedIdentity: 0x00,
	}
	for _, ext := range []ExtensionBody{&sv, &ks, &psk} {
		err = sh.Extensions.Add(ext)
		if err != nil {
			return nil, 0, err
		}
	}

	shm, err := c.marshalOne(sh)
	if err != nil {
		return nil, 0, err
	}

	logf(logTypeCompression, "Decompression.ServerHello.Out: [%d] [%x]", len(shm), shm)
	return shm, len(cshData), nil
}

// Server: EE, Fin
// Client: Fin
const (
	pskServerFlightLength = 2
	pskClientFlightLength = 1
)

func (c PSKCompression) compressFlight(hmData []byte, server bool) ([]byte, error) {
	logf(logTypeCompression, "Compression.Flight.In: [%v] [%d] [%x]", server, len(hmData), hmData)
	hms, err := c.unmarshalMessages(hmData)
	if err != nil {
		return nil, err
	}

	flightLength := pskClientFlightLength
	if server {
		flightLength = pskServerFlightLength
	}
	if len(hms) != flightLength {
		return nil, fmt.Errorf("Incorrect server flight length [%d] != [%d]", len(hms), flightLength)
	}

	if server {
		if hms[0].msgType != HandshakeTypeEncryptedExtensions {
			return nil, fmt.Errorf("Malformed server flight (EE)")
		}

		hms = hms[1:]
	}

	// TODO verify that the flight is compressible

	// Process Finished
	body, err := hms[0].ToBody()
	fin, ok := body.(*FinishedBody)
	if err != nil || !ok {
		return nil, err
	}
	mac := fin.VerifyData

	cfData := mac

	logf(logTypeCompression, "Compression.Flight.Out: [%d] [%x]", len(cfData), cfData)
	return cfData, nil
}

func (c PSKCompression) decompressFlight(cfData []byte, server bool) ([]byte, error) {
	logf(logTypeCompression, "Decompression.Flight.In: [%v] [%d] [%x]", server, len(cfData), cfData)

	mac := cfData
	hms := []HandshakeMessageBody{}

	if server {
		ee := &EncryptedExtensionsBody{}
		hms = []HandshakeMessageBody{ee}
	}

	fin := &FinishedBody{
		VerifyDataLen: len(mac),
		VerifyData:    mac,
	}
	hms = append(hms, fin)

	hmData, err := c.marshalMessages(hms)
	if err != nil {
		return nil, err
	}

	logf(logTypeCompression, "Decompression.Flight.Out: [%d] [%x]", len(hmData), hmData)
	return hmData, nil
}

func (c PSKCompression) CompressServerFlight(hmData []byte) ([]byte, error) {
	return c.compressFlight(hmData, true)
}

func (c PSKCompression) CompressClientFlight(hmData []byte) ([]byte, error) {
	return c.compressFlight(hmData, false)
}

func (c PSKCompression) DecompressServerFlight(hmData []byte) ([]byte, error) {
	return c.decompressFlight(hmData, true)
}

func (c PSKCompression) DecompressClientFlight(hmData []byte) ([]byte, error) {
	return c.decompressFlight(hmData, false)
}
