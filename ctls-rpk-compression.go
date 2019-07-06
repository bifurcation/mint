package mint

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/bifurcation/mint/syntax"
)

type RPKCompression struct {
	// Compression attributes
	ServerName       string
	CipherSuite      CipherSuite
	SupportedVersion uint16
	SupportedGroup   NamedGroup
	SignatureScheme  SignatureScheme
	Certificates     map[string]*Certificate

	// TLS tweaks
	ZeroRandom      bool
	VirtualFinished bool
}

func (c RPKCompression) unmarshalOne(msgType HandshakeType, data []byte) (HandshakeMessageBody, error) {
	hms, err := c.unmarshalMessages(data)
	if err != nil {
		return nil, err
	}

	if len(hms) != 1 || hms[0].msgType != msgType {
		return nil, AlertUnexpectedMessage
	}

	return hms[0].ToBody()
}

func (c RPKCompression) marshalOne(body HandshakeMessageBody) ([]byte, error) {
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

func (c RPKCompression) unmarshalMessages(data []byte) ([]*HandshakeMessage, error) {
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

func (c RPKCompression) marshalMessages(hms []HandshakeMessageBody) ([]byte, error) {
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

type ecdsaASN struct {
	R *big.Int
	S *big.Int
}

func (c RPKCompression) compressECDSA(sigIn []byte) []byte {
	var sig ecdsaASN
	asn1.Unmarshal(sigIn, &sig)

	rb := sig.R.Bytes()
	sb := sig.S.Bytes()

	il := c.sigSize() / 2
	rb = rb[il-len(rb):]
	sb = sb[il-len(sb):]

	return append(rb, sb...)
}

func (c RPKCompression) decompressECDSA(sigIn []byte) []byte {
	il := c.sigSize() / 2
	rb := sigIn[:il]
	sb := sigIn[il:]

	sig := ecdsaASN{
		R: big.NewInt(0).SetBytes(rb),
		S: big.NewInt(0).SetBytes(sb),
	}
	sigOut, _ := asn1.Marshal(sig)
	return sigOut
}

func (c RPKCompression) sigSize() int {
	switch c.SignatureScheme {
	case ECDSA_P256_SHA256, Ed25519:
		return 64
	case ECDSA_P384_SHA384:
		return 96
	case Ed448:
		return 112
	case ECDSA_P521_SHA512:
		return 132
	default:
		panic("Non-compressible signature scheme")
	}
}

func (c RPKCompression) macSize() int {
	if c.VirtualFinished {
		return 0
	}

	switch c.CipherSuite {
	case TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
		TLS_AES_128_CCM_SHA256, TLS_AES_256_CCM_8_SHA256:
		return 32
	case TLS_AES_256_GCM_SHA384:
		return 48
	default:
		panic("Unknown ciphersuite")
	}
}

type rpkHello struct {
	Random   [32]byte
	KeyShare []byte `tls:"head=none"`
}

type rpkHelloZeroRandom struct {
	KeyShare []byte `tls:"head=none"`
}

func (c RPKCompression) CompressClientHello(chm []byte) ([]byte, error) {
	logf(logTypeCompression, "Compression.ClientHello.In: [%d] [%x]", len(chm), chm)
	body, err := c.unmarshalOne(HandshakeTypeClientHello, chm)
	if err != nil {
		return nil, err
	}
	ch := body.(*ClientHelloBody)

	// TODO verify that the ClientHello is compressible

	ks := &KeyShareExtension{HandshakeType: HandshakeTypeClientHello}
	found, err := ch.Extensions.Find(ks)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("No KeyShares extension")
	}

	var cchData []byte
	if c.ZeroRandom {
		cch := rpkHelloZeroRandom{
			KeyShare: ks.Shares[0].KeyExchange,
		}

		cchData, err = syntax.Marshal(cch)
	} else {
		cch := rpkHello{
			Random:   ch.Random,
			KeyShare: ks.Shares[0].KeyExchange,
		}

		cchData, err = syntax.Marshal(cch)
	}
	if err != nil {
		return nil, err
	}

	logf(logTypeCompression, "Compression.ClientHello.Out: [%d] [%x]", len(cchData), cchData)
	return cchData, nil
}

func (c RPKCompression) ReadClientHello(cchData []byte) ([]byte, int, error) {
	logf(logTypeCompression, "Decompression.ClientHello.In: [%d] [%x]", len(cchData), cchData)

	var err error
	var read int
	var random [32]byte
	var keyShare []byte
	if c.ZeroRandom {
		cch := rpkHelloZeroRandom{}
		read, err = syntax.Unmarshal(cchData, &cch)
		if err != nil {
			return nil, 0, err
		}

		random = [32]byte{}
		keyShare = cch.KeyShare
	} else {
		cch := rpkHello{}
		read, err = syntax.Unmarshal(cchData, &cch)
		if err != nil {
			return nil, 0, err
		}

		random = cch.Random
		keyShare = cch.KeyShare
	}

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
			{c.SupportedGroup, keyShare},
		},
	}
	for _, ext := range []ExtensionBody{&sni, &sv, &sg, &sa, &ks} {
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
	return chm, read, nil
}

func (c RPKCompression) CompressServerHello(shm []byte) ([]byte, error) {
	logf(logTypeCompression, "Compression.ServerHello.In: [%d] [%x]", len(shm), shm)
	body, err := c.unmarshalOne(HandshakeTypeServerHello, shm)
	if err != nil {
		return nil, err
	}
	ch := body.(*ServerHelloBody)

	// TODO verify that the ServerHello is compressible

	ks := &KeyShareExtension{HandshakeType: HandshakeTypeServerHello}
	found, err := ch.Extensions.Find(ks)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("No KeyShares extension")
	}

	var cshData []byte
	if c.ZeroRandom {
		csh := rpkHelloZeroRandom{
			KeyShare: ks.Shares[0].KeyExchange,
		}

		cshData, err = syntax.Marshal(csh)
	} else {
		csh := rpkHello{
			Random:   ch.Random,
			KeyShare: ks.Shares[0].KeyExchange,
		}

		cshData, err = syntax.Marshal(csh)
	}
	if err != nil {
		return nil, err
	}

	logf(logTypeCompression, "Compression.ServerHello.Out: [%d] [%x]", len(cshData), cshData)
	return cshData, nil
}

func (c RPKCompression) ReadServerHello(cshData []byte) ([]byte, int, error) {
	logf(logTypeCompression, "Decompression.ServerHello.In: [%d] [%x]", len(cshData), cshData)

	var err error
	var read int
	var random [32]byte
	var keyShare []byte
	if c.ZeroRandom {
		csh := rpkHelloZeroRandom{}
		read, err = syntax.Unmarshal(cshData, &csh)
		if err != nil {
			return nil, 0, err
		}

		random = [32]byte{}
		keyShare = csh.KeyShare
	} else {
		csh := rpkHello{}
		read, err = syntax.Unmarshal(cshData, &csh)
		if err != nil {
			return nil, 0, err
		}

		random = csh.Random
		keyShare = csh.KeyShare
	}

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
	for _, ext := range []ExtensionBody{&sv, &ks} {
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
	return shm, read, nil
}

// Server: EE, CR, Cert, CV, Fin
// Client: Cert, CV, Fin
const (
	rpkServerFlightLength = 5
	rpkClientFlightLength = 3
)

func (c RPKCompression) compressFlight(hmData []byte, server bool) ([]byte, error) {
	logf(logTypeCompression, "Compression.Flight.In: [%v] [%d] [%x]", server, len(hmData), hmData)
	hms, err := c.unmarshalMessages(hmData)
	if err != nil {
		return nil, err
	}

	flightLength := rpkClientFlightLength
	if server {
		flightLength = rpkServerFlightLength
	}
	if c.VirtualFinished {
		flightLength -= 1
	}
	if len(hms) != flightLength {
		return nil, fmt.Errorf("Incorrect server flight length")
	}

	if server {
		if hms[0].msgType != HandshakeTypeEncryptedExtensions ||
			hms[1].msgType != HandshakeTypeCertificateRequest {
			return nil, fmt.Errorf("Malformed server flight (EE, CR)")
		}

		hms = hms[2:]
	}

	// TODO verify that the flight is compressible

	// Process Certificate
	body, err := hms[0].ToBody()
	cert, ok := body.(*CertificateBody)
	if err != nil || !ok {
		return nil, err
	}

	var certID []byte
	certData := cert.CertificateList[0].CertData.Raw
	for name, cert := range c.Certificates {
		if bytes.Equal(certData, cert.Chain[0].Raw) {
			certID = []byte(name)
			break
		}
	}
	if certID == nil {
		return nil, fmt.Errorf("Unkonwn certificate")
	}

	// Process CertificateVerify
	body, err = hms[1].ToBody()
	cv, ok := body.(*CertificateVerifyBody)
	if err != nil || !ok {
		return nil, err
	}

	sig := cv.Signature
	if c.SignatureScheme == ECDSA_P256_SHA256 ||
		c.SignatureScheme == ECDSA_P384_SHA384 ||
		c.SignatureScheme == ECDSA_P521_SHA512 {
		sig = c.compressECDSA(sig)
	}

	// Process Finished
	mac := []byte{}
	if !c.VirtualFinished {
		body, err = hms[2].ToBody()
		fin, ok := body.(*FinishedBody)
		if err != nil || !ok {
			return nil, err
		}

		mac = fin.VerifyData
	}

	cfData := append(certID, sig...)
	cfData = append(cfData, mac...)

	logf(logTypeCompression, "Compression.Flight.Out: [%d] [%x]", len(cfData), cfData)
	return cfData, nil
}

func (c RPKCompression) decompressFlight(cfData []byte, server bool) ([]byte, error) {
	logf(logTypeCompression, "Deompression.Flight.In: [%v] [%d] [%x]", server, len(cfData), cfData)

	sigSize := c.sigSize()
	macSize := c.macSize()
	cut1 := len(cfData) - sigSize - macSize
	cut2 := len(cfData) - macSize

	certID := string(cfData[:cut1])
	sig := cfData[cut1:cut2]
	mac := cfData[cut2:]

	if c.SignatureScheme == ECDSA_P256_SHA256 ||
		c.SignatureScheme == ECDSA_P384_SHA384 ||
		c.SignatureScheme == ECDSA_P521_SHA512 {
		sig = c.decompressECDSA(sig)
	}

	hms := []HandshakeMessageBody{}

	if server {
		ee := &EncryptedExtensionsBody{}

		cr := &CertificateRequestBody{}
		schemes := &SignatureAlgorithmsExtension{Algorithms: []SignatureScheme{c.SignatureScheme}}
		err := cr.Extensions.Add(schemes)
		if err != nil {
			return nil, err
		}

		hms = []HandshakeMessageBody{ee, cr}
	}

	certChain, found := c.Certificates[certID]
	if !found {
		return nil, fmt.Errorf("Unknown certificate for ID [%s]", certID)
	}

	chain := certChain.Chain
	cert := &CertificateBody{
		CertificateList: make([]CertificateEntry, len(chain)),
	}
	for i, entry := range chain {
		cert.CertificateList[i] = CertificateEntry{CertData: entry}
	}
	hms = append(hms, cert)

	cv := &CertificateVerifyBody{
		Algorithm: c.SignatureScheme,
		Signature: sig,
	}
	hms = append(hms, cv)

	if !c.VirtualFinished {
		fin := &FinishedBody{
			VerifyDataLen: len(mac),
			VerifyData:    mac,
		}
		hms = append(hms, fin)
	}

	hmData, err := c.marshalMessages(hms)
	if err != nil {
		return nil, err
	}

	logf(logTypeCompression, "Decompression.Flight.Out: [%d] [%x]", len(hmData), hmData)
	return hmData, nil
}

func (c RPKCompression) CompressServerFlight(hmData []byte) ([]byte, error) {
	return c.compressFlight(hmData, true)
}

func (c RPKCompression) CompressClientFlight(hmData []byte) ([]byte, error) {
	return c.compressFlight(hmData, false)
}

func (c RPKCompression) DecompressServerFlight(hmData []byte) ([]byte, error) {
	return c.decompressFlight(hmData, true)
}

func (c RPKCompression) DecompressClientFlight(hmData []byte) ([]byte, error) {
	return c.decompressFlight(hmData, false)
}
