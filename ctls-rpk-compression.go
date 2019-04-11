package mint

import (
	"bytes"
	"fmt"

	"github.com/bifurcation/mint/syntax"
)

type RPKCompression struct {
	ServerName       string
	CipherSuite      CipherSuite
	SupportedVersion uint16
	SupportedGroup   NamedGroup
	SignatureScheme  SignatureScheme
	Certificates     map[string]*Certificate
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

type rpkHello struct {
	Random   [32]byte
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

	cch := rpkHello{
		Random:   ch.Random,
		KeyShare: ks.Shares[0].KeyExchange,
	}

	cchData, err := syntax.Marshal(cch)
	if err != nil {
		return nil, err
	}

	logf(logTypeCompression, "Compression.ClientHello.Out: [%d] [%x]", len(cchData), cchData)
	return cchData, nil
}

func (c RPKCompression) ReadClientHello(cchData []byte) ([]byte, int, error) {
	logf(logTypeCompression, "Decompression.ClientHello.In: [%d] [%x]", len(cchData), cchData)
	cch := rpkHello{}
	n, err := syntax.Unmarshal(cchData, &cch)
	if err != nil {
		return nil, 0, err
	}

	ch := &ClientHelloBody{
		LegacyVersion: tls12Version,
		Random:        cch.Random,
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
	return chm, n, nil
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

	csh := rpkHello{
		Random:   ch.Random,
		KeyShare: ks.Shares[0].KeyExchange,
	}

	cshData, err := syntax.Marshal(csh)
	if err != nil {
		return nil, err
	}

	logf(logTypeCompression, "Compression.ServerHello.Out: [%d] [%x]", len(cshData), cshData)
	return cshData, nil
}

func (c RPKCompression) ReadServerHello(cshData []byte) ([]byte, int, error) {
	logf(logTypeCompression, "Decompression.ServerHello.In: [%d] [%x]", len(cshData), cshData)
	csh := rpkHello{}
	n, err := syntax.Unmarshal(cshData, &csh)
	if err != nil {
		return nil, 0, err
	}

	sh := &ServerHelloBody{
		Version:     tls12Version,
		Random:      csh.Random,
		CipherSuite: c.CipherSuite,
	}

	sv := SupportedVersionsExtension{HandshakeType: HandshakeTypeServerHello, Versions: []uint16{tls13Version}}
	ks := KeyShareExtension{
		HandshakeType: HandshakeTypeServerHello,
		Shares: []KeyShareEntry{
			{c.SupportedGroup, csh.KeyShare},
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
	return shm, n, nil
}

// Server: EE, CR, Cert, CV, Fin
// Client: Cert, CV, Fin
const (
	rpkServerFlightLength = 5
	rpkClientFlightLength = 3
)

type rpkFlight struct {
	CertID    []byte `tls:"head=1"`
	Signature []byte `tls:"head=1"`
	MAC       []byte `tls:"head=none"`
}

func (c RPKCompression) compressFlight(hmData []byte, server bool) ([]byte, error) {
	logf(logTypeCompression, "Compression.Flight.In: [%v] [%d] [%x]", server, len(hmData), hmData)
	hms, err := c.unmarshalMessages(hmData)
	if err != nil {
		return nil, err
	}

	if server {
		if len(hms) != rpkServerFlightLength {
			return nil, fmt.Errorf("Incorrect server flight length")
		}

		if hms[0].msgType != HandshakeTypeEncryptedExtensions ||
			hms[1].msgType != HandshakeTypeCertificateRequest {
			return nil, fmt.Errorf("Malformed server flight (EE, CR)")
		}

		hms = hms[2:]
	} else if len(hms) != rpkClientFlightLength {
		return nil, fmt.Errorf("Incorrect server flight length")
	}

	// TODO verify that the flight is compressible

	body, err := hms[0].ToBody()
	cert, ok := body.(*CertificateBody)
	if err != nil || !ok {
		return nil, err
	}

	body, err = hms[1].ToBody()
	cv, ok := body.(*CertificateVerifyBody)
	if err != nil || !ok {
		return nil, err
	}

	body, err = hms[2].ToBody()
	fin, ok := body.(*FinishedBody)
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

	cf := rpkFlight{
		CertID:    certID,
		Signature: cv.Signature,
		MAC:       fin.VerifyData,
	}

	cfData, err := syntax.Marshal(cf)
	if err != nil {
		return nil, err
	}

	logf(logTypeCompression, "Compression.Flight.Out: [%d] [%x]", len(cfData), cfData)
	return cfData, nil
}

func (c RPKCompression) decompressFlight(cfData []byte, server bool) ([]byte, error) {
	logf(logTypeCompression, "Deompression.Flight.In: [%v] [%d] [%x]", server, len(cfData), cfData)

	cf := rpkFlight{}
	_, err := syntax.Unmarshal(cfData, &cf)
	if err != nil {
		return nil, err
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

	certID := string(cf.CertID)
	certChain, found := c.Certificates[certID]
	if !found {
		return nil, fmt.Errorf("Unknown certificate for ID [%s] [%x]", certID, cf.CertID)
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
		Signature: cf.Signature,
	}
	hms = append(hms, cv)

	fin := &FinishedBody{
		VerifyDataLen: len(cf.MAC),
		VerifyData:    cf.MAC,
	}
	hms = append(hms, fin)

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
