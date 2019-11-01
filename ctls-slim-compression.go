package mint

import (
	"crypto/x509"
	"fmt"

	"github.com/bifurcation/mint/syntax"
)

// Slimmed-down message formats

type slimExtension struct {
	ExtensionType ExtensionType `tls:varint`
	ExtensionData []byte        `tls:"head=varint"`
}

type slimClientHello struct {
	Random       [32]byte
	CipherSuites []CipherSuite   `tls:"head=varint"`
	Extensions   []slimExtension `tls:"head=varint"`
}

type slimServerHello struct {
	Random      [32]byte
	CipherSuite CipherSuite
	Extensions  []slimExtension `tls:"head=varint"`
}

type slimEncryptedExtensions struct {
	Extensions []slimExtension `tls:"head=varint"`
}

type slimCertificateRequest struct {
	CertificateRequestContext []byte          `tls:"head=varint"`
	Extensions                []slimExtension `tls:"head=varint"`
}

type slimCertificateEntry struct {
	CertData   []byte          `tls:"head=varint"`
	Extensions []slimExtension `tls:"head=varint"`
}

type slimCertificate struct {
	CertificateRequestContext []byte                 `tls:"head=varint"`
	CertificateList           []slimCertificateEntry `tls:"head=varint"`
}

type slimCertificateVerify struct {
	Algorithm SignatureScheme
	Signature []byte `tls:"head=varint"`
}

func slimify(exts ExtensionList) []slimExtension {
	slim := make([]slimExtension, len(exts))
	for i, ext := range exts {
		slim[i] = slimExtension{ext.ExtensionType, ext.ExtensionData}
	}
	return slim
}

func unslimify(slim []slimExtension) ExtensionList {
	exts := make(ExtensionList, len(slim))
	for i, ext := range slim {
		exts[i] = Extension{ext.ExtensionType, ext.ExtensionData}
	}
	return exts
}

// Compression logic

type SlimCompression struct {
}

func (c SlimCompression) unmarshalOne(msgType HandshakeType, data []byte) (HandshakeMessageBody, error) {
	hms, err := c.unmarshalMessages(data)
	if err != nil {
		return nil, err
	}

	if len(hms) != 1 || hms[0].msgType != msgType {
		return nil, AlertUnexpectedMessage
	}

	return hms[0].ToBody()
}

func (c SlimCompression) marshalOne(body HandshakeMessageBody) ([]byte, error) {
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

func (c SlimCompression) unmarshalMessages(data []byte) ([]*HandshakeMessage, error) {
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

func (c SlimCompression) marshalMessages(hms []HandshakeMessageBody) ([]byte, error) {
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

func (c SlimCompression) CompressClientHello(chm []byte) ([]byte, error) {
	logf(logTypeCompression, "Compression.ClientHello.In: [%d] [%x]", len(chm), chm)
	body, err := c.unmarshalOne(HandshakeTypeClientHello, chm)
	if err != nil {
		return nil, err
	}
	ch := body.(*ClientHelloBody)

	sch := slimClientHello{
		Random:       ch.Random,
		CipherSuites: ch.CipherSuites,
		Extensions:   slimify(ch.Extensions),
	}

	schData, err := syntax.Marshal(sch)
	if err != nil {
		return nil, err
	}

	logf(logTypeCompression, "Compression.ClientHello.Out: [%d] [%x]", len(schData), schData)
	return schData, nil
}

func (c SlimCompression) ReadClientHello(schData []byte) ([]byte, int, error) {
	logf(logTypeCompression, "Decompression.ClientHello.In: [%d] [%x]", len(schData), schData)

	sch := slimClientHello{}
	read, err := syntax.Unmarshal(schData, &sch)
	if err != nil {
		return nil, 0, err
	}

	ch := &ClientHelloBody{
		LegacyVersion: tls12Version,
		Random:        sch.Random,
		CipherSuites:  sch.CipherSuites,
		Extensions:    unslimify(sch.Extensions),
	}

	chm, err := c.marshalOne(ch)
	if err != nil {
		return nil, 0, err
	}

	logf(logTypeCompression, "Decompression.ClientHello.Out: [%d] [%x]", len(chm), chm)
	return chm, read, nil
}

func (c SlimCompression) CompressServerHello(shm []byte) ([]byte, error) {
	logf(logTypeCompression, "Compression.ServerHello.In: [%d] [%x]", len(shm), shm)
	body, err := c.unmarshalOne(HandshakeTypeServerHello, shm)
	if err != nil {
		return nil, err
	}
	sh := body.(*ServerHelloBody)

	ssh := slimServerHello{
		Random:      sh.Random,
		CipherSuite: sh.CipherSuite,
		Extensions:  slimify(sh.Extensions),
	}

	sshData, err := syntax.Marshal(ssh)
	if err != nil {
		return nil, err
	}

	logf(logTypeCompression, "Compression.ServerHello.Out: [%d] [%x]", len(sshData), sshData)
	return sshData, nil
}

func (c SlimCompression) ReadServerHello(sshData []byte) ([]byte, int, error) {
	logf(logTypeCompression, "Decompression.ServerHello.In: [%d] [%x]", len(sshData), sshData)

	ssh := slimServerHello{}
	read, err := syntax.Unmarshal(sshData, &ssh)
	if err != nil {
		return nil, 0, err
	}

	sh := &ServerHelloBody{
		Version:     tls12Version,
		Random:      ssh.Random,
		CipherSuite: ssh.CipherSuite,
		Extensions:  unslimify(ssh.Extensions),
	}

	shm, err := c.marshalOne(sh)
	if err != nil {
		return nil, 0, err
	}

	logf(logTypeCompression, "Decompression.ServerHello.Out: [%d] [%x]", len(shm), shm)
	return shm, read, nil
}

func (c SlimCompression) compressFlight(hmData []byte, server bool) ([]byte, error) {
	logf(logTypeCompression, "Compression.Flight.In: [%v] [%d] [%x]", server, len(hmData), hmData)
	hms, err := c.unmarshalMessages(hmData)
	if err != nil {
		return nil, err
	}

	flightLength := rpkClientFlightLength
	if server {
		flightLength = rpkServerFlightLength
	}
	if len(hms) != flightLength {
		return nil, fmt.Errorf("Incorrect server flight length")
	}

	eeData := []byte{}
	certReqData := []byte{}
	if server {
		// Process EncryptedExtensions
		body, err := hms[0].ToBody()
		if err != nil {
			return nil, err
		}
		ee, ok := body.(*EncryptedExtensionsBody)
		if !ok {
			return nil, fmt.Errorf("Unexpected message")
		}

		see := slimEncryptedExtensions{
			Extensions: slimify(ee.Extensions),
		}

		eeData, err = syntax.Marshal(see)
		if err != nil {
			return nil, err
		}

		// Process CertificateRequest
		body, err = hms[1].ToBody()
		if err != nil {
			return nil, err
		}
		cr, ok := body.(*CertificateRequestBody)
		if !ok {
			return nil, fmt.Errorf("Unexpected message")
		}

		scr := slimCertificateRequest{
			CertificateRequestContext: cr.CertificateRequestContext,
			Extensions:                slimify(cr.Extensions),
		}

		certReqData, err = syntax.Marshal(scr)
		if err != nil {
			return nil, err
		}

		hms = hms[2:]
	}

	// Process Certificate
	body, err := hms[0].ToBody()
	cert, ok := body.(*CertificateBody)
	if err != nil || !ok {
		return nil, err
	}

	scert := slimCertificate{
		CertificateRequestContext: cert.CertificateRequestContext,
		CertificateList:           make([]slimCertificateEntry, len(cert.CertificateList)),
	}
	for i, entry := range cert.CertificateList {
		scert.CertificateList[i] = slimCertificateEntry{
			CertData:   entry.CertData.Raw,
			Extensions: slimify(entry.Extensions),
		}
	}

	certData, err := syntax.Marshal(scert)
	if err != nil {
		return nil, err
	}

	// Process CertificateVerify
	body, err = hms[1].ToBody()
	cv, ok := body.(*CertificateVerifyBody)
	if err != nil || !ok {
		return nil, err
	}

	scv := slimCertificateVerify{
		Algorithm: cv.Algorithm,
		Signature: cv.Signature,
	}

	cvData, err := syntax.Marshal(scv)
	if err != nil {
		return nil, err
	}

	// Process Finished
	body, err = hms[2].ToBody()
	fin, ok := body.(*FinishedBody)
	if err != nil || !ok {
		return nil, err
	}
	finData := fin.VerifyData

	// Concatenate everything
	flightData := append(eeData, certReqData...)
	flightData = append(flightData, certData...)
	flightData = append(flightData, cvData...)
	flightData = append(flightData, finData...)

	logf(logTypeCompression, "Compression.Flight.Out: [%d] [%x]", len(flightData), flightData)
	return flightData, nil
}

func (c SlimCompression) decompressFlight(flightData []byte, server bool) ([]byte, error) {
	logf(logTypeCompression, "Deompression.Flight.In: [%v] [%d] [%x]", server, len(flightData), flightData)

	hms := []HandshakeMessageBody{}
	if server {
		// Process EncryptedExtensions
		see := slimEncryptedExtensions{}
		read, err := syntax.Unmarshal(flightData, &see)
		if err != nil {
			return nil, err
		}

		ee := &EncryptedExtensionsBody{unslimify(see.Extensions)}

		flightData = flightData[read:]
		hms = append(hms, ee)

		// Process CertificateRequest
		scr := slimCertificateRequest{}
		read, err = syntax.Unmarshal(flightData, &scr)
		if err != nil {
			return nil, err
		}

		cr := &CertificateRequestBody{
			CertificateRequestContext: scr.CertificateRequestContext,
			Extensions:                unslimify(scr.Extensions),
		}

		flightData = flightData[read:]
		hms = append(hms, cr)
	}

	// Process Certificate
	scert := slimCertificate{}
	read, err := syntax.Unmarshal(flightData, &scert)
	if err != nil {
		return nil, err
	}

	cert := &CertificateBody{
		CertificateRequestContext: scert.CertificateRequestContext,
		CertificateList:           make([]CertificateEntry, len(scert.CertificateList)),
	}
	for i, entry := range scert.CertificateList {
		cert.CertificateList[i] = CertificateEntry{Extensions: unslimify(entry.Extensions)}
		cert.CertificateList[i].CertData, err = x509.ParseCertificate(entry.CertData)
	}

	flightData = flightData[read:]
	hms = append(hms, cert)

	// Process CertificateVerify
	scv := slimCertificateVerify{}
	read, err = syntax.Unmarshal(flightData, &scv)
	if err != nil {
		return nil, err
	}

	cv := &CertificateVerifyBody{
		Algorithm: scv.Algorithm,
		Signature: scv.Signature,
	}

	flightData = flightData[read:]
	hms = append(hms, cv)

	// Process Finished
	fin := &FinishedBody{
		VerifyDataLen: len(flightData),
		VerifyData:    flightData,
	}

	hms = append(hms, fin)

	// Assemble the outgoing package
	hmData, err := c.marshalMessages(hms)
	if err != nil {
		return nil, err
	}

	logf(logTypeCompression, "Decompression.Flight.Out: [%d] [%x]", len(hmData), hmData)
	return hmData, nil
}

func (c SlimCompression) CompressServerFlight(hmData []byte) ([]byte, error) {
	return c.compressFlight(hmData, true)
}

func (c SlimCompression) CompressClientFlight(hmData []byte) ([]byte, error) {
	return c.compressFlight(hmData, false)
}

func (c SlimCompression) DecompressServerFlight(hmData []byte) ([]byte, error) {
	return c.decompressFlight(hmData, true)
}

func (c SlimCompression) DecompressClientFlight(hmData []byte) ([]byte, error) {
	return c.decompressFlight(hmData, false)
}
