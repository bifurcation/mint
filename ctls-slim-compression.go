package mint

import (
	"bytes"
	"crypto/x509"
	"fmt"

	"github.com/bifurcation/mint/syntax"
)

// Slimmed-down message formats

type slimExtension struct {
	ExtensionType ExtensionType `tls:"varint"`
	ExtensionData []byte        `tls:"head=varint"`
}

type slimExtensionList struct {
	Extensions []slimExtension `tls:"head=varint"`
}

type slimCipherSuites struct {
	CipherSuites []CipherSuite `tls:"head=varint"`
}

type slimCertificateRequest struct {
	CertificateRequestContext []byte `tls:"head=varint"`
	Extensions                slimExtensionList
}

type slimCertificateEntry struct {
	CertData   []byte `tls:"head=varint"`
	Extensions slimExtensionList
}

type slimCertificate struct {
	CertificateRequestContext []byte                 `tls:"head=varint"`
	CertificateList           []slimCertificateEntry `tls:"head=varint"`
}

type slimCertificateVerify struct {
	Algorithm SignatureScheme
	Signature []byte `tls:"head=varint"`
}

// Extension slimming

// Pre-defined extensions can be used as part of slimming compression.
//
// On compress:
// * Extensions in the map are not serialized
// * It is an error if any of the following occur
//   * The value of an extension in the map differs from the value in the map
//   * An extension in the map is not provided
// * ... because then decompression will produce a different result
//
// On decompress:
// * Extensions in the map are added to the decompressed extension list
// * It is an error if an extension in the map is present in the compressed list
//   with a different value than is specified in the map
type PredefinedExtensions map[ExtensionType][]byte

func slimify(exts ExtensionList, predefined PredefinedExtensions) (slimExtensionList, error) {
	predefSeen := map[ExtensionType]bool{}

	slim := []slimExtension{}
	for _, ext := range exts {
		predefVal, defined := predefined[ext.ExtensionType]

		if !defined {
			slim = append(slim, slimExtension{ext.ExtensionType, ext.ExtensionData})
			continue
		}

		predefSeen[ext.ExtensionType] = true

		if !bytes.Equal(predefVal, ext.ExtensionData) {
			err := fmt.Errorf("Incorrect value for predefined extension")
			logf(logTypeCompression, "Compression.Ext error: [%v] [%x] [%x]", err, predefVal, ext.ExtensionData)
			return slimExtensionList{}, err
		}
	}

	for extType := range predefined {
		if predefSeen[extType] {
			continue
		}

		err := fmt.Errorf("Required extension %04x not provided", extType)
		logf(logTypeCompression, "Compression.Ext error: [%v] [%x] [%x]", err, predefSeen, predefined)
		return slimExtensionList{}, err
	}

	return slimExtensionList{slim}, nil
}

func unslimify(slim slimExtensionList, predefined PredefinedExtensions) (ExtensionList, error) {
	exts := ExtensionList{}

	for _, ext := range slim.Extensions {
		predefVal, defined := predefined[ext.ExtensionType]

		if defined && !bytes.Equal(predefVal, ext.ExtensionData) {
			err := fmt.Errorf("Incorrect value for predefined extension")
			logf(logTypeCompression, "Decompression.Ext error: [%v] [%x] [%x]", err, predefVal, ext.ExtensionData)
			return nil, err
		}

		exts.AddExtension(ext.ExtensionType, ext.ExtensionData)
	}

	for extType, data := range predefined {
		exts.AddExtension(extType, data)
	}

	return exts, nil
}

// Compression logic

type ClientHelloConstraints struct {
	RandomSize int
	Extensions PredefinedExtensions
}

type ServerHelloConstraints struct {
	RandomSize int
	Extensions PredefinedExtensions
}

type CertificateRequestConstraints struct {
	Omit       bool
	Extensions PredefinedExtensions
}

type CertificateConstraints struct {
	Omit       bool
	KnownCerts map[string][]byte
	Extensions PredefinedExtensions
}

type SlimCompression struct {
	CipherSuite         *CipherSuite
	ClientHello         ClientHelloConstraints
	ServerHello         ServerHelloConstraints
	EncryptedExtensions PredefinedExtensions
	CertificateRequest  CertificateRequestConstraints
	Certificate         CertificateConstraints
}

func (c SlimCompression) clientFlightLength() int {
	length := 1 // Finished
	if !c.Certificate.Omit {
		length += 2 // Certificate + CertificateVerify
	}
	return length
}

func (c SlimCompression) serverFlightLength() int {
	length := c.clientFlightLength() + 1 // EncryptedExtensions
	if !c.CertificateRequest.Omit {
		length += 1 // CertificateRequest
	}
	return length
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
		logf(logTypeCompression, "Compression.ClientHello.Error1: [%v]", err)
		return nil, err
	}
	ch := body.(*ClientHelloBody)

	randomData := ch.Random[:c.ClientHello.RandomSize]

	suiteData := []byte{}
	if c.CipherSuite == nil {
		suites := slimCipherSuites{ch.CipherSuites}
		suiteData, err = syntax.Marshal(suites)
		if err != nil {
			logf(logTypeCompression, "Compression.ClientHello.Error2: [%v]", err)
			return nil, err
		}
	}

	extensions, err := slimify(ch.Extensions, c.ClientHello.Extensions)
	if err != nil {
		logf(logTypeCompression, "Compression.ClientHello.Error3: [%v]", err)
		return nil, err
	}

	extData, err := syntax.Marshal(extensions)
	if err != nil {
		logf(logTypeCompression, "Compression.ClientHello.Error4: [%v]", err)
		return nil, err
	}

	schData := append(randomData, suiteData...)
	schData = append(schData, extData...)

	logf(logTypeCompression, "Compression.ClientHello.Out: [%d] [%x]", len(schData), schData)
	return schData, nil
}

func (c SlimCompression) ReadClientHello(schData []byte) ([]byte, int, error) {
	logf(logTypeCompression, "Decompression.ClientHello.In: [%d] [%x]", len(schData), schData)

	random := schData[:c.ClientHello.RandomSize]
	schData = schData[c.ClientHello.RandomSize:]
	read := len(random)

	suites := []CipherSuite{}
	if c.CipherSuite != nil {
		suites = []CipherSuite{*c.CipherSuite}
	} else {
		ssuites := slimCipherSuites{}
		readSuites, err := syntax.Unmarshal(schData, &ssuites)
		if err != nil {
			logf(logTypeCompression, "Decompression.ClientHello.Error1: [%v]", err)
			return nil, 0, err
		}

		suites = ssuites.CipherSuites
		schData = schData[readSuites:]
		read += readSuites
	}

	sext := slimExtensionList{}
	readExt, err := syntax.Unmarshal(schData, &sext)
	if err != nil {
		logf(logTypeCompression, "Decompression.ClientHello.Error2: [%v]", err)
		return nil, 0, err
	}

	read += readExt

	ch := &ClientHelloBody{
		LegacyVersion: tls12Version,
		CipherSuites:  suites,
	}

	copy(ch.Random[:], random)

	ch.Extensions, err = unslimify(sext, c.ClientHello.Extensions)
	if err != nil {
		logf(logTypeCompression, "Decompression.ClientHello.Error3: [%v]", err)
		return nil, 0, err
	}

	chm, err := c.marshalOne(ch)
	if err != nil {
		logf(logTypeCompression, "Decompression.ClientHello.Error4: [%v] [%+v]", err, ch)
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

	randomData := sh.Random[:c.ServerHello.RandomSize]

	suiteData := []byte{}
	if c.CipherSuite == nil {
		suiteData, err = syntax.Marshal(sh.CipherSuite)
		if err != nil {
			return nil, err
		}
	}

	sext, err := slimify(sh.Extensions, c.ServerHello.Extensions)
	if err != nil {
		return nil, err
	}

	extData, err := syntax.Marshal(sext)
	if err != nil {
		return nil, err
	}

	sshData := append(randomData, suiteData...)
	sshData = append(sshData, extData...)

	logf(logTypeCompression, "Compression.ServerHello.Out: [%d] [%x]", len(sshData), sshData)
	return sshData, nil
}

func (c SlimCompression) ReadServerHello(sshData []byte) ([]byte, int, error) {
	logf(logTypeCompression, "Decompression.ServerHello.In: [%d] [%x]", len(sshData), sshData)

	random := sshData[:c.ServerHello.RandomSize]
	sshData = sshData[c.ServerHello.RandomSize:]
	read := c.ServerHello.RandomSize

	var suite CipherSuite
	if c.CipherSuite != nil {
		suite = *c.CipherSuite
	} else {
		readSuite, err := syntax.Unmarshal(sshData, &suite)
		if err != nil {
			return nil, 0, err
		}

		sshData = sshData[readSuite:]
		read += readSuite
	}

	sext := slimExtensionList{}
	readExt, err := syntax.Unmarshal(sshData, &sext)
	if err != nil {
		return nil, 0, err
	}

	read += readExt

	sh := &ServerHelloBody{
		Version:     tls12Version,
		CipherSuite: suite,
	}

	copy(sh.Random[:], random)

	sh.Extensions, err = unslimify(sext, c.ServerHello.Extensions)
	if err != nil {
		return nil, 0, err
	}

	shm, err := c.marshalOne(sh)
	if err != nil {
		return nil, 0, err
	}

	logf(logTypeCompression, "Decompression.ServerHello.Out: [%d] [%x]", len(shm), shm)
	return shm, read, nil
}

func (c SlimCompression) compressFlight(hmData []byte, server bool) (flightData []byte, err error) {
	defer func() {
		if err != nil {
			logf(logTypeCompression, "Compression.Flight.Error: [%v]", err)
		}
	}()

	logf(logTypeCompression, "Compression.Flight.In: [%v] [%d] [%x]", server, len(hmData), hmData)
	hms, err := c.unmarshalMessages(hmData)
	if err != nil {
		return nil, err
	}

	flightLength := c.clientFlightLength()
	if server {
		flightLength = c.serverFlightLength()
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
			return nil, fmt.Errorf("Unexpected message of type [%v]", body.Type())
		}

		see, err := slimify(ee.Extensions, c.EncryptedExtensions)
		if err != nil {
			return nil, err
		}

		eeData, err = syntax.Marshal(see)
		if err != nil {
			return nil, err
		}

		hms = hms[1:]

		// Process CertificateRequest
		if !c.CertificateRequest.Omit {
			body, err = hms[0].ToBody()
			if err != nil {
				return nil, err
			}
			cr, ok := body.(*CertificateRequestBody)
			if !ok {
				return nil, fmt.Errorf("Unexpected message of type [%v]", body.Type())
			}

			scr := slimCertificateRequest{
				CertificateRequestContext: cr.CertificateRequestContext,
			}
			scr.Extensions, err = slimify(cr.Extensions, c.CertificateRequest.Extensions)
			if err != nil {
				return nil, err
			}

			certReqData, err = syntax.Marshal(scr)
			if err != nil {
				return nil, err
			}

			hms = hms[1:]
		}
	}

	certData := []byte{}
	cvData := []byte{}
	if !c.Certificate.Omit {
		// Process Certificate
		body, err := hms[0].ToBody()
		if err != nil {
			return nil, err
		}
		cert, ok := body.(*CertificateBody)
		if !ok {
			return nil, fmt.Errorf("Unexpected message of type [%v]", body.Type())
		}

		certDataLen := 0
		scert := slimCertificate{
			CertificateRequestContext: cert.CertificateRequestContext,
			CertificateList:           make([]slimCertificateEntry, len(cert.CertificateList)),
		}
		for i, entry := range cert.CertificateList {
			// XXX(rlb): This just opportunistically replaces known certificates with
			// labels from the dictionary, so there's a risk of collision on
			// decompression.  This seems unlikely to be a problem in practice, but
			// might merit some signaling.
			certData := entry.CertData.Raw
			for id, knownCert := range c.Certificate.KnownCerts {
				if bytes.Equal(knownCert, certData) {
					certData = []byte(id)
					break
				}
			}

			scert.CertificateList[i] = slimCertificateEntry{CertData: certData}
			scert.CertificateList[i].Extensions, err = slimify(entry.Extensions, c.Certificate.Extensions)
			if err != nil {
				return nil, err
			}

			certDataLen += len(scert.CertificateList[i].CertData)
		}
		logf(logTypeCompression, "Compression.Flight.CertData: [%d]", certDataLen)

		certData, err = syntax.Marshal(scert)
		if err != nil {
			return nil, err
		}

		// Process CertificateVerify
		body, err = hms[1].ToBody()
		if err != nil {
			return nil, err
		}
		cv, ok := body.(*CertificateVerifyBody)
		if !ok {
			return nil, fmt.Errorf("Unexpected message of type [%v]", body.Type())
		}

		scv := slimCertificateVerify{
			Algorithm: cv.Algorithm,
			Signature: cv.Signature,
		}

		cvData, err = syntax.Marshal(scv)
		if err != nil {
			return nil, err
		}

		hms = hms[2:]
	}

	// Process Finished
	body, err := hms[0].ToBody()
	if err != nil {
		return nil, err
	}
	fin, ok := body.(*FinishedBody)
	if !ok {
		return nil, fmt.Errorf("Unexpected message of type [%v]", body.Type())
	}
	finData := fin.VerifyData

	// Concatenate everything
	flightData = append(eeData, certReqData...)
	flightData = append(flightData, certData...)
	flightData = append(flightData, cvData...)
	flightData = append(flightData, finData...)

	logf(logTypeCompression, "Compression.Flight.Out: [%d] [%x]", len(flightData), flightData)
	return flightData, nil
}

func (c SlimCompression) decompressFlight(flightData []byte, server bool) (hmData []byte, err error) {
	defer func() {
		if err != nil {
			logf(logTypeCompression, "Deompression.Flight.Error: [%v]", err)
		}
	}()

	logf(logTypeCompression, "Deompression.Flight.In: [%v] [%d] [%x]", server, len(flightData), flightData)

	hms := []HandshakeMessageBody{}
	if server {
		// Process EncryptedExtensions
		see := slimExtensionList{}
		read, err := syntax.Unmarshal(flightData, &see)
		if err != nil {
			return nil, err
		}

		ee := &EncryptedExtensionsBody{}
		ee.Extensions, err = unslimify(see, c.EncryptedExtensions)
		if err != nil {
			return nil, err
		}

		flightData = flightData[read:]
		hms = append(hms, ee)

		if !c.CertificateRequest.Omit {
			// Process CertificateRequest
			scr := slimCertificateRequest{}
			read, err = syntax.Unmarshal(flightData, &scr)
			if err != nil {
				return nil, err
			}

			cr := &CertificateRequestBody{CertificateRequestContext: scr.CertificateRequestContext}
			cr.Extensions, err = unslimify(scr.Extensions, c.CertificateRequest.Extensions)
			if err != nil {
				return nil, err
			}

			flightData = flightData[read:]
			hms = append(hms, cr)
		}
	}

	// Process Certificate
	if !c.Certificate.Omit {
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
			cert.CertificateList[i] = CertificateEntry{}

			// Decompress any compressed certificates
			certData := entry.CertData
			for id, knownCert := range c.Certificate.KnownCerts {
				if id == string(certData) {
					certData = knownCert
					break
				}
			}

			cert.CertificateList[i].CertData, err = x509.ParseCertificate(certData)
			if err != nil {
				return nil, err
			}

			cert.CertificateList[i].Extensions, err = unslimify(entry.Extensions, c.Certificate.Extensions)
			if err != nil {
				return nil, err
			}
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
	}

	// Process Finished
	fin := &FinishedBody{
		VerifyDataLen: len(flightData),
		VerifyData:    flightData,
	}

	hms = append(hms, fin)

	// Assemble the outgoing package
	hmData, err = c.marshalMessages(hms)
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
