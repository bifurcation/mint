package mint

import (
	"encoding/hex"
	"fmt"
)

type Conn struct {
	in, out *recordLayer
}

const verifyDataLen = 20 // XXX

func (c *Conn) ClientHandshake() {
	hIn := newHandshakeLayer(c.in)
	hOut := newHandshakeLayer(c.out)

	// Generate, construct, and marshal key share
	config_keyShareGroups := []namedGroup{namedGroupP256, namedGroupP384, namedGroupP521}
	privateKeys := map[namedGroup][]byte{}
	ks := &keyShareExtension{
		roleIsServer: false,
		shares:       make([]keyShare, len(config_keyShareGroups)),
	}
	for i, group := range config_keyShareGroups {
		pub, priv, err := newKeyShare(group)
		if err != nil {
			panic(err) // XXX
		}

		ks.shares[i].group = group
		ks.shares[i].keyExchange = pub
		privateKeys[group] = priv
	}

	// Construct and write ClientHello
	ch := &clientHelloBody{
		cipherSuites: []cipherSuite{0x0000}, // XXX
	}
	ch.extensions.Add(ks)
	err := hOut.WriteMessageBody(ch)
	if err != nil {
		panic(err) // XXX Do something better
	}

	// Read ServerHello
	sh := new(serverHelloBody)
	err = hIn.ReadMessageBody(sh)
	if err != nil {
		panic(err) // XXX Do something better
	}

	// Read the key_share extension and do key agreement
	foundKeyShare := false
	serverKeyShares := keyShareExtension{roleIsServer: true}
	for _, ext := range sh.extensions {
		if ext.extensionType == extensionTypeKeyShare {
			_, err := serverKeyShares.Unmarshal(ext.extensionData)
			foundKeyShare = (err == nil)
			if foundKeyShare {
				break
			}
		}
	}
	if !foundKeyShare {
		panic("No client key share")
	}
	if len(serverKeyShares.shares) != 1 {
		panic("Server provided empty key_shares") // XXX should check in Unmarshal
	}
	sks := serverKeyShares.shares[0]
	priv, ok := privateKeys[sks.group]
	if !ok {
		panic("Server sent a private key for a group we didn't send")
	}
	ES, err := keyAgreement(sks.group, sks.keyExchange, priv)
	if err != nil {
		panic(err)
	}

	fmt.Println("ES_client:", hex.EncodeToString(ES))

	// Read Finished
	serverFin := new(finishedBody)
	serverFin.verifyDataLen = verifyDataLen // XXX
	err = hIn.ReadMessageBody(serverFin)
	if err != nil {
		panic(err) // XXX Do something better
	}

	// Write Finished
	clientFin := &finishedBody{
		verifyDataLen: verifyDataLen,
		verifyData:    make([]byte, verifyDataLen),
	}
	err = hOut.WriteMessageBody(clientFin)
	if err != nil {
		panic(err)
	}

	fmt.Println("Client done")
}

func (c *Conn) ServerHandshake() {
	hIn := newHandshakeLayer(c.in)
	hOut := newHandshakeLayer(c.out)

	// Read ClientHello
	ch := new(clientHelloBody)
	err := hIn.ReadMessageBody(ch)
	if err != nil {
		panic(err) // XXX Do something better
	}

	// Find key_share extension and do key agreement
	config_supportedGroup := map[namedGroup]bool{
		namedGroupP384: true,
		namedGroupP521: true,
	}
	clientKeyShares := &keyShareExtension{roleIsServer: false}
	found := ch.extensions.Find(clientKeyShares)
	if !found {
		panic("No client key shares")
	}
	var serverKeyShare *keyShareExtension
	var ES []byte
	for _, share := range clientKeyShares.shares {
		if config_supportedGroup[share.group] {
			pub, priv, err := newKeyShare(share.group)
			if err != nil {
				panic(err) // XXX
			}

			ES, err = keyAgreement(share.group, share.keyExchange, priv)
			serverKeyShare = &keyShareExtension{
				roleIsServer: true,
				shares:       []keyShare{keyShare{group: share.group, keyExchange: pub}},
			}
			break
		}
	}
	if serverKeyShare == nil || len(ES) == 0 {
		panic("key agreement failed")
	}

	fmt.Println("ES_server:", hex.EncodeToString(ES))

	// Create and write ServerHello
	sh := &serverHelloBody{
		cipherSuite: 0x0000,
	}
	sh.extensions.Add(serverKeyShare)
	err = hOut.WriteMessageBody(sh)
	if err != nil {
		panic(err) // XXX Do something better
	}

	// Create and write Finished
	serverFin := &finishedBody{
		verifyDataLen: verifyDataLen,
		verifyData:    make([]byte, verifyDataLen),
	}
	err = hOut.WriteMessageBody(serverFin)
	if err != nil {
		panic(err)
	}

	// Read Finished
	clientFin := new(finishedBody)
	clientFin.verifyDataLen = verifyDataLen // XXX
	err = hIn.ReadMessageBody(clientFin)
	if err != nil {
		panic(err) // XXX Do something better
	}

	fmt.Println("Server done")
}
