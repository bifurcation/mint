package mint

import (
	"fmt"
)

type Conn struct {
	in, out *recordLayer
}

const verifyDataLen = 20 // XXX

func (c *Conn) ClientHandshake() {
	hIn := newHandshakeLayer(c.in)
	hOut := newHandshakeLayer(c.out)

	// Construct and write ClientHello
	ch := &clientHelloBody{
		cipherSuites: []cipherSuite{0x0000}, // XXX
	}
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

	// Create and write ServerHello
	sh := &serverHelloBody{
		cipherSuite: 0x0000,
	}
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
