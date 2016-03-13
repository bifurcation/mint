package mint

import (
	"io"
	"testing"
)

type pipeReadWriter struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func pipe() *pipeReadWriter {
	p := new(pipeReadWriter)
	p.r, p.w = io.Pipe()
	return p
}

func (p *pipeReadWriter) Read(data []byte) (n int, err error) {
	return p.r.Read(data)
}

func (p *pipeReadWriter) Write(data []byte) (n int, err error) {
	return p.w.Write(data)
}

func TestBasicFlow(t *testing.T) {
	c2s := pipe()
	s2c := pipe()

	client := &Conn{
		isClient: true,
		in:       newRecordLayer(s2c),
		out:      newRecordLayer(c2s),
	}
	server := &Conn{
		isClient: false,
		in:       newRecordLayer(c2s),
		out:      newRecordLayer(s2c),
	}

	done := make(chan bool)
	go func(t *testing.T) {
		err := server.Handshake()
		assertNotError(t, err, "Server failed handshake")
		done <- true
	}(t)

	err := client.Handshake()
	assertNotError(t, err, "Client failed handshake")

	buf := make([]byte, 0)
	_, err = client.Read(buf)
	assertNotError(t, err, "Failed to read")

	<-done

	// Tests that the client and server arrive at the same crypto contexts
	assertEquals(t, client.context.state, server.context.state)
	assertEquals(t, client.context.suite, server.context.suite)
	assertEquals(t, client.context.params, server.context.params)
	assertEquals(t, len(client.context.transcript), len(server.context.transcript))
	assertByteEquals(t, client.context.ES, server.context.ES)
	assertByteEquals(t, client.context.SS, server.context.SS)
	assertByteEquals(t, client.context.xES, server.context.xES)
	assertByteEquals(t, client.context.xSS, server.context.xSS)
	assertDeepEquals(t, client.context.handshakeKeys, client.context.handshakeKeys)
	assertByteEquals(t, client.context.mES, server.context.mES)
	assertByteEquals(t, client.context.mSS, server.context.mSS)
	assertByteEquals(t, client.context.masterSecret, server.context.masterSecret)
	assertByteEquals(t, client.context.serverFinishedKey, server.context.serverFinishedKey)
	assertByteEquals(t, client.context.serverFinishedData, server.context.serverFinishedData)
	assertByteEquals(t, client.context.clientFinishedKey, server.context.clientFinishedKey)
	assertByteEquals(t, client.context.clientFinishedData, server.context.clientFinishedData)
	assertByteEquals(t, client.context.trafficSecret, server.context.trafficSecret)
	assertDeepEquals(t, client.context.applicationKeys, client.context.applicationKeys)
}
