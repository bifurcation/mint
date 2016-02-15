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
		in:  newRecordLayer(s2c),
		out: newRecordLayer(c2s),
	}
	server := &Conn{
		in:  newRecordLayer(c2s),
		out: newRecordLayer(s2c),
	}

	go func() {
		server.ServerHandshake()
	}()

	client.ClientHandshake()
}
