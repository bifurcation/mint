package mint

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func newLocalListener(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ln, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func TestDialTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	listener := newLocalListener(t)

	addr := listener.Addr().String()
	defer listener.Close()

	complete := make(chan bool)
	defer close(complete)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Error(err)
			return
		}
		<-complete
		conn.Close()
	}()

	dialer := &net.Dialer{
		Timeout: 10 * time.Millisecond,
	}

	var err error
	if _, err = DialWithDialer(dialer, "tcp", addr, nil); err == nil {
		t.Fatal("DialWithTimeout completed successfully")
	}

	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("resulting error not a timeout: %s", err)
	}
}

func TestDialNonBlocking(t *testing.T) {
	config := &Config{NonBlocking: true}
	_, err := Dial("tcp", "localhost:1234", config)
	assertEquals(t, err.Error(), "dialing not possible in non-blocking mode")
	_, err = DialWithDialer(&net.Dialer{}, "tcp", "localhost:1234", config)
	assertEquals(t, err.Error(), "dialing not possible in non-blocking mode")
}

func TestListenNonBlocking(t *testing.T) {
	config := &Config{
		NonBlocking:  true,
		Certificates: certificates,
	}
	_, err := Listen("tcp", "localhost:1234", config)
	assertEquals(t, err.Error(), "listening not possible in non-blocking mode")
	_, err = NewListener(newLocalListener(t), config)
	assertEquals(t, err.Error(), "listening not possible in non-blocking mode")
}

// tests that Conn.Read returns (non-zero, io.EOF) instead of
// (non-zero, nil) when a Close (alertCloseNotify) is sitting right
// behind the application data in the buffer.
func DISABLEDTestConnReadNonzeroAndEOF(t *testing.T) {
	// This test is racy: it assumes that after a write to a
	// localhost TCP connection, the peer TCP connection can
	// immediately read it.  Because it's racy, we skip this test
	// in short mode, and then retry it several times with an
	// increasing sleep in between our final write (via srv.Close
	// below) and the following read.
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	var err error
	for delay := time.Millisecond; delay <= 64*time.Millisecond; delay *= 2 {
		if err = testConnReadNonzeroAndEOF(t, delay); err == nil {
			return
		}
	}
	t.Error(err)
}

func testConnReadNonzeroAndEOF(t *testing.T, delay time.Duration) error {
	ln := newLocalListener(t)
	defer ln.Close()

	srvCh := make(chan *Conn, 1)
	var serr error
	go func() {
		sconn, err := ln.Accept()
		if err != nil {
			serr = err
			srvCh <- nil
			return
		}
		serverConfig := Config{ServerName: "example.com"}
		srv := Server(sconn, &serverConfig)
		if alert := srv.Handshake(); alert != AlertNoAlert {
			serr = fmt.Errorf("handshake: %v", alert)
			srvCh <- nil
			return
		}
		srvCh <- srv
	}()

	clientConfig := Config{ServerName: "example.com"}
	conn, err := Dial("tcp", ln.Addr().String(), &clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	srv := <-srvCh
	if srv == nil {
		return serr
	}

	buf := make([]byte, 16)
	buf = buf[0:6]

	// Consume NST.
	zeroBuf := []byte{}
	conn.Read(zeroBuf)

	srv.Write([]byte("foobar"))
	n, err := conn.Read(buf)
	if n != 6 || err != nil || string(buf) != "foobar" {
		return fmt.Errorf("Read = %d, %v, data %q; want 6, nil, foobar", n, err, buf)
	}

	srv.Write([]byte("foobartoo"))
	n, err = conn.Read(buf)
	if n != 6 || err != nil || string(buf) != "foobar" {
		return fmt.Errorf("Read = %d, %v, data %q; want 6, nil, foobar", n, err, buf)
	}

	n, err = conn.Read(buf)
	if n != 3 || err != nil || string(buf[0:3]) != "too" {
		return fmt.Errorf("Read = %d, %v, data %q; want 3, nil, too", n, err, buf)
	}

	srv.Write([]byte("four"))
	n, err = conn.Read(buf)
	if n != 4 || err != nil || string(buf[0:4]) != "four" {
		return fmt.Errorf("Read = %d, %v, data %q; want 4, nil, foor", n, err, buf)
	}

	srv.Write([]byte("abcdefgh"))
	srv.Close()
	time.Sleep(delay)
	n, err = conn.Read(buf)
	if n != 6 || string(buf) != "abcdef" {
		return fmt.Errorf("Read = %d, buf= %q; want 6, abcdef", n, buf)
	}
	if err != nil {
		return fmt.Errorf("First Read error = %v; want nil", err)
	}

	n, err = conn.Read(buf)
	if n != 2 || string(buf[0:2]) != "gh" {
		return fmt.Errorf("Read = %d, buf= %q; want 2, gh", n, buf)
	}

	return nil
}

func TestExchangeData(t *testing.T) {
	ln := newLocalListener(t)
	defer ln.Close()

	srvCh := make(chan *Conn, 1)
	var serr error
	go func() {
		sconn, err := ln.Accept()
		if err != nil {
			serr = err
			srvCh <- nil
			return
		}
		serverConfig := Config{Certificates: certificates}
		srv := Server(sconn, &serverConfig)
		if alert := srv.Handshake(); alert != AlertNoAlert {
			serr = fmt.Errorf("handshake: %v", alert)
			srvCh <- nil
			return
		}
		srvCh <- srv
	}()

	clientConfig := Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
	}
	conn, err := Dial("tcp", ln.Addr().String(), &clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	srv := <-srvCh
	assertNotNil(t, srv, "Server should have completed handshake")

	buf := make([]byte, 16)
	buf = buf[0:6]
	srv.Write([]byte("foobar"))
	n, err := conn.Read(buf)
	if n != 6 || err != nil || string(buf) != "foobar" {
		t.Fatalf("Read = %d, %v, data %q; want 6, nil, foobar", n, err, buf)
		return
	}
	srv.Write([]byte("foobartoo"))
	n, err = conn.Read(buf)
	if n != 6 || err != nil || string(buf) != "foobar" {
		t.Fatalf("Read = %d, %v, data %q; want 6, nil, foobar", n, err, buf)
		return
	}

	n, err = conn.Read(buf)
	if n != 3 || err != nil || string(buf[0:3]) != "too" {
		t.Fatalf("Read = %d, %v, data %q; want 3, nil, too", n, err, buf)
		return
	}
	srv.Write([]byte("four"))
	n, err = conn.Read(buf)
	if n != 4 || err != nil || string(buf[0:4]) != "four" {
		t.Fatalf("Read = %d, %v, data %q; want 4, nil, four", n, err, buf)
		return
	}

	return
}
