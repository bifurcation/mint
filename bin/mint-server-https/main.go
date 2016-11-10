package main

import (
	"crypto"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/bifurcation/mint"
	"github.com/cloudflare/cfssl/helpers"
	"golang.org/x/net/http2"
)

var (
	port         string
	serverName   string
	certFile     string
	keyFile      string
	responseFile string
	h2           bool
	sendTickets  bool
)

type responder []byte

func (rsp responder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write(rsp)
}

func main() {
	flag.StringVar(&port, "port", "4430", "port")
	flag.StringVar(&serverName, "host", "example.com", "hostname")
	flag.StringVar(&certFile, "cert", "", "certificate chain in PEM or DER")
	flag.StringVar(&keyFile, "key", "", "private key in PEM format")
	flag.StringVar(&responseFile, "response", "", "file to serve")
	flag.BoolVar(&h2, "h2", false, "whether to use HTTP/2 (exclusively)")
	flag.BoolVar(&sendTickets, "tickets", true, "whether to send session tickets")
	flag.Parse()

	var certChain []*x509.Certificate
	var priv crypto.Signer
	var response []byte
	var err error

	// Load the key and certificate chain
	if certFile != "" {
		certs, err := ioutil.ReadFile(certFile)
		if err != nil {
			log.Fatalf("Error: %v", err)
		} else {
			certChain, err = helpers.ParseCertificatesPEM(certs)
			if err != nil {
				certChain, _, err = helpers.ParseCertificatesDER(certs, "")
			}
		}
	}
	if keyFile != "" {
		keyPEM, err := ioutil.ReadFile(keyFile)
		if err != nil {
			log.Fatalf("Error: %v", err)
		} else {
			priv, err = helpers.ParsePrivateKeyPEM(keyPEM)
		}
	}
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Load response file
	if responseFile != "" {
		log.Printf("Loading response file: %v", responseFile)
		response, err = ioutil.ReadFile(responseFile)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	} else {
		response = []byte("Welcome to the TLS 1.3 zone!")
	}
	handler := responder(response)

	config := mint.Config{
		SendSessionTickets: true,
		ServerName:         serverName,
		NextProtos:         []string{"http/1.1"},
	}

	if h2 {
		config.NextProtos = []string{"h2"}
	}

	config.SendSessionTickets = sendTickets

	if certChain != nil && priv != nil {
		log.Printf("Loading cert: %v key: %v", certFile, keyFile)
		config.Certificates = []*mint.Certificate{
			&mint.Certificate{
				Chain:      certChain,
				PrivateKey: priv,
			},
		}
	}
	config.Init(false)

	service := "0.0.0.0:" + port
	srv := &http.Server{Handler: handler}

	log.Printf("Listening on port %v", port)
	// Need the inner loop here because the h1 server errors on a dropped connection
	// Need the outer loop here because the h2 server is per-connection
	for {
		listener, err := mint.Listen("tcp", service, &config)
		if err != nil {
			log.Printf("Listen Error: %v", err)
			continue
		}

		if !h2 {
			err = srv.Serve(listener)
			if err != nil {
				log.Printf("Serve Error: %v", err)
			}
		} else {
			srv2 := new(http2.Server)
			opts := &http2.ServeConnOpts{
				Handler:    handler,
				BaseConfig: srv,
			}

			for {
				conn, err := listener.Accept()
				if err != nil {
					log.Printf("Accept error: %v", err)
					continue
				}
				go srv2.ServeConn(conn, opts)
			}
		}
	}
}
