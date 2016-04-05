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
)

var (
	port         string
	serverName   string
	certFile     string
	keyFile      string
	responseFile string
)

func main() {
	flag.StringVar(&port, "port", "4430", "port")
	flag.StringVar(&serverName, "host", "example.com", "hostname")
	flag.StringVar(&certFile, "cert", "", "certificate chain in PEM or DER")
	flag.StringVar(&keyFile, "key", "", "private key in PEM format")
	flag.StringVar(&responseFile, "response", "", "file to serve")
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

	config := mint.Config{
		SendSessionTickets: true,
		ServerName:         serverName,
	}

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
	listener, err := mint.Listen("tcp", service, &config)

	if err != nil {
		log.Printf("Error: %v", err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write(response)
	})

	s := &http.Server{}
	s.Serve(listener)
}
