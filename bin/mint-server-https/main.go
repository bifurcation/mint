package main

import (
	"crypto"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/bifurcation/mint"
	"github.com/cloudflare/cfssl/helpers"
)

var (
	port       string
	serverName string
	certFile   string
	keyFile    string
)

func main() {
	flag.StringVar(&port, "port", "4430", "port")
	flag.StringVar(&serverName, "host", "example.com", "hostname")
	flag.StringVar(&certFile, "cert", "", "certificate chain in PEM or DER")
	flag.StringVar(&keyFile, "key", "", "private key in PEM format")
	flag.Parse()

	var certChain []*x509.Certificate
	var priv crypto.Signer
	var err error

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

	http.HandleFunc("/", handleClient)
	s := &http.Server{}
	s.Serve(listener)
}

func handleClient(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Welcome to the TLS 1.3 zone!")
}
