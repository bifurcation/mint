package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/bifurcation/mint"
)

var (
	port         string
	serverName   string
	certFile     string
	keyFile      string
	responseFile string
)

func parsePrivateKey(pemBytes []byte) (crypto.Signer, error) {
	keyDERBlock, _ := pem.Decode(pemBytes)

	if key, err := x509.ParsePKCS1PrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(keyDERBlock.Bytes); err == nil {
		return key, nil
	}
	return nil, errors.New("need a DER key")
}

func main() {
	flag.StringVar(&port, "port", "4430", "port")
	flag.StringVar(&serverName, "name", "example.com", "hostname")
	flag.StringVar(&certFile, "cert", "", "certificate")
	flag.StringVar(&keyFile, "key", "", "key")
	flag.StringVar(&responseFile, "response", "", "response")
	flag.Parse()

	var cert []byte
	var key []byte
	var err error
	var response []byte

	if certFile != "" {
		certPEM, err := ioutil.ReadFile(certFile)
		if err != nil {
			var certBlock *pem.Block
			certBlock, _ = pem.Decode(certPEM)
			cert = certBlock.Bytes
		}
	}
	if keyFile != "" {
		key, err = ioutil.ReadFile(keyFile)
	}
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	if responseFile != "" {
		response, err = ioutil.ReadFile(responseFile)
		if err != nil {
			log.Fatalf("Error: %v", err)
		}
	} else {
		response = []byte("Hello There!\n")
	}

	config := mint.Config{
		SendSessionTickets: true,
		ServerName:         serverName,
	}

	log.Printf("Loading cert: %v key: %v", certFile, keyFile)
	if cert != nil && key != nil {
		log.Printf("Loading cert: %v key: %v", certFile, keyFile)
		x5cert, err := x509.ParseCertificate(cert)
		if err != nil {
			log.Fatalf("Error parsing cert: %v, %v", cert, err)
		}
		chain := []*x509.Certificate{x5cert}
		priv, err := parsePrivateKey(key)
		if err != nil {
			log.Fatalf("Error parsing key: %v", key, err)
		}

		configCert := mint.Certificate{
			Chain:      chain,
			PrivateKey: priv,
		}
		config.Certificates = []*mint.Certificate{&configCert}
	}
	config.Init(false)

	service := "0.0.0.0:" + port
	listener, err := mint.Listen("tcp", service, &config)

	if err != nil {
		log.Printf("Error: %v", err)
	}

	http.HandleFunc("/",
		func(w http.ResponseWriter, r *http.Request) {
			w.Write(response)
		})

	s := &http.Server{}
	s.Serve(listener)
}
