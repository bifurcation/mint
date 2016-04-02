package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/bifurcation/mint"
)

var (
	port       string
	serverName string
	certFile   string
	keyFile    string
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
	flag.Parse()

	var cert []byte
	var key []byte
	var err error

	if certFile != "" {
		certPEM, err := ioutil.ReadFile(certFile)
		if err == nil {
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

	config := mint.Config{
		SendSessionTickets: true,
		ServerName:         serverName,
	}

	if cert != nil && key != nil {
		log.Printf("Loading cert: %v key: %v", certFile, keyFile)
		x5cert, err := x509.ParseCertificate(cert)
		if err != nil {
			log.Fatalf("Error parsing cert: %v, %v", cert, err)
		}
		priv, err := parsePrivateKey(key)
		if err != nil {
			log.Fatalf("Error parsing key: %v", key, err)
		}

		log.Printf("x5cert %v", x5cert.DNSNames)
		config.Certificates = []*mint.Certificate{
			&mint.Certificate{
				Chain:      []*x509.Certificate{x5cert},
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
	fmt.Fprintln(w, "Hi there!")
}
