package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/bifurcation/mint"
)

var port string

func main() {
	var config mint.Config
	config.Init(false)

	flag.StringVar(&port, "port", "4430", "port")
	flag.Parse()

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
