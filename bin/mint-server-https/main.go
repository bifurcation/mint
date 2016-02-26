package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/bifurcation/mint"
)

func main() {
	service := "0.0.0.0:4430"
	listener, err := mint.Listen("tcp", service, &mint.Config{})

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
