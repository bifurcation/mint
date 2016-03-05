package main

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/bifurcation/mint"
)

func main() {
	flagURL := flag.String("URL", "https://localhost:4430", "URL to send request")
	flag.Parse()
	mintdial := func(network, addr string) (net.Conn, error) {
		return mint.Dial(network, addr, nil)
	}

	tr := &http.Transport{
		DialTLS:            mintdial,
		DisableCompression: true,
	}
	client := &http.Client{Transport: tr}

	response, err := client.Get(*flagURL)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
	defer response.Body.Close()

	err = response.Write(os.Stdout)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
}
