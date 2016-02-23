package main

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/bifurcation/mint"
)

func main() {
	mintdial := func(network, addr string) (net.Conn, error) {
		return mint.Dial(network, addr, nil)
	}

	tr := &http.Transport{
		DialTLS:            mintdial,
		DisableCompression: true,
	}
	client := &http.Client{Transport: tr}

	response, err := client.Get("https://localhost:4430/")
	if err != nil {
		fmt.Println("err:", err)
		return
	}

	fmt.Println("==== RESPONSE ====")
	err = response.Write(os.Stdout)
	if err != nil {
		fmt.Println("err:", err)
		return
	}
}
