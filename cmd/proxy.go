package main

import (
	"github.com/kanopeld/go-socks5"
	"os"
)

func main() {
	// Create a SOCKS5 server
	conf := &socks5.Config{}
	server, err := socks5.New(conf)
	if err != nil {
		panic(err)
	}

	// Create SOCKS5 proxy on localhost port 8000
	if err := server.ListenAndServe("tcp", ":"+os.Getenv("PROXY_PORT")); err != nil {
		panic(err)
	}
}
