package main

import (
	"fmt"
	"log"

	tlsSession "trieutrng.com/toy-tls/session"
)

func main() {
	domain := "trieutrng.github.io"
	var err error

	session, err := tlsSession.NewSession(domain)
	if err != nil {
		log.Fatalf("%s", err)
	}

	err = session.Write([]byte("hello world"))
	if err != nil {
		log.Fatalf("%s", err)
	}

	data, err := session.Read()
	if err != nil {
		log.Fatalf("%s", err)
	}

	fmt.Println(string(data))
}
