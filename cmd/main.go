package main

import (
	"fmt"

	log "github.com/sirupsen/logrus"
	tlsSession "trieutrng.com/toy-tls/session"
)

func init() {
	log.SetLevel(log.DebugLevel)
}

func main() {
	domain := "jvns.ca"
	var err error

	session, err := tlsSession.NewSession(domain)
	if err != nil {
		log.Fatalf("Can't init new tls session - Caused by: %s", err)
	}

	err = session.Write([]byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", domain)))
	if err != nil {
		log.Fatalf("%s", err)
	}

	data, err := session.Read()
	if err != nil {
		log.Fatalf("%s", err)
	}

	fmt.Println(string(data))
}
