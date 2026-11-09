// Independent Go crypto/tls TLS 1.2 server for synthetic Bend client interop only.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func fail(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main() {
	cert := flag.String("cert", "", "synthetic certificate")
	key := flag.String("key", "", "synthetic key")
	suite := flag.Int("suite", 0, "the only TLS 1.2 suite (0: Go defaults)")
	group := flag.Int("group", 29, "the only curve")
	max := flag.Int("max", 0x0303, "maximum version")
	flag.Parse()
	pair, err := tls.LoadX509KeyPair(*cert, *key)
	fail(err)
	config := &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12,
		MaxVersion: uint16(*max), CurvePreferences: []tls.CurveID{tls.CurveID(*group)},
		NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
	if *suite != 0 {
		config.CipherSuites = []uint16{uint16(*suite)}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	fail(err)
	defer listener.Close()
	fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	raw, err := listener.Accept()
	fail(err)
	connection := tls.Server(raw, config)
	defer connection.Close()
	fail(connection.SetDeadline(time.Now().Add(15 * time.Second)))
	fail(connection.Handshake())
	var received [4]byte
	_, err = io.ReadFull(connection, received[:])
	fail(err)
	if string(received[:]) != "ping" {
		fail(fmt.Errorf("bad application input"))
	}
	_, err = connection.Write([]byte("pong"))
	fail(err)
	state := connection.ConnectionState()
	fmt.Printf("{\"version\":%d,\"suite\":%d,\"alpn\":%q}\n", state.Version, state.CipherSuite, state.NegotiatedProtocol)
}
