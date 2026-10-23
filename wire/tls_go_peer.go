// Independent Go crypto/tls peer for synthetic Bend interoperability only.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	role := flag.String("role", "client", "client or server")
	address := flag.String("address", "127.0.0.1:0", "loopback address")
	cert := flag.String("cert", "", "synthetic certificate")
	key := flag.String("key", "", "synthetic key")
	ca := flag.String("ca", "", "explicit synthetic trust root")
	group := flag.Int("group", 29, "selected group")
	suite := flag.Int("suite", 4865, "expected TLS 1.3 suite")
	flag.Parse()
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveID(*group)}, NextProtos: []string{"http/1.1"},
		SessionTicketsDisabled: true}
	var connection *tls.Conn
	if *role == "server" {
		pair, err := tls.LoadX509KeyPair(*cert, *key)
		fail(err)
		config.Certificates = []tls.Certificate{pair}
		listener, err := net.Listen("tcp4", *address)
		fail(err)
		defer listener.Close()
		fmt.Println("ready")
		raw, err := listener.Accept()
		fail(err)
		connection = tls.Server(raw, config)
	} else {
		roots := x509.NewCertPool()
		data, err := os.ReadFile(*ca)
		fail(err)
		if !roots.AppendCertsFromPEM(data) {
			fail(fmt.Errorf("invalid test CA"))
		}
		config.RootCAs, config.ServerName = roots, "localhost"
		raw, err := net.DialTimeout("tcp4", *address, 5*time.Second)
		fail(err)
		connection = tls.Client(raw, config)
	}
	defer connection.Close()
	fail(connection.SetDeadline(time.Now().Add(15 * time.Second)))
	fail(connection.Handshake())
	state := connection.ConnectionState()
	if int(state.CipherSuite) != *suite || int(state.CurveID) != *group || state.NegotiatedProtocol != "http/1.1" {
		fail(fmt.Errorf("unexpected negotiation: suite=%d group=%d ALPN=%q", state.CipherSuite, state.CurveID, state.NegotiatedProtocol))
	}
	if *role == "client" {
		_, err := connection.Write([]byte("ping"))
		fail(err)
	}
	var received [4]byte
	_, err := io.ReadFull(connection, received[:])
	fail(err)
	if *role == "server" {
		if string(received[:]) != "ping" {
			fail(fmt.Errorf("bad application input"))
		}
		_, err := connection.Write([]byte("pong"))
		fail(err)
	}
	fail(json.NewEncoder(os.Stdout).Encode(map[string]any{"suite": state.CipherSuite,
		"group": state.CurveID, "alpn": state.NegotiatedProtocol, "application": string(received[:]),
		"verification": *role == "client" && len(state.VerifiedChains) > 0}))
	if *role == "client" {
		var end [1]byte
		_, err := connection.Read(end[:])
		if err != io.EOF {
			fail(fmt.Errorf("missing close_notify: %v", err))
		}
	}
}
