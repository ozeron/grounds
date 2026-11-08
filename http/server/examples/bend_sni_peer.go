// Independent Go crypto/tls SNI peer. Built only in a temporary directory.
// Usage: bend_sni_peer ca.pem 127.0.0.1:port server-name
// Full chain and hostname verification against ca.pem; prints one JSON row.
package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(os.Args[1])
	must(err)
	if !roots.AppendCertsFromPEM(pem) {
		panic("CA import")
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp4", os.Args[2], &tls.Config{RootCAs: roots, ServerName: os.Args[3],
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}})
	if err != nil {
		out(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer conn.Close()
	must(conn.SetDeadline(time.Now().Add(10 * time.Second)))
	state := conn.ConnectionState()
	leaf := sha256.Sum256(state.PeerCertificates[0].Raw)
	_, err = fmt.Fprintf(conn, "GET /whoami HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", os.Args[3])
	must(err)
	body, err := io.ReadAll(bufio.NewReader(conn))
	must(err)
	out(map[string]any{"ok": true, "leaf_sha256": hex.EncodeToString(leaf[:]), "version": state.Version,
		"alpn": state.NegotiatedProtocol, "response": string(body)})
}

func out(row map[string]any) {
	encoded, err := json.Marshal(row)
	must(err)
	fmt.Println(string(encoded))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
