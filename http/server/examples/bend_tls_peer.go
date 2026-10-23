// Independent net/http peer. Built only in /tmp; never linked into Grounds.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
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
	dials := 0
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}, ForceAttemptHTTP2: false,
		DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	dial := tr.DialContext
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials++
		return dial(ctx, network, address)
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	payload := bytes.Repeat([]byte{0, 255, 1, 42}, 20000)
	rows := []map[string]any{}
	for _, path := range []string{"/", "/echo", "/stream"} {
		method := "GET"
		var body io.Reader
		if path == "/echo" {
			method = "POST"
			body = bytes.NewReader(payload)
		}
		req, err := http.NewRequest(method, os.Args[2]+path, body)
		must(err)
		response, err := client.Do(req)
		must(err)
		content, err := io.ReadAll(response.Body)
		must(err)
		must(response.Body.Close())
		expected := []byte("secure\n")
		if path == "/echo" {
			expected = payload
		}
		if path == "/stream" {
			expected = []byte("first\nsecond\n")
		}
		if response.StatusCode != 200 || !bytes.Equal(content, expected) {
			panic(fmt.Sprint(path, response.StatusCode, len(content)))
		}
		hash := sha256.Sum256(content)
		rows = append(rows, map[string]any{"path": path, "bytes": len(content), "sha256": hex.EncodeToString(hash[:]), "suite": response.TLS.CipherSuite, "version": response.TLS.Version, "alpn": response.TLS.NegotiatedProtocol})
	}
	if dials != 1 {
		panic(fmt.Sprintf("want one keep-alive connection, got %d", dials))
	}
	must(json.NewEncoder(os.Stdout).Encode(map[string]any{"requests": rows, "connections": dials}))
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
