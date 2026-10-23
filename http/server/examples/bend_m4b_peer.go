// Independent Go standard-library HTTPS and WSS peers (synthetic fixtures).
package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	if os.Args[1] == "server" {
		certificate, err := tls.LoadX509KeyPair(os.Args[2], os.Args[3])
		must(err)
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		must(err)
		fmt.Println(listener.Addr().String())
		server := &http.Server{ReadHeaderTimeout: 3 * time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "go peer") })}
		must(server.Serve(tls.NewListener(listener, server.TLSConfig)))
		return
	}
	ca, err := os.ReadFile(os.Args[2])
	must(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		panic("invalid CA")
	}
	conn, err := tls.Dial("tcp4", os.Args[3], &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}})
	must(err)
	defer conn.Close()
	must(conn.SetDeadline(time.Now().Add(5 * time.Second)))
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	_, err = fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nOrigin: https://grounds.test\r\nAuthorization: Bearer synthetic\r\nCookie: %s\r\n\r\n", key, os.Args[4])
	must(err)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	must(err)
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if response.StatusCode != 101 || response.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(sum[:]) {
		panic("upgrade rejected")
	}
	for _, op := range []byte{1, 2, 9, 8} {
		payload := []byte("go echo")
		if op == 8 {
			payload = make([]byte, 2)
			binary.BigEndian.PutUint16(payload, 1000)
		}
		mask := []byte{1, 2, 3, 4}
		frame := []byte{0x80 | op, 0x80 | byte(len(payload))}
		frame = append(frame, mask...)
		for i, b := range payload {
			frame = append(frame, b^mask[i%4])
		}
		_, err = conn.Write(frame)
		must(err)
		head := make([]byte, 2)
		_, err = io.ReadFull(reader, head)
		must(err)
		want := op
		if op == 9 {
			want = 10
		}
		if head[0] != 0x80|want || head[1] != byte(len(payload)) {
			panic("frame header")
		}
		body := make([]byte, len(payload))
		_, err = io.ReadFull(reader, body)
		must(err)
		if string(body) != string(payload) {
			panic("frame payload")
		}
	}
	if _, err = reader.ReadByte(); err != io.EOF {
		panic(fmt.Sprintf("missing close_notify: %v", err))
	}
	fmt.Println("Go WSS: verified upgrade, text/binary, ping/pong, close_notify")
}
