package main

import (
	"encoding/json"
	"os"
)

func main() {
	b, _ := os.ReadFile(os.Args[1])
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		os.Exit(1)
	}
	out, _ := json.Marshal(v)
	os.Stdout.Write(out)
}
