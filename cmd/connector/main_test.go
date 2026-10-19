package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestMainVersionFlag(t *testing.T) {
	cmd := exec.Command("go", "run", "main.go", "-version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run main.go -version failed: %v, output: %s", err, string(out))
	}

	if !strings.Contains(string(out), "anchor-connector v0.1.0") {
		t.Fatalf("unexpected version output: %s", string(out))
	}
}
