//go:build pkcs11 && cgo
// +build pkcs11,cgo

package pkcs11

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/cfssl/helpers/pkcs11uri"
)

func TestResolvePIN(t *testing.T) {
	dir := t.TempDir()
	pinFile := filepath.Join(dir, "pin")
	if err := os.WriteFile(pinFile, []byte("file-pin\n"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CFSSL_TEST_PKCS11_PIN", "env-pin\n")
	t.Setenv("CFSSL_TEST_PKCS11_PIN_EMPTY", "")

	cases := []struct {
		name      string
		uri       *pkcs11uri.PKCS11URI
		want      string
		expectErr bool
	}{
		{"pin-value takes precedence", &pkcs11uri.PKCS11URI{PinValue: "inline", PinSource: pinFile}, "inline", false},
		{"no pin", &pkcs11uri.PKCS11URI{}, "", false},
		{"bare path pin-source", &pkcs11uri.PKCS11URI{PinSource: pinFile}, "file-pin", false},
		{"file: prefixed pin-source", &pkcs11uri.PKCS11URI{PinSource: "file:" + pinFile}, "file-pin", false},
		{"file:// authority form", &pkcs11uri.PKCS11URI{PinSource: "file://" + pinFile}, "file-pin", false},
		{"env: pin-source", &pkcs11uri.PKCS11URI{PinSource: "env:CFSSL_TEST_PKCS11_PIN"}, "env-pin", false},
		{"env: unset variable", &pkcs11uri.PKCS11URI{PinSource: "env:CFSSL_TEST_PKCS11_PIN_EMPTY"}, "", false},
		{"missing file", &pkcs11uri.PKCS11URI{PinSource: filepath.Join(dir, "nope")}, "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolvePIN(tc.uri)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got pin %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("resolvePIN = %q, want %q", got, tc.want)
			}
		})
	}
}
