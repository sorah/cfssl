//go:build pkcs11 && cgo
// +build pkcs11,cgo

package keyload

import (
	"strings"
	"testing"
)

// With pkcs11 support compiled in, a pkcs11: URI must route to the real
// PKCS #11 loader rather than being read as a file. Without a token it
// fails while configuring the (bogus) module, which still proves the
// routing: a file-path mistake would instead yield an "unknown prefix"
// or PEM-parse error.
func TestLoadSignerPKCS11Routes(t *testing.T) {
	_, err := LoadSigner("pkcs11:token=t;object=k?module-path=/nonexistent-module.so", nil)
	if err == nil {
		t.Fatal("expected error loading from a nonexistent pkcs11 module")
	}
	if !strings.Contains(err.Error(), "pkcs11") {
		t.Errorf("expected a pkcs11 loader error, got: %v", err)
	}
}
