//go:build !pkcs11 || !cgo
// +build !pkcs11 !cgo

package keyload

import (
	"strings"
	"testing"
)

// In a build without the pkcs11 tag, a pkcs11: URI must route to the
// PKCS #11 signer stub and fail cleanly as unavailable, never being
// mistaken for a file path.
func TestLoadSignerPKCS11Unavailable(t *testing.T) {
	_, err := LoadSigner("pkcs11:token=t;object=k?module-path=/x.so", nil)
	if err == nil {
		t.Fatal("expected error for pkcs11 URI in a build without pkcs11 support")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "unavailable") {
		t.Errorf("expected an 'unavailable' error, got: %v", err)
	}
}
