//go:build !pkcs11 || !cgo
// +build !pkcs11 !cgo

package pkcs11

import "testing"

func TestEnabledIsFalse(t *testing.T) {
	if Enabled {
		t.Fatal("Enabled should be false in a build without the pkcs11 tag")
	}
}

func TestNewReportsUnavailable(t *testing.T) {
	if _, err := New("pkcs11:object=key?module-path=/x.so", "cert.pem", nil); err == nil {
		t.Fatal("New should return an error when PKCS #11 support is not built in")
	}
	if _, err := LoadSigner("pkcs11:object=key?module-path=/x.so"); err == nil {
		t.Fatal("LoadSigner should return an error when PKCS #11 support is not built in")
	}
}
