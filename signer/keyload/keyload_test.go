package keyload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writeTestKey(t *testing.T) (path string, want *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "ca-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return path, key
}

func TestLoadSignerPEMFile(t *testing.T) {
	path, want := writeTestKey(t)

	signer, err := LoadSigner(path, nil)
	if err != nil {
		t.Fatalf("LoadSigner returned error: %v", err)
	}
	if !want.PublicKey.Equal(signer.Public()) {
		t.Error("loaded signer public key does not match the written key")
	}
}

func TestLoadSignerMissingFile(t *testing.T) {
	if _, err := LoadSigner(filepath.Join(t.TempDir(), "nope.pem"), nil); err == nil {
		t.Fatal("expected error loading a non-existent key file")
	}
}
