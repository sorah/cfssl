// Package keyload resolves a CA signing key from a "locator" string into
// a crypto.Signer. A locator is either an RFC 7512 pkcs11: URI (loaded
// from a PKCS #11 token via signer/pkcs11, which requires the `pkcs11`
// build tag and cgo) or a PEM key file/env input in the usual CFSSL
// "[file:]name" / "env:name" forms.
//
// It exists so the commands that consume a CA key directly (initca,
// crl, the served CRL endpoint) can accept a pkcs11: key without each
// duplicating the URI-vs-file branch.
package keyload

import (
	"crypto"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/pkcs11uri"
	"github.com/cloudflare/cfssl/signer/pkcs11"
)

// LoadSigner returns a crypto.Signer for the given key locator. When the
// locator is a pkcs11: URI the password argument is ignored, since the
// token PIN is carried by the URI itself.
func LoadSigner(locator string, password []byte) (crypto.Signer, error) {
	if pkcs11uri.IsPKCS11URI(locator) {
		return pkcs11.LoadSigner(locator)
	}

	data, err := helpers.ReadBytes(locator)
	if err != nil {
		return nil, err
	}
	return helpers.ParsePrivateKeyPEMWithPassword(data, password)
}
