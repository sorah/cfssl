//go:build !pkcs11 || !cgo
// +build !pkcs11 !cgo

package pkcs11

import (
	"crypto"

	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/signer"
)

// Enabled is false because CFSSL was built without PKCS #11 support.
// Rebuild with `-tags pkcs11` and cgo enabled to use a PKCS #11 signer.
const Enabled = false

// New always returns an error in this build. See the Enabled constant.
func New(uri, caCertFile string, policy *config.Signing) (signer.Signer, error) {
	return nil, cferr.New(cferr.PrivateKeyError, cferr.Unavailable)
}

// LoadSigner always returns an error in this build. See the Enabled constant.
func LoadSigner(uri string) (crypto.Signer, error) {
	return nil, cferr.New(cferr.PrivateKeyError, cferr.Unavailable)
}
