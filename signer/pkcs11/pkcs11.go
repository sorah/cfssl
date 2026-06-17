//go:build pkcs11 && cgo
// +build pkcs11,cgo

package pkcs11

import (
	"crypto"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ThalesIgnite/crypto11"
	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/pkcs11uri"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

// Enabled is true when CFSSL is built with PKCS #11 support.
const Enabled = true

// New returns a local signer whose private key lives in a PKCS #11
// token identified by uri, paired with the CA certificate read from
// caCertFile. caCertFile accepts the same "[file:]name" / "env:name"
// forms as other CFSSL certificate inputs.
func New(uri, caCertFile string, policy *config.Signing) (signer.Signer, error) {
	priv, err := LoadSigner(uri)
	if err != nil {
		return nil, err
	}

	certData, err := helpers.ReadBytes(caCertFile)
	if err != nil {
		return nil, cferr.Wrap(cferr.CertificateError, cferr.ReadFailed, err)
	}

	cert, err := helpers.ParseCertificatePEM(certData)
	if err != nil {
		return nil, err
	}

	return local.NewSigner(priv, cert, signer.DefaultSigAlgo(priv), policy)
}

// LoadSigner parses a PKCS #11 URI and returns a crypto.Signer backed
// by the key pair it identifies. It is exported so callers that only
// need the key (rather than a full CFSSL signer) can reuse it.
func LoadSigner(uri string) (crypto.Signer, error) {
	parsed, err := pkcs11uri.ParsePKCS11URI(uri)
	if err != nil {
		return nil, cferr.Wrap(cferr.PrivateKeyError, cferr.ParseFailed, err)
	}

	modulePath := parsed.ModulePath
	if modulePath == "" {
		// module-name refers to a module configured in the system
		// pkcs11 config; module-path points directly at the shared
		// library. crypto11 only understands the latter, so a bare
		// module-name cannot be resolved here.
		return nil, cferr.Wrap(cferr.PrivateKeyError, cferr.ReadFailed,
			fmt.Errorf("pkcs11 URI must specify module-path (module-name is not supported)"))
	}

	pin, err := resolvePIN(parsed)
	if err != nil {
		return nil, err
	}

	cfg := &crypto11.Config{
		Path:            modulePath,
		TokenSerial:     parsed.Serial,
		TokenLabel:      parsed.Token,
		SlotNumber:      parsed.SlotID,
		Pin:             pin,
		MaxSessions:     parsed.MaxSessions,
		PoolWaitTimeout: 10 * time.Second,
	}
	// crypto11 reserves one session for its own background use, so the
	// effective minimum that still leaves a session for signing is 2.
	if cfg.MaxSessions < 2 {
		cfg.MaxSessions = 2
	}

	log.Debugf("loading PKCS #11 module %s", modulePath)
	ctx, err := crypto11.Configure(cfg)
	if err != nil {
		return nil, cferr.Wrap(cferr.PrivateKeyError, cferr.ReadFailed, fmt.Errorf("pkcs11 configure: %w", err))
	}

	priv, err := ctx.FindKeyPair(parsed.ID, parsed.Object)
	if err != nil {
		return nil, cferr.Wrap(cferr.PrivateKeyError, cferr.ReadFailed, fmt.Errorf("pkcs11 find key pair: %w", err))
	}
	if priv == nil {
		return nil, cferr.Wrap(cferr.PrivateKeyError, cferr.ReadFailed,
			fmt.Errorf("pkcs11 key pair not found for the given id/object"))
	}

	return priv, nil
}

// resolvePIN returns the token PIN, preferring an inline pin-value and
// falling back to the pin-source reference. A pin-source may be:
//
//   - env:NAME       read the PIN from the NAME environment variable
//     (a CFSSL extension to RFC 7512, mirroring the env:
//     convention used for other CFSSL inputs)
//   - a file: URI    file:/path, file:///path, or file://host/path
//     (RFC 8089)
//   - a bare path    treated as a file path
//
// For env and file sources a trailing CR/LF is stripped so a PIN file
// or variable written with a trailing newline still works.
func resolvePIN(parsed *pkcs11uri.PKCS11URI) (string, error) {
	if parsed.PinValue != "" {
		return parsed.PinValue, nil
	}
	if parsed.PinSource == "" {
		return "", nil
	}

	if name := strings.TrimPrefix(parsed.PinSource, "env:"); name != parsed.PinSource {
		return strings.TrimRight(os.Getenv(name), "\r\n"), nil
	}

	path := parsed.PinSource
	if u, err := url.Parse(path); err == nil && u.Scheme == "file" {
		// u.Opaque covers the file:relative form; u.Path covers the
		// absolute and authority forms.
		if u.Opaque != "" {
			path = u.Opaque
		} else {
			path = u.Path
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "", cferr.Wrap(cferr.PrivateKeyError, cferr.ReadFailed, fmt.Errorf("pkcs11 pin-source: %w", err))
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}
