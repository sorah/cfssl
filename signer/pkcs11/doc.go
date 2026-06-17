// Package pkcs11 implements a CFSSL local signer backed by a private
// key stored in a PKCS #11 token (for example, a hardware security
// module). The key is identified by a PKCS #11 URI as specified in RFC
// 7512; see github.com/cloudflare/cfssl/helpers/pkcs11uri for the URI
// format.
//
// PKCS #11 support relies on cgo and a Cryptoki module loaded at
// runtime. To keep the default CFSSL build free of a cgo dependency,
// the real implementation is only compiled when CFSSL is built with the
// `pkcs11` build tag and cgo enabled:
//
//	go build -tags pkcs11 ./cmd/cfssl
//
// Without that build tag the New function is a stub that reports the
// feature as unavailable, and the Enabled constant is false.
//
// Operators should fully qualify the signing key in the URI: when the
// id/object selector matches more than one key pair, or the token
// selector matches more than one token, the underlying module picks the
// first match, which for a CA key is an unwanted ambiguity. Pair a
// unique id (or object) with a token or serial to make selection
// deterministic. A pin-source file should be readable only by the CFSSL
// user (mode 0600).
package pkcs11
