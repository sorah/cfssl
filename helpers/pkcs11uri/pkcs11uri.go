// Package pkcs11uri provides a parser for the PKCS #11 URI format as
// specified in RFC 7512: The PKCS #11 URI Scheme.
//
// The parser is pure Go and has no dependency on a PKCS #11 module or
// cgo, so it is always compiled regardless of build tags. Loading an
// actual key from a parsed URI is implemented by the
// github.com/cloudflare/cfssl/signer/pkcs11 package, which is only
// available when CFSSL is built with the `pkcs11` build tag and cgo
// enabled.
package pkcs11uri

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// errEmptyOrInvalid is returned when the input is not a valid PKCS #11
// URI. It carries no copy of the input, since the input may include an
// inline pin-value secret that must not reach error output or logs.
var errEmptyOrInvalid = errors.New("pkcs11uri: input is not a valid PKCS #11 URI")

// PKCS11URI holds the attributes parsed from a PKCS #11 URI. It
// identifies a storage object such as a public key, private key, or a
// certificate, together with enough information to locate the module,
// token, and slot that provide it.
//
// The field comments reference the RFC 7512 attribute name and the
// Cryptoki structure member that backs it.
type PKCS11URI struct {
	// Path attributes.
	Token  string //        token <- CK_TOKEN_INFO
	Manuf  string // manufacturer <- CK_TOKEN_INFO
	Serial string //       serial <- CK_TOKEN_INFO
	Model  string //        model <- CK_TOKEN_INFO

	LibManuf string // library-manufacturer <- CK_INFO
	LibDesc  string //  library-description <- CK_INFO
	LibVer   string //      library-version <- CK_INFO

	Object []byte // object <- CKA_LABEL
	Type   string //   type <- CKA_CLASS
	ID     []byte //     id <- CKA_ID

	SlotManuf string // slot-manufacturer <- CK_SLOT_INFO
	SlotDesc  string //  slot-description <- CK_SLOT_INFO
	SlotID    *int   //           slot-id <- CK_SLOT_ID

	// Query attributes.
	PinSource string // pin-source
	PinValue  string //  pin-value

	ModuleName string // module-name
	ModulePath string // module-path

	// MaxSessions is a vendor-specific query attribute used to bound the
	// number of concurrent sessions opened against the module.
	MaxSessions int // max-sessions
}

// The grammar below follows RFC 7512 section 2.3. It is intentionally
// permissive about which attribute names appear; unknown names are
// rejected during parsing rather than by the regular expression.
var pkcs11URIRegexp = func() *regexp.Regexp {
	aChar := "[a-z-_]"
	pChar := `[a-zA-Z0-9-_.~%:\[\]@!\$'\(\)\*\+,=&]`
	pAttr := aChar + "+=" + pChar + "+"
	pClause := "(" + pAttr + ";)*(" + pAttr + ")"
	qChar := `[a-zA-Z0-9-_.~%:\[\]@!\$'\(\)\*\+,=/\?\|]`
	qAttr := aChar + "+=" + qChar + "+"
	qClause := "(" + qAttr + "&)*(" + qAttr + ")"

	return regexp.MustCompile("^pkcs11:" + pClause + `(\?` + qClause + ")?$")
}()

// IsPKCS11URI reports whether uri is a syntactically valid PKCS #11 URI.
// It is used to decide whether a CA key location should be interpreted
// as a PKCS #11 URI rather than a file path.
func IsPKCS11URI(uri string) bool {
	return pkcs11URIRegexp.MatchString(uri)
}

// ParsePKCS11URI decodes a PKCS #11 URI and returns it as a PKCS11URI.
//
// A PKCS #11 URI is a sequence of attribute/value pairs forming a
// one-level path component, optionally followed by a query component:
//
//	pkcs11:path-component[?query-component]
//
// Path attributes are delimited by ';' and query attributes by '&'.
// See https://tools.ietf.org/html/rfc7512#section-2.3 for the full
// grammar.
//
// An error is returned if the input does not follow the grammar or if
// it contains an unrecognized attribute.
func ParsePKCS11URI(uri string) (*PKCS11URI, error) {
	if !IsPKCS11URI(uri) {
		// The raw URI is deliberately not echoed: it may carry an inline
		// pin-value secret, and this error can reach logs.
		return nil, errEmptyOrInvalid
	}

	var parsed PKCS11URI

	body := strings.TrimPrefix(uri, "pkcs11:")
	parts := strings.SplitN(body, "?", 2)

	pathAttrs := strings.Split(parts[0], ";")
	if err := parsePathAttrs(pathAttrs, &parsed); err != nil {
		return nil, err
	}

	if len(parts) > 1 {
		queryAttrs := strings.Split(parts[1], "&")
		if err := parseQueryAttrs(queryAttrs, &parsed); err != nil {
			return nil, err
		}
	}

	return &parsed, nil
}

func splitAttr(attr string) (key, value string, err error) {
	kv := strings.SplitN(attr, "=", 2)
	if len(kv) != 2 {
		// Echo only the attribute name, never the value, which could be a
		// pin-value secret.
		return "", "", fmt.Errorf("pkcs11uri: malformed attribute %q", kv[0])
	}
	key = strings.Trim(kv[0], " \n\t\r")
	// RFC 7512 uses RFC 3986 percent-encoding, where a literal '+' is
	// not special. PathUnescape preserves it (QueryUnescape would turn
	// it into a space), which matters for byte-valued id/object.
	value, err = url.PathUnescape(strings.Trim(kv[1], " \n\t\r"))
	if err != nil {
		return "", "", fmt.Errorf("pkcs11uri: cannot unescape attribute %q: %w", key, err)
	}
	return key, value, nil
}

func parsePathAttrs(attrs []string, parsed *PKCS11URI) error {
	for _, attr := range attrs {
		key, value, err := splitAttr(attr)
		if err != nil {
			return err
		}

		switch key {
		case "token":
			parsed.Token = value
		case "manufacturer":
			parsed.Manuf = value
		case "serial":
			parsed.Serial = value
		case "model":
			parsed.Model = value
		case "library-manufacturer":
			parsed.LibManuf = value
		case "library-description":
			parsed.LibDesc = value
		case "library-version":
			parsed.LibVer = value
		case "object":
			parsed.Object = []byte(value)
		case "type":
			parsed.Type = value
		case "id":
			parsed.ID = []byte(value)
		case "slot-manufacturer":
			parsed.SlotManuf = value
		case "slot-description":
			parsed.SlotDesc = value
		case "slot-id":
			id, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("pkcs11uri: invalid slot-id %q: %w", value, err)
			}
			// CK_SLOT_ID is unsigned; reject negatives rather than passing
			// a nonsensical slot number down to the module.
			if id < 0 {
				return fmt.Errorf("pkcs11uri: slot-id must not be negative, got %d", id)
			}
			parsed.SlotID = &id
		default:
			return fmt.Errorf("pkcs11uri: unknown path attribute %q", key)
		}
	}
	return nil
}

func parseQueryAttrs(attrs []string, parsed *PKCS11URI) error {
	for _, attr := range attrs {
		key, value, err := splitAttr(attr)
		if err != nil {
			return err
		}

		switch key {
		case "pin-source":
			parsed.PinSource = value
		case "pin-value":
			parsed.PinValue = value
		case "module-name":
			parsed.ModuleName = value
		case "module-path":
			parsed.ModulePath = value
		case "max-sessions":
			maxSessions, err := strconv.Atoi(value)
			if err != nil {
				return fmt.Errorf("pkcs11uri: invalid max-sessions %q: %w", value, err)
			}
			if maxSessions < 0 {
				return fmt.Errorf("pkcs11uri: max-sessions must not be negative, got %d", maxSessions)
			}
			parsed.MaxSessions = maxSessions
		default:
			return fmt.Errorf("pkcs11uri: unknown query attribute %q", key)
		}
	}
	return nil
}
