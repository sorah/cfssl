package pkcs11uri

import (
	"bytes"
	"strings"
	"testing"
)

func TestIsPKCS11URI(t *testing.T) {
	cases := []struct {
		uri  string
		want bool
	}{
		{"pkcs11:token=foo;object=bar?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-value=1234", true},
		{"pkcs11:object=my-key", true},
		{"pkcs11:slot-id=0?module-path=/lib/mod.so", true},
		{"", false},
		{"file:/etc/ssl/key.pem", false},
		{"/etc/ssl/key.pem", false},
		{"pkcs11:", false},
		{"https://example.com", false},
	}

	for _, tc := range cases {
		if got := IsPKCS11URI(tc.uri); got != tc.want {
			t.Errorf("IsPKCS11URI(%q) = %v, want %v", tc.uri, got, tc.want)
		}
	}
}

func TestParsePKCS11URI(t *testing.T) {
	slot := 3
	uri := "pkcs11:token=My%20Token;object=signing-key;id=%01%02;serial=abc123;slot-id=3" +
		"?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-value=1234&max-sessions=5"

	parsed, err := ParsePKCS11URI(uri)
	if err != nil {
		t.Fatalf("ParsePKCS11URI returned error: %v", err)
	}

	if parsed.Token != "My Token" {
		t.Errorf("Token = %q, want %q", parsed.Token, "My Token")
	}
	if string(parsed.Object) != "signing-key" {
		t.Errorf("Object = %q, want %q", parsed.Object, "signing-key")
	}
	if !bytes.Equal(parsed.ID, []byte{0x01, 0x02}) {
		t.Errorf("ID = %v, want %v", parsed.ID, []byte{0x01, 0x02})
	}
	if parsed.Serial != "abc123" {
		t.Errorf("Serial = %q, want %q", parsed.Serial, "abc123")
	}
	if parsed.SlotID == nil || *parsed.SlotID != slot {
		t.Errorf("SlotID = %v, want %d", parsed.SlotID, slot)
	}
	if parsed.ModulePath != "/usr/lib/softhsm/libsofthsm2.so" {
		t.Errorf("ModulePath = %q", parsed.ModulePath)
	}
	if parsed.PinValue != "1234" {
		t.Errorf("PinValue = %q, want %q", parsed.PinValue, "1234")
	}
	if parsed.MaxSessions != 5 {
		t.Errorf("MaxSessions = %d, want 5", parsed.MaxSessions)
	}
}

func TestParsePKCS11URILiteralPlus(t *testing.T) {
	// RFC 7512 follows RFC 3986: a bare '+' is a literal, not a space.
	parsed, err := ParsePKCS11URI("pkcs11:object=my+key")
	if err != nil {
		t.Fatalf("ParsePKCS11URI returned error: %v", err)
	}
	if string(parsed.Object) != "my+key" {
		t.Errorf("Object = %q, want %q", parsed.Object, "my+key")
	}
}

func TestParsePKCS11URIErrorDoesNotLeakSecret(t *testing.T) {
	// A malformed URI carrying an inline pin-value must not have the
	// secret echoed back in the error (it can reach logs).
	const secret = "SuperSecretPIN123"
	_, err := ParsePKCS11URI("pkcs11:object=k?pin-value=" + secret + "&module-path=/has a space/m.so")
	if err == nil {
		t.Fatal("expected error for malformed URI")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error message leaks pin-value secret: %q", err.Error())
	}
}

func TestParsePKCS11URIErrors(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{"not a uri", "/etc/ssl/key.pem"},
		{"unknown path attr", "pkcs11:bogus=foo"},
		{"unknown query attr", "pkcs11:object=k?bogus=foo"},
		{"bad slot-id", "pkcs11:slot-id=notanumber"},
		{"negative slot-id", "pkcs11:slot-id=-1"},
		{"bad max-sessions", "pkcs11:object=k?max-sessions=lots"},
		{"negative max-sessions", "pkcs11:object=k?max-sessions=-1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePKCS11URI(tc.uri); err == nil {
				t.Errorf("ParsePKCS11URI(%q) expected error, got nil", tc.uri)
			}
		})
	}
}
