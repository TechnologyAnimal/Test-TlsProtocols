//go:build integration

package scanner

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestProtocolByName(t *testing.T) {
	tests := []struct {
		name  string
		found bool
	}{
		{"Tls12", true},
		{"tls12", true},
		{"Tls13", true},
		{"Ssl3", true},
		{"InvalidProto", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := ProtocolByName(tt.name)
			if ok != tt.found {
				t.Errorf("ProtocolByName(%q) = _, %v; want %v", tt.name, ok, tt.found)
			}
		})
	}
}

func TestSupportedProtocolNames(t *testing.T) {
	names := SupportedProtocolNames()
	if len(names) != 5 {
		t.Errorf("expected 5 protocols, got %d", len(names))
	}
	expected := []string{"Ssl3", "Tls10", "Tls11", "Tls12", "Tls13"}
	for i, name := range expected {
		if names[i] != name {
			t.Errorf("protocol[%d] = %q; want %q", i, names[i], name)
		}
	}
}

func TestCheckDeprecated(t *testing.T) {
	s := New(Options{
		Server:    "example.com",
		Ports:     []int{443},
		Protocols: []string{"Ssl3", "Tls10", "Tls12"},
		Timeout:   2 * time.Second,
	})
	s.CheckDeprecated()

	if len(s.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(s.Warnings))
	}
	if !strings.Contains(s.Warnings[0], "Ssl3") {
		t.Errorf("warning should mention Ssl3: %s", s.Warnings[0])
	}
	if !strings.Contains(s.Warnings[0], "Tls10") {
		t.Errorf("warning should mention Tls10: %s", s.Warnings[0])
	}
	// The warning lists deprecated protocols before "Consider using", so check only that prefix
	deprecatedPart := strings.Split(s.Warnings[0], ".")[0]
	if strings.Contains(deprecatedPart, "Tls12") {
		t.Errorf("warning should NOT list Tls12 as deprecated: %s", s.Warnings[0])
	}
}

func TestCheckDeprecatedNone(t *testing.T) {
	s := New(Options{
		Server:    "example.com",
		Ports:     []int{443},
		Protocols: []string{"Tls12", "Tls13"},
		Timeout:   2 * time.Second,
	})
	s.CheckDeprecated()

	if len(s.Warnings) != 0 {
		t.Errorf("expected no warnings, got %d: %v", len(s.Warnings), s.Warnings)
	}
}

func TestResolveServerFQDN(t *testing.T) {
	s := New(Options{Server: "google.com", Ports: []int{443}, Timeout: 5 * time.Second})
	fqdn, ip, err := s.ResolveServer()
	if err != nil {
		t.Fatalf("ResolveServer() error: %v", err)
	}
	if fqdn != "google.com" {
		t.Errorf("fqdn = %q; want 'google.com'", fqdn)
	}
	if ip == "" {
		t.Error("ip should not be empty")
	}
}

func TestResolveServerIP(t *testing.T) {
	s := New(Options{Server: "8.8.8.8", Ports: []int{443}, Timeout: 5 * time.Second})
	fqdn, ip, err := s.ResolveServer()
	if err != nil {
		t.Fatalf("ResolveServer() error: %v", err)
	}
	if ip != "8.8.8.8" {
		t.Errorf("ip = %q; want '8.8.8.8'", ip)
	}
	if fqdn == "" {
		t.Error("fqdn should not be empty")
	}
}

func TestResolveServerInvalid(t *testing.T) {
	s := New(Options{Server: "this-does-not-exist-12345.invalid", Ports: []int{443}, Timeout: 5 * time.Second})
	_, _, err := s.ResolveServer()
	if err == nil {
		t.Error("expected error for invalid server, got nil")
	}
}

func TestScanTls12(t *testing.T) {
	s := New(Options{
		Server:               "google.com",
		Ports:                []int{443},
		Protocols:            []string{"Tls12"},
		Timeout:              5 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	r := results[0]
	if r.FQDN != "google.com" {
		t.Errorf("FQDN = %q; want 'google.com'", r.FQDN)
	}
	if r.Port != 443 {
		t.Errorf("Port = %d; want 443", r.Port)
	}
	if len(r.Protocols) != 1 {
		t.Fatalf("expected 1 protocol result, got %d", len(r.Protocols))
	}
	if !r.Protocols[0].Success {
		t.Error("Tls12 should succeed for google.com")
	}
	if r.Cipher == nil {
		t.Error("Cipher info should be present")
	} else if r.Cipher.NegotiatedCipherSuite == "" {
		t.Error("NegotiatedCipherSuite should not be empty")
	}
}

func TestScanSsl3Fails(t *testing.T) {
	s := New(Options{
		Server:               "google.com",
		Ports:                []int{443},
		Protocols:            []string{"Ssl3"},
		Timeout:              5 * time.Second,
		IgnoreCertValidation: true,
		IncludeErrors:        true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if r.Protocols[0].Success {
		t.Error("Ssl3 should fail for google.com")
	}
	if r.Protocols[0].ErrorMsg == "" {
		t.Error("ErrorMsg should be present when IncludeErrors is true")
	}
}

func TestScanWithCertInfo(t *testing.T) {
	s := New(Options{
		Server:               "github.com",
		Ports:                []int{443},
		Protocols:            []string{"Tls12"},
		Timeout:              5 * time.Second,
		IgnoreCertValidation: true,
		IncludeCertInfo:      true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if r.Cert == nil {
		t.Fatal("Cert info should be present")
	}
	if r.Cert.Subject == "" {
		t.Error("Subject should not be empty")
	}
	if r.Cert.Issuer == "" {
		t.Error("Issuer should not be empty")
	}
	if r.Cert.Thumbprint == "" {
		t.Error("Thumbprint should not be empty")
	}
}

func TestScanUnreachablePort(t *testing.T) {
	s := New(Options{
		Server:    "google.com",
		Ports:     []int{9999},
		Protocols: []string{"Tls12"},
		Timeout:   2 * time.Second,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if r.Protocols[0].Success {
		t.Error("should not succeed on unreachable port")
	}
}

func TestScanMultiplePorts(t *testing.T) {
	s := New(Options{
		Server:               "google.com",
		Ports:                []int{443, 80},
		Protocols:            []string{"Tls12"},
		Timeout:              5 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestScanMultipleProtocols(t *testing.T) {
	s := New(Options{
		Server:               "google.com",
		Ports:                []int{443},
		Protocols:            []string{"Tls12", "Tls13"},
		Timeout:              5 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if len(r.Protocols) != 2 {
		t.Fatalf("expected 2 protocol results, got %d", len(r.Protocols))
	}
}

// Output format tests

func TestWriteJSON(t *testing.T) {
	results := []ScanResult{{
		FQDN: "test.com",
		IP:   "1.2.3.4",
		Port: 443,
		Protocols: []ProtocolResult{
			{Name: "Tls12", Success: true},
		},
		Cipher: &CipherInfo{NegotiatedCipherSuite: "TLS_AES_128_GCM_SHA256"},
	}}

	var buf bytes.Buffer
	err := WriteJSON(&buf, results, []string{"Tls12"}, false)
	if err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "test.com") {
		t.Error("JSON should contain FQDN")
	}
	if !strings.Contains(output, "TLS_AES_128_GCM_SHA256") {
		t.Error("JSON should contain cipher suite")
	}

	// Verify it's valid JSON-ish (our ordered output)
	if !strings.Contains(output, "\"fqdn\"") {
		t.Error("JSON should contain fqdn key")
	}
}

func TestWriteCSV(t *testing.T) {
	results := []ScanResult{{
		FQDN: "test.com",
		IP:   "1.2.3.4",
		Port: 443,
		Protocols: []ProtocolResult{
			{Name: "Tls12", Success: true},
			{Name: "Tls13", Success: false},
		},
		Cipher: &CipherInfo{NegotiatedCipherSuite: "TLS_AES_128_GCM_SHA256"},
	}}

	var buf bytes.Buffer
	err := WriteCSV(&buf, results, []string{"Tls12", "Tls13"}, false)
	if err != nil {
		t.Fatalf("WriteCSV error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 CSV lines (header + data), got %d", len(lines))
	}
	if !strings.Contains(lines[0], "FQDN") {
		t.Error("CSV header should contain FQDN")
	}
	if !strings.Contains(lines[1], "test.com") {
		t.Error("CSV data should contain test.com")
	}
}

func TestWriteText(t *testing.T) {
	results := []ScanResult{{
		FQDN: "test.com",
		IP:   "1.2.3.4",
		Port: 443,
		Protocols: []ProtocolResult{
			{Name: "Tls12", Success: true},
		},
	}}

	var buf bytes.Buffer
	WriteText(&buf, results, []string{"Tls12"}, false)

	output := buf.String()
	if !strings.Contains(output, "test.com") {
		t.Error("text should contain FQDN")
	}
	if !strings.Contains(output, "true") {
		t.Error("text should contain 'true' for Tls12")
	}
}

func TestFlattenWithErrors(t *testing.T) {
	r := ScanResult{
		FQDN: "test.com",
		IP:   "1.2.3.4",
		Port: 443,
		Protocols: []ProtocolResult{
			{Name: "Ssl3", Success: false, ErrorMsg: "protocol not supported"},
		},
	}

	f := Flatten(r, true)
	if f.ErrorMsgs["Ssl3ErrorMsg"] != "protocol not supported" {
		t.Errorf("expected error msg, got %q", f.ErrorMsgs["Ssl3ErrorMsg"])
	}
}

func TestExportCertPEM(t *testing.T) {
	// Test with a nil cert should not panic
	s := New(Options{
		Server:               "github.com",
		Ports:                []int{443},
		Protocols:            []string{"Tls12"},
		Timeout:              5 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if results[0].RawCert == nil {
		t.Fatal("expected raw cert")
	}

	pem := ExportCertPEM(results[0].RawCert)
	if !strings.Contains(string(pem), "BEGIN CERTIFICATE") {
		t.Error("PEM should contain BEGIN CERTIFICATE")
	}

	der := ExportCertDER(results[0].RawCert)
	if len(der) == 0 {
		t.Error("DER should not be empty")
	}
}

func TestIsFIPSCipherSuite(t *testing.T) {
	tests := []struct {
		name string
		id   uint16
		fips bool
	}{
		{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xc02f, true},
		{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xc02c, true},
		{"TLS_AES_128_GCM_SHA256", 0x1301, true},
		{"TLS_AES_256_GCM_SHA384", 0x1302, true},
		{"TLS_CHACHA20_POLY1305_SHA256", 0x1303, false},
		{"TLS_RSA_WITH_AES_128_CBC_SHA", 0x002f, false},
		{"Unknown", 0x0000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsFIPSCipherSuite(tt.id); got != tt.fips {
				t.Errorf("IsFIPSCipherSuite(0x%04x) = %v; want %v", tt.id, got, tt.fips)
			}
		})
	}
}

func TestFIPSCipherSuiteIDs(t *testing.T) {
	ids := FIPSCipherSuiteIDs()
	if len(ids) == 0 {
		t.Fatal("FIPSCipherSuiteIDs should return at least one suite")
	}
	for _, id := range ids {
		if !IsFIPSCipherSuite(id) {
			t.Errorf("FIPSCipherSuiteIDs returned 0x%04x which is not FIPS-approved", id)
		}
	}
}

func TestScanFIPSOnly(t *testing.T) {
	s := New(Options{
		Server:               "google.com",
		Ports:                []int{443},
		Protocols:            []string{"Tls12"},
		Timeout:              5 * time.Second,
		IgnoreCertValidation: true,
		FIPSOnly:             true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if !r.Protocols[0].Success {
		t.Error("Tls12 with FIPS ciphers should succeed for google.com")
	}
	if r.Cipher == nil {
		t.Fatal("Cipher info should be present")
	}
	if !r.Cipher.FIPSCompliant {
		t.Errorf("negotiated cipher %s should be FIPS-compliant", r.Cipher.NegotiatedCipherSuite)
	}
}

func TestScanFIPSCompliantField(t *testing.T) {
	s := New(Options{
		Server:               "google.com",
		Ports:                []int{443},
		Protocols:            []string{"Tls12"},
		Timeout:              5 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if r.Cipher == nil {
		t.Fatal("Cipher info should be present")
	}
	// google.com should negotiate a FIPS-approved cipher with default settings
	if r.Cipher.NegotiatedCipherSuite == "" {
		t.Error("NegotiatedCipherSuite should not be empty")
	}
	// FIPSCompliant should be populated (true or false, just check it's set)
	f := Flatten(r, false)
	if f.FIPSCompliant == nil {
		t.Error("FIPSCompliant should be set when cipher info is present")
	}
}

func TestWriteJSONValid(t *testing.T) {
	// Verify the JSON output can be parsed by encoding/json for single result
	results := []ScanResult{{
		FQDN: "test.com",
		IP:   "1.2.3.4",
		Port: 443,
		Protocols: []ProtocolResult{
			{Name: "Tls12", Success: true},
		},
		Cipher: &CipherInfo{NegotiatedCipherSuite: "TLS_AES_128"},
	}}

	var buf bytes.Buffer
	_ = WriteJSON(&buf, results, []string{"Tls12"}, false)

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Errorf("JSON output should be valid JSON: %v\nOutput: %s", err, buf.String())
	}
}
