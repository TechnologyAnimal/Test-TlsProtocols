package scanner

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// newLocalTLSServer creates a TLS server on localhost with the given config.
// Returns the listener and a cleanup function.
func newLocalTLSServer(t *testing.T, tlsConfig *tls.Config) (net.Listener, int, func()) {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}

	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			// Complete the handshake then close
			tlsConn := conn.(*tls.Conn)
			_ = tlsConn.Handshake()
			conn.Close()
		}
	}()

	return ln, port, func() { ln.Close() }
}

// generateSelfSignedCert creates a self-signed TLS certificate for testing.
func generateSelfSignedCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test-TlsProtocols Unit Test"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
		Leaf:        parsedCert,
	}

	return tlsCert, parsedCert
}

// newTLS12OnlyServer creates a local TLS server that only supports TLS 1.2.
func newTLS12OnlyServer(t *testing.T) (int, func()) {
	t.Helper()
	cert, _ := generateSelfSignedCert(t)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}
	_, port, cleanup := newLocalTLSServer(t, cfg)
	return port, cleanup
}

// newTLS13OnlyServer creates a local TLS server that only supports TLS 1.3.
func newTLS13OnlyServer(t *testing.T) (int, func()) {
	t.Helper()
	cert, _ := generateSelfSignedCert(t)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
	_, port, cleanup := newLocalTLSServer(t, cfg)
	return port, cleanup
}

// newMultiVersionServer creates a local TLS server that supports TLS 1.2 and 1.3.
func newMultiVersionServer(t *testing.T) (int, func()) {
	t.Helper()
	cert, _ := generateSelfSignedCert(t)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	_, port, cleanup := newLocalTLSServer(t, cfg)
	return port, cleanup
}

// --- Unit Tests ---

func TestUnit_ScanTLS12Only(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12", "Tls13"},
		Timeout:              2 * time.Second,
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
	if len(r.Protocols) != 2 {
		t.Fatalf("expected 2 protocol results, got %d", len(r.Protocols))
	}

	// TLS 1.2 should succeed
	if !r.Protocols[0].Success {
		t.Error("Tls12 should succeed")
	}
	// TLS 1.3 should fail
	if r.Protocols[1].Success {
		t.Error("Tls13 should fail on TLS 1.2-only server")
	}
}

func TestUnit_ScanTLS13Only(t *testing.T) {
	port, cleanup := newTLS13OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12", "Tls13"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	// TLS 1.2 should fail
	if r.Protocols[0].Success {
		t.Error("Tls12 should fail on TLS 1.3-only server")
	}
	// TLS 1.3 should succeed
	if !r.Protocols[1].Success {
		t.Error("Tls13 should succeed")
	}
}

func TestUnit_ScanMultiVersion(t *testing.T) {
	port, cleanup := newMultiVersionServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12", "Tls13"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if !r.Protocols[0].Success {
		t.Error("Tls12 should succeed")
	}
	if !r.Protocols[1].Success {
		t.Error("Tls13 should succeed")
	}
}

func TestUnit_ScanDeprecatedProtocolFails(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Ssl3"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
		IncludeErrors:        true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if r.Protocols[0].Success {
		t.Error("Ssl3 should fail on TLS 1.2 server")
	}
	if r.Protocols[0].ErrorMsg == "" {
		t.Error("ErrorMsg should be populated when IncludeErrors is true")
	}
}

func TestUnit_ScanCipherInfo(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if r.Cipher == nil {
		t.Fatal("Cipher should be populated")
	}
	if r.Cipher.NegotiatedCipherSuite == "" {
		t.Error("NegotiatedCipherSuite should not be empty")
	}
}

func TestUnit_ScanCertInfo(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
		IncludeCertInfo:      true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if r.Cert == nil {
		t.Fatal("Cert should be populated when IncludeCertInfo is true")
	}
	if r.Cert.Subject == "" {
		t.Error("Subject should not be empty")
	}
	if r.Cert.Thumbprint == "" {
		t.Error("Thumbprint should not be empty")
	}
	if r.Cert.SignatureAlgorithm == "" {
		t.Error("SignatureAlgorithm should not be empty")
	}
}

func TestUnit_ScanCertNotIncludedByDefault(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if results[0].Cert != nil {
		t.Error("Cert should be nil when IncludeCertInfo is false")
	}
}

func TestUnit_ScanFIPSCompliantLocal(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
		FIPSOnly:             true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if !r.Protocols[0].Success {
		t.Error("Tls12 with FIPS ciphers should succeed (ECDHE+AES-GCM is default)")
	}
	if r.Cipher == nil {
		t.Fatal("Cipher should be populated")
	}
	if !r.Cipher.FIPSCompliant {
		t.Errorf("cipher %s should be FIPS-compliant", r.Cipher.NegotiatedCipherSuite)
	}
}

func TestUnit_ScanUnreachablePort(t *testing.T) {
	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{1}, // port 1 — almost certainly not listening
		Protocols:            []string{"Tls12"},
		Timeout:              1 * time.Second,
		IgnoreCertValidation: true,
		IncludeErrors:        true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if r.Protocols[0].Success {
		t.Error("should not succeed on unreachable port")
	}
	if r.Protocols[0].ErrorMsg == "" {
		t.Error("ErrorMsg should be set for unreachable port")
	}
}

func TestUnit_ScanConcurrent(t *testing.T) {
	port, cleanup := newMultiVersionServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12", "Tls13"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
		Concurrent:           true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if len(r.Protocols) != 2 {
		t.Fatalf("expected 2 protocol results, got %d", len(r.Protocols))
	}
	if !r.Protocols[0].Success {
		t.Error("Tls12 should succeed (concurrent)")
	}
	if !r.Protocols[1].Success {
		t.Error("Tls13 should succeed (concurrent)")
	}
}

func TestUnit_ScanMultiplePorts(t *testing.T) {
	port1, cleanup1 := newTLS12OnlyServer(t)
	defer cleanup1()
	port2, cleanup2 := newTLS13OnlyServer(t)
	defer cleanup2()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port1, port2},
		Protocols:            []string{"Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Port 1 (TLS 1.2 server) — should succeed
	if !results[0].Protocols[0].Success {
		t.Error("Tls12 should succeed on TLS 1.2 server")
	}
	// Port 2 (TLS 1.3 server) — Tls12 should fail
	if results[1].Protocols[0].Success {
		t.Error("Tls12 should fail on TLS 1.3-only server")
	}
}

func TestUnit_RawCertPopulated(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if results[0].RawCert == nil {
		t.Error("RawCert should be populated for successful TLS connection")
	}
}

func TestUnit_ExportCertFormats(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	cert := results[0].RawCert
	if cert == nil {
		t.Fatal("RawCert should be populated")
	}

	pem := ExportCertPEM(cert)
	if !strings.Contains(string(pem), "BEGIN CERTIFICATE") {
		t.Error("PEM should contain BEGIN CERTIFICATE header")
	}

	der := ExportCertDER(cert)
	if len(der) == 0 {
		t.Error("DER should not be empty")
	}
}

// --- Output format unit tests with local data ---

func TestUnit_WriteTextLocal(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	var buf bytes.Buffer
	WriteText(&buf, results, []string{"Tls12"}, false)
	output := buf.String()

	if !strings.Contains(output, "127.0.0.1") {
		t.Error("text output should contain server IP")
	}
	if !strings.Contains(output, "true") {
		t.Error("text output should contain 'true' for Tls12")
	}
	if !strings.Contains(output, "FIPSCompliant") {
		t.Error("text output should contain FIPSCompliant field")
	}
}

func TestUnit_WriteJSONLocal(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteJSON(&buf, results, []string{"Tls12"}, false); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Errorf("JSON output should be valid: %v\nOutput: %s", err, buf.String())
	}
	if _, ok := parsed["fipsCompliant"]; !ok {
		t.Error("JSON should contain fipsCompliant key")
	}
}

func TestUnit_WriteCSVLocal(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteCSV(&buf, results, []string{"Tls12"}, false); err != nil {
		t.Fatalf("WriteCSV error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 CSV lines, got %d", len(lines))
	}
	if !strings.Contains(lines[0], "FIPSCompliant") {
		t.Error("CSV header should contain FIPSCompliant")
	}
}

func TestUnit_DeprecatedWarnings(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Ssl3", "Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	_, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(s.Warnings) == 0 {
		t.Error("should have deprecation warnings for Ssl3")
	}
	if !strings.Contains(s.Warnings[0], "Ssl3") {
		t.Errorf("warning should mention Ssl3: %s", s.Warnings[0])
	}
}

func TestUnit_NoWarningsForModernProtocols(t *testing.T) {
	port, cleanup := newMultiVersionServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12", "Tls13"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	_, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if len(s.Warnings) != 0 {
		t.Errorf("should have no warnings for Tls12+Tls13: %v", s.Warnings)
	}
}

func TestUnit_FIPSOnlyFieldInFlatResult(t *testing.T) {
	// Test that FIPSCompliant is correctly populated in FlatResult
	r := ScanResult{
		FQDN: "test.local",
		IP:   "127.0.0.1",
		Port: 443,
		Protocols: []ProtocolResult{
			{Name: "Tls12", Success: true},
		},
		Cipher: &CipherInfo{
			NegotiatedCipherSuite: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
			FIPSCompliant:         true,
		},
	}

	f := Flatten(r, false)
	if f.FIPSCompliant == nil {
		t.Fatal("FIPSCompliant should be set")
	}
	if !*f.FIPSCompliant {
		t.Error("FIPSCompliant should be true")
	}

	// Test with non-FIPS cipher
	r2 := ScanResult{
		FQDN: "test.local",
		IP:   "127.0.0.1",
		Port: 443,
		Protocols: []ProtocolResult{
			{Name: "Tls13", Success: true},
		},
		Cipher: &CipherInfo{
			NegotiatedCipherSuite: "TLS_CHACHA20_POLY1305_SHA256",
			FIPSCompliant:         false,
		},
	}

	f2 := Flatten(r2, false)
	if f2.FIPSCompliant == nil {
		t.Fatal("FIPSCompliant should be set")
	}
	if *f2.FIPSCompliant {
		t.Error("FIPSCompliant should be false for ChaCha20")
	}
}

func TestUnit_ErrorMsgsInFlatResult(t *testing.T) {
	r := ScanResult{
		FQDN: "test.local",
		IP:   "127.0.0.1",
		Port: 443,
		Protocols: []ProtocolResult{
			{Name: "Ssl3", Success: false, ErrorMsg: "protocol version not supported"},
			{Name: "Tls12", Success: true},
		},
	}

	f := Flatten(r, true)
	if f.ErrorMsgs["Ssl3ErrorMsg"] != "protocol version not supported" {
		t.Errorf("Ssl3ErrorMsg = %q; want 'protocol version not supported'", f.ErrorMsgs["Ssl3ErrorMsg"])
	}

	// Errors not included when includeErrors is false
	f2 := Flatten(r, false)
	if len(f2.ErrorMsgs) != 0 {
		t.Errorf("ErrorMsgs should be empty when includeErrors=false, got %v", f2.ErrorMsgs)
	}
}

func TestUnit_PortInResult(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	if results[0].Port != port {
		t.Errorf("Port = %d; want %d", results[0].Port, port)
	}
}

func TestUnit_FQDNAndIPPopulated(t *testing.T) {
	port, cleanup := newTLS12OnlyServer(t)
	defer cleanup()

	s := New(Options{
		Server:               "127.0.0.1",
		Ports:                []int{port},
		Protocols:            []string{"Tls12"},
		Timeout:              2 * time.Second,
		IgnoreCertValidation: true,
	})

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	r := results[0]
	if r.IP != "127.0.0.1" {
		t.Errorf("IP = %q; want '127.0.0.1'", r.IP)
	}
	// FQDN may be 'localhost' or '127.0.0.1' depending on reverse DNS
	if r.FQDN == "" {
		t.Error("FQDN should not be empty")
	}
}

func TestUnit_WriteTextMultipleResults(t *testing.T) {
	results := []ScanResult{
		{
			FQDN: "server1.local", IP: "10.0.0.1", Port: 443,
			Protocols: []ProtocolResult{{Name: "Tls12", Success: true}},
			Cipher:    &CipherInfo{NegotiatedCipherSuite: "TLS_AES_128_GCM_SHA256", FIPSCompliant: true},
		},
		{
			FQDN: "server2.local", IP: "10.0.0.2", Port: 443,
			Protocols: []ProtocolResult{{Name: "Tls12", Success: false}},
		},
	}

	var buf bytes.Buffer
	WriteText(&buf, results, []string{"Tls12"}, false)
	output := buf.String()

	if !strings.Contains(output, "server1.local") {
		t.Error("should contain server1")
	}
	if !strings.Contains(output, "server2.local") {
		t.Error("should contain server2")
	}
	if strings.Count(output, fmt.Sprintf("%d", 443)) < 2 {
		t.Error("should contain port 443 twice")
	}
}
