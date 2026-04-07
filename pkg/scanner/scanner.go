package scanner

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func sha1Sum(data []byte) []byte {
	h := sha1.Sum(data)
	return h[:]
}

// Protocol represents a TLS/SSL protocol version.
type Protocol struct {
	Name    string
	Version uint16
}

// SupportedProtocols lists all testable TLS/SSL protocols.
var SupportedProtocols = []Protocol{
	{Name: "Ssl3", Version: tls.VersionSSL30},
	{Name: "Tls10", Version: tls.VersionTLS10},
	{Name: "Tls11", Version: tls.VersionTLS11},
	{Name: "Tls12", Version: tls.VersionTLS12},
	{Name: "Tls13", Version: tls.VersionTLS13},
}

// DeprecatedProtocols that should trigger warnings.
var DeprecatedProtocols = map[string]bool{
	"Ssl3":  true,
	"Tls10": true,
	"Tls11": true,
}

// FIPSApprovedCipherSuites lists FIPS 140-3 approved TLS cipher suites
// per NIST SP 800-52 Rev 2 (https://doi.org/10.6028/NIST.SP.800-52r2).
// See FIPS.md for the full reference and rationale.
var FIPSApprovedCipherSuites = map[uint16]bool{
	// TLS 1.2 FIPS-approved suites
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: true,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   true,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   true,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: true,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   true,
	// TLS 1.3 FIPS-approved suites (AES-GCM only; ChaCha20 is not FIPS-approved)
	tls.TLS_AES_128_GCM_SHA256: true,
	tls.TLS_AES_256_GCM_SHA384: true,
}

// FIPSCipherSuiteIDs returns the TLS 1.2 FIPS-approved cipher suite IDs
// for use in tls.Config.CipherSuites. TLS 1.3 suites are not configurable in Go.
func FIPSCipherSuiteIDs() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}
}

// IsFIPSCipherSuite returns whether a cipher suite ID is FIPS-approved.
func IsFIPSCipherSuite(id uint16) bool {
	return FIPSApprovedCipherSuites[id]
}

// ProtocolByName returns the Protocol for a given name (case-insensitive).
func ProtocolByName(name string) (Protocol, bool) {
	lower := strings.ToLower(name)
	for _, p := range SupportedProtocols {
		if strings.ToLower(p.Name) == lower {
			return p, true
		}
	}
	return Protocol{}, false
}

// SupportedProtocolNames returns all protocol names.
func SupportedProtocolNames() []string {
	names := make([]string, len(SupportedProtocols))
	for i, p := range SupportedProtocols {
		names[i] = p.Name
	}
	return names
}

// CertInfo holds remote certificate information.
type CertInfo struct {
	Thumbprint         string `json:"certificateThumbprint,omitempty"`
	Subject            string `json:"certificateSubject,omitempty"`
	Issuer             string `json:"certificateIssuer,omitempty"`
	Issued             string `json:"certificateIssued,omitempty"`
	Expires            string `json:"certificateExpires,omitempty"`
	SignatureAlgorithm string `json:"signatureAlgorithm,omitempty"`
}

// CipherInfo holds negotiated cipher suite information.
type CipherInfo struct {
	NegotiatedCipherSuite string `json:"negotiatedCipherSuite,omitempty"`
	FIPSCompliant         bool   `json:"fipsCompliant"`
}

// ProtocolResult holds the result of testing a single protocol.
type ProtocolResult struct {
	Name     string `json:"name"`
	Success  bool   `json:"success"`
	ErrorMsg string `json:"errorMsg,omitempty"`
}

// ScanResult holds the full result of scanning a server:port.
type ScanResult struct {
	FQDN      string            `json:"fqdn"`
	IP        string            `json:"ip"`
	Port      int               `json:"port"`
	Protocols []ProtocolResult  `json:"protocols"`
	Cipher    *CipherInfo       `json:"cipher,omitempty"`
	Cert      *CertInfo         `json:"cert,omitempty"`
	RawCert   *x509.Certificate `json:"-"`
}

// Options configures a scan.
type Options struct {
	Server               string
	Ports                []int
	Protocols            []string
	Timeout              time.Duration
	IgnoreCertValidation bool
	IncludeCertInfo      bool
	IncludeErrors        bool
	ExportCert           bool
	ReturnCertOnly       bool
	Concurrent           bool
	FIPSOnly             bool
}

// Scanner performs TLS protocol scans.
type Scanner struct {
	Options  Options
	Warnings []string
}

// New creates a new Scanner with the given options.
func New(opts Options) *Scanner {
	return &Scanner{Options: opts}
}

// ResolveServer resolves the server to FQDN and IP.
func (s *Scanner) ResolveServer() (fqdn string, ip string, err error) {
	server := s.Options.Server
	if net.ParseIP(server) != nil {
		// Server is an IP address
		names, err := net.LookupAddr(server)
		if err != nil || len(names) == 0 {
			return server, server, nil // can't resolve, use IP as-is
		}
		fqdn = strings.TrimSuffix(names[0], ".")
		return fqdn, server, nil
	}

	// Server is a hostname
	addrs, err := net.LookupHost(server)
	if err != nil {
		return "", "", fmt.Errorf("unable to resolve server '%s': %w", server, err)
	}
	return server, strings.Join(addrs, ", "), nil
}

// CheckDeprecated checks for deprecated protocols and adds warnings.
func (s *Scanner) CheckDeprecated() {
	var deprecated []string
	for _, name := range s.Options.Protocols {
		if DeprecatedProtocols[name] {
			deprecated = append(deprecated, name)
		}
	}
	if len(deprecated) > 0 {
		s.Warnings = append(s.Warnings,
			fmt.Sprintf("The following protocols are deprecated and insecure (RFC 8996): %s. Consider using Tls12 or Tls13.",
				strings.Join(deprecated, ", ")))
	}
}

// Scan performs the full scan across all ports and protocols.
func (s *Scanner) Scan() ([]ScanResult, error) {
	fqdn, ip, err := s.ResolveServer()
	if err != nil {
		return nil, err
	}

	s.CheckDeprecated()

	protocols := s.Options.Protocols
	if len(protocols) == 0 {
		protocols = SupportedProtocolNames()
	}

	var results []ScanResult

	for _, port := range s.Options.Ports {
		result := ScanResult{
			FQDN: fqdn,
			IP:   ip,
			Port: port,
		}

		// Check if port is open
		addr := net.JoinHostPort(s.Options.Server, fmt.Sprintf("%d", port))
		conn, err := net.DialTimeout("tcp", addr, s.Options.Timeout)
		if err != nil {
			// Port unreachable — mark all protocols as unknown
			for _, name := range protocols {
				pr := ProtocolResult{Name: name, Success: false, ErrorMsg: ""}
				if s.Options.IncludeErrors {
					pr.ErrorMsg = fmt.Sprintf("Could not connect to %s on TCP port %d.", s.Options.Server, port)
				}
				result.Protocols = append(result.Protocols, pr)
			}
			results = append(results, result)
			continue
		}
		conn.Close()

		// Test each protocol
		if s.Options.Concurrent {
			result.Protocols = s.scanProtocolsConcurrent(fqdn, port, protocols)
		} else {
			result.Protocols = s.scanProtocolsSequential(fqdn, port, protocols)
		}

		// Collect cipher and cert info from first successful protocol
		for _, pr := range result.Protocols {
			if pr.Success {
				cipher, cert, rawCert := s.collectDetails(fqdn, port, pr.Name)
				result.Cipher = cipher
				if s.Options.IncludeCertInfo {
					result.Cert = cert
				}
				result.RawCert = rawCert
				break
			}
		}

		results = append(results, result)
	}

	return results, nil
}

func (s *Scanner) scanProtocolsSequential(fqdn string, port int, protocols []string) []ProtocolResult {
	var results []ProtocolResult
	for _, name := range protocols {
		results = append(results, s.testProtocol(fqdn, port, name))
	}
	return results
}

func (s *Scanner) scanProtocolsConcurrent(fqdn string, port int, protocols []string) []ProtocolResult {
	results := make([]ProtocolResult, len(protocols))
	var wg sync.WaitGroup
	for i, name := range protocols {
		wg.Add(1)
		go func(idx int, proto string) {
			defer wg.Done()
			results[idx] = s.testProtocol(fqdn, port, proto)
		}(i, name)
	}
	wg.Wait()
	return results
}

func (s *Scanner) testProtocol(fqdn string, port int, name string) ProtocolResult {
	proto, ok := ProtocolByName(name)
	if !ok {
		return ProtocolResult{Name: name, Success: false, ErrorMsg: "unknown protocol"}
	}

	addr := net.JoinHostPort(fqdn, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: s.Options.Timeout}

	tlsConfig := &tls.Config{
		ServerName:         fqdn,
		MinVersion:         proto.Version,
		MaxVersion:         proto.Version,
		InsecureSkipVerify: s.Options.IgnoreCertValidation,
	}
	if s.Options.FIPSOnly {
		tlsConfig.CipherSuites = FIPSCipherSuiteIDs()
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		pr := ProtocolResult{Name: name, Success: false}
		if s.Options.IncludeErrors {
			pr.ErrorMsg = err.Error()
		}
		return pr
	}
	conn.Close()

	return ProtocolResult{Name: name, Success: true}
}

func (s *Scanner) collectDetails(fqdn string, port int, protoName string) (*CipherInfo, *CertInfo, *x509.Certificate) {
	proto, ok := ProtocolByName(protoName)
	if !ok {
		return nil, nil, nil
	}

	addr := net.JoinHostPort(fqdn, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: s.Options.Timeout}

	tlsConfig := &tls.Config{
		ServerName:         fqdn,
		MinVersion:         proto.Version,
		MaxVersion:         proto.Version,
		InsecureSkipVerify: s.Options.IgnoreCertValidation,
	}
	if s.Options.FIPSOnly {
		tlsConfig.CipherSuites = FIPSCipherSuiteIDs()
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	if err != nil {
		return nil, nil, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()

	cipher := &CipherInfo{
		NegotiatedCipherSuite: tls.CipherSuiteName(state.CipherSuite),
		FIPSCompliant:         IsFIPSCipherSuite(state.CipherSuite),
	}

	var cert *CertInfo
	var rawCert *x509.Certificate
	if len(state.PeerCertificates) > 0 {
		c := state.PeerCertificates[0]
		rawCert = c
		cert = &CertInfo{
			Thumbprint:         fmt.Sprintf("%X", c.Raw),
			Subject:            c.Subject.String(),
			Issuer:             c.Issuer.String(),
			Issued:             c.NotBefore.Format(time.RFC3339),
			Expires:            c.NotAfter.Format(time.RFC3339),
			SignatureAlgorithm: c.SignatureAlgorithm.String(),
		}
		// Use SHA1 fingerprint instead of full raw bytes
		cert.Thumbprint = fmt.Sprintf("%X", sha1Sum(c.Raw))
	}

	return cipher, cert, rawCert
}

// ExportCertPEM exports a certificate to PEM format bytes.
func ExportCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
}

// ExportCertDER exports a certificate to DER format bytes (.cer).
func ExportCertDER(cert *x509.Certificate) []byte {
	return cert.Raw
}
