package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TechnologyAnimal/Test-TlsProtocols/pkg/scanner"
)

const (
	exitOK       = 0
	exitError    = 1
	exitFIPSFail = 2
)

func main() {
	var (
		server        = flag.String("server", "", "Server FQDN or IP address (required)")
		ports         = flag.String("port", "443", "Comma-separated list of ports to test")
		protocols     = flag.String("protocol", "", "Comma-separated list of protocols to test (default: all)")
		format        = flag.String("format", "text", "Output format: text, json, csv")
		timeout       = flag.Int("timeout", 2, "Connection timeout in seconds (1-5)")
		ignoreCert    = flag.Bool("ignore-cert", false, "Skip certificate validation")
		includeCert   = flag.Bool("include-cert", false, "Include remote certificate info in output")
		includeErrors = flag.Bool("include-errors", false, "Include error messages for failed protocols")
		exportCert    = flag.Bool("export-cert", false, "Export remote certificate to .cer file")
		certOnly      = flag.Bool("cert-only", false, "Return remote certificate only (PEM to stdout)")
		concurrent    = flag.Bool("concurrent", false, "Test protocols concurrently")
		fipsOnly      = flag.Bool("fips", false, "Only offer FIPS 140-3 approved cipher suites (see FIPS.md)")
		verbose       = flag.Bool("verbose", false, "Print detailed progress to stderr")
		inputFile     = flag.String("input-file", "", "CSV file with Server,Port columns for batch scanning")
		listProtocols = flag.Bool("list-protocols", false, "List supported protocol names and exit")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: test-tls-protocols -server <host> [options]\n\n")
		fmt.Fprintf(os.Stderr, "Test SSL/TLS protocols supported by a remote server.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  test-tls-protocols -server github.com\n")
		fmt.Fprintf(os.Stderr, "  test-tls-protocols -server github.com -protocol Tls12,Tls13\n")
		fmt.Fprintf(os.Stderr, "  test-tls-protocols -server github.com -format json -include-cert\n")
		fmt.Fprintf(os.Stderr, "  test-tls-protocols -server 10.0.0.1 -ignore-cert -include-errors\n")
		fmt.Fprintf(os.Stderr, "  test-tls-protocols -server github.com -export-cert\n")
		fmt.Fprintf(os.Stderr, "  test-tls-protocols -server github.com -fips\n")
		fmt.Fprintf(os.Stderr, "  test-tls-protocols -input-file servers.csv -format csv\n")
	}

	flag.Parse()

	// Configure verbose logger
	vlog := log.New(os.Stderr, "VERBOSE: ", 0)
	if !*verbose {
		vlog.SetOutput(io.Discard)
	}

	if *listProtocols {
		fmt.Println("Supported protocols:")
		for _, name := range scanner.SupportedProtocolNames() {
			dep := ""
			if scanner.DeprecatedProtocols[name] {
				dep = " (deprecated)"
			}
			fmt.Printf("  %s%s\n", name, dep)
		}
		os.Exit(0)
	}

	if *timeout < 1 || *timeout > 5 {
		fmt.Fprintln(os.Stderr, "Error: -timeout must be between 1 and 5")
		os.Exit(exitError)
	}

	// Parse protocols
	var protoList []string
	if *protocols != "" {
		protoList = strings.Split(*protocols, ",")
		for i := range protoList {
			protoList[i] = strings.TrimSpace(protoList[i])
		}
		for _, name := range protoList {
			if _, ok := scanner.ProtocolByName(name); !ok {
				fmt.Fprintf(os.Stderr, "Error: unknown protocol '%s'. Supported: %s\n",
					name, strings.Join(scanner.SupportedProtocolNames(), ", "))
				os.Exit(exitError)
			}
		}
	} else {
		protoList = scanner.SupportedProtocolNames()
	}
	vlog.Printf("Protocols to test: %v", protoList)

	// Build list of scan targets: either from -input-file or -server/-port
	var targets []target

	if *inputFile != "" {
		entries, err := parseInputFile(*inputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading input file: %v\n", err)
			os.Exit(exitError)
		}
		targets = entries
		vlog.Printf("Loaded %d target(s) from %s", len(targets), *inputFile)
	} else {
		if *server == "" {
			fmt.Fprintln(os.Stderr, "Error: -server or -input-file is required")
			flag.Usage()
			os.Exit(exitError)
		}
		host, urlPort := parseServer(*server)
		var portList []int
		if urlPort > 0 {
			portList = []int{urlPort}
			vlog.Printf("Port extracted from URL: %d", urlPort)
		} else {
			var err error
			portList, err = parsePorts(*ports)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(exitError)
			}
		}
		targets = append(targets, target{Server: host, Ports: portList})
	}

	// Scan all targets and collect results
	var allResults []scanner.ScanResult
	var allWarnings []string

	for _, t := range targets {
		vlog.Printf("Scanning %s:%v (protocols: %s, fips: %v)", t.Server, t.Ports, strings.Join(protoList, ", "), *fipsOnly)

		opts := scanner.Options{
			Server:               t.Server,
			Ports:                t.Ports,
			Protocols:            protoList,
			Timeout:              time.Duration(*timeout) * time.Second,
			IgnoreCertValidation: *ignoreCert,
			IncludeCertInfo:      *includeCert,
			IncludeErrors:        *includeErrors,
			ExportCert:           *exportCert,
			ReturnCertOnly:       *certOnly,
			Concurrent:           *concurrent,
			FIPSOnly:             *fipsOnly,
		}

		s := scanner.New(opts)
		results, err := s.Scan()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning %s: %v\n", t.Server, err)
			continue
		}
		allResults = append(allResults, results...)
		allWarnings = append(allWarnings, s.Warnings...)
	}

	vlog.Printf("Scan complete: %d result(s)", len(allResults))

	for _, w := range allWarnings {
		fmt.Fprintf(os.Stderr, "WARNING: %s\n", w)
	}

	results := allResults

	// Handle cert-only mode
	if *certOnly {
		for _, r := range results {
			if r.RawCert != nil {
				os.Stdout.Write(scanner.ExportCertPEM(r.RawCert))
				os.Exit(exitOK)
			}
		}
		fmt.Fprintln(os.Stderr, "Error: no certificate obtained")
		os.Exit(exitError)
	}

	// Handle cert export
	if *exportCert {
		for _, r := range results {
			if r.RawCert != nil {
				filename := r.FQDN + ".cer"
				if _, err := os.Stat(filename); err == nil {
					fmt.Fprintf(os.Stderr, "Certificate file %s already exists, skipping export.\n", filename)
				} else {
					err := os.WriteFile(filename, scanner.ExportCertDER(r.RawCert), 0644)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error exporting certificate: %v\n", err)
					} else {
						fmt.Fprintf(os.Stderr, "Exported %s\n", filename)
					}
				}
				break
			}
		}
	}

	// Output results
	switch strings.ToLower(*format) {
	case "json":
		if err := scanner.WriteJSON(os.Stdout, results, protoList, *includeErrors); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
			os.Exit(exitError)
		}
	case "csv":
		if err := scanner.WriteCSV(os.Stdout, results, protoList, *includeErrors); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing CSV: %v\n", err)
			os.Exit(exitError)
		}
	case "text":
		scanner.WriteText(os.Stdout, results, protoList, *includeErrors)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown format '%s'. Use text, json, or csv.\n", *format)
		os.Exit(exitError)
	}

	// Exit code 2 if -fips was requested and any negotiated cipher is non-FIPS
	if *fipsOnly {
		for _, r := range results {
			if r.Cipher != nil && !r.Cipher.FIPSCompliant {
				vlog.Printf("Non-FIPS cipher negotiated on %s: %s", r.FQDN, r.Cipher.NegotiatedCipherSuite)
				fmt.Fprintf(os.Stderr, "FIPS FAIL: %s negotiated cipher %s is not FIPS 140-3 approved\n", r.FQDN, r.Cipher.NegotiatedCipherSuite)
				os.Exit(exitFIPSFail)
			}
		}
		vlog.Printf("All negotiated ciphers are FIPS 140-3 approved")
	}
}

type target struct {
	Server string
	Ports  []int
}

func parseInputFile(path string) ([]target, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true

	records, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("invalid CSV: %w", err)
	}

	if len(records) < 2 {
		return nil, fmt.Errorf("CSV file must have a header row and at least one data row")
	}

	// Find column indices from header (strip UTF-8 BOM if present)
	header := records[0]
	if len(header) > 0 {
		header[0] = strings.TrimPrefix(header[0], "\xEF\xBB\xBF")
	}
	serverCol, portCol := -1, -1
	for i, h := range header {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "server":
			serverCol = i
		case "port":
			portCol = i
		}
	}
	if serverCol == -1 {
		return nil, fmt.Errorf("CSV must have a 'Server' column")
	}

	var targets []target
	for _, row := range records[1:] {
		if serverCol >= len(row) {
			continue
		}
		srv := strings.TrimSpace(row[serverCol])
		if srv == "" {
			continue
		}

		port := 443 // default
		if portCol >= 0 && portCol < len(row) {
			if p := strings.TrimSpace(row[portCol]); p != "" {
				parsed, err := strconv.Atoi(p)
				if err != nil {
					return nil, fmt.Errorf("invalid port '%s' for server '%s'", p, srv)
				}
				port = parsed
			}
		}
		targets = append(targets, target{Server: srv, Ports: []int{port}})
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid entries found in CSV")
	}
	return targets, nil
}

// parseServer extracts host and optional port from a URL or plain hostname.
// Examples:
//
//	"https://myservice.com:900/path" → ("myservice.com", 900)
//	"myservice.com:900/path"         → ("myservice.com", 900)
//	"github.com"                     → ("github.com", 0)
//	"10.0.0.1"                       → ("10.0.0.1", 0)
func parseServer(input string) (host string, port int) {
	input = strings.TrimSpace(input)

	// Add scheme if missing so url.Parse works correctly
	normalized := input
	if !strings.Contains(normalized, "://") {
		normalized = "https://" + normalized
	}

	u, err := url.Parse(normalized)
	if err != nil || u.Host == "" {
		// Fall back: strip any path and return as-is
		host = strings.SplitN(input, "/", 2)[0]
		return host, 0
	}

	host = u.Hostname()
	if p := u.Port(); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil {
			port = parsed
		}
	}
	return host, port
}

func parsePorts(s string) ([]int, error) {
	parts := strings.Split(s, ",")
	var ports []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		port, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid port '%s'", p)
		}
		if port < 1 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range (1-65535)", port)
		}
		ports = append(ports, port)
	}
	return ports, nil
}
