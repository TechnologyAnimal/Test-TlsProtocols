package scanner

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// FlatResult is a flattened representation of ScanResult for output.
type FlatResult struct {
	FQDN                  string `json:"fqdn"`
	IP                    string `json:"ip"`
	Port                  int    `json:"port"`
	Protocols             map[string]interface{}
	NegotiatedCipherSuite string `json:"negotiatedCipherSuite,omitempty"`
	FIPSCompliant         *bool  `json:"fipsCompliant,omitempty"`
	CertificateThumbprint string `json:"certificateThumbprint,omitempty"`
	CertificateSubject    string `json:"certificateSubject,omitempty"`
	CertificateIssuer     string `json:"certificateIssuer,omitempty"`
	CertificateIssued     string `json:"certificateIssued,omitempty"`
	CertificateExpires    string `json:"certificateExpires,omitempty"`
	SignatureAlgorithm    string `json:"signatureAlgorithm,omitempty"`
	ErrorMsgs             map[string]string
}

// Flatten converts a ScanResult to a FlatResult for output.
func Flatten(r ScanResult, includeErrors bool) FlatResult {
	f := FlatResult{
		FQDN:      r.FQDN,
		IP:        r.IP,
		Port:      r.Port,
		Protocols: make(map[string]interface{}),
		ErrorMsgs: make(map[string]string),
	}

	for _, p := range r.Protocols {
		f.Protocols[p.Name] = p.Success
		if includeErrors && p.ErrorMsg != "" {
			f.ErrorMsgs[p.Name+"ErrorMsg"] = p.ErrorMsg
		}
	}

	if r.Cipher != nil {
		f.NegotiatedCipherSuite = r.Cipher.NegotiatedCipherSuite
		fips := r.Cipher.FIPSCompliant
		f.FIPSCompliant = &fips
	}

	if r.Cert != nil {
		f.CertificateThumbprint = r.Cert.Thumbprint
		f.CertificateSubject = r.Cert.Subject
		f.CertificateIssuer = r.Cert.Issuer
		f.CertificateIssued = r.Cert.Issued
		f.CertificateExpires = r.Cert.Expires
		f.SignatureAlgorithm = r.Cert.SignatureAlgorithm
	}

	return f
}

// orderedMap builds a JSON-friendly ordered representation.
func orderedMap(f FlatResult, protocols []string, includeErrors bool) []byte {
	var b strings.Builder
	b.WriteString("{\n")

	entries := []struct{ k, v string }{
		{"fqdn", quote(f.FQDN)},
		{"ip", quote(f.IP)},
		{"port", fmt.Sprintf("%d", f.Port)},
	}

	// Cert info before protocols (if present)
	if f.CertificateThumbprint != "" {
		entries = append(entries,
			struct{ k, v string }{"certificateThumbprint", quote(f.CertificateThumbprint)},
			struct{ k, v string }{"certificateSubject", quote(f.CertificateSubject)},
			struct{ k, v string }{"certificateIssuer", quote(f.CertificateIssuer)},
			struct{ k, v string }{"certificateIssued", quote(f.CertificateIssued)},
			struct{ k, v string }{"certificateExpires", quote(f.CertificateExpires)},
			struct{ k, v string }{"signatureAlgorithm", quote(f.SignatureAlgorithm)},
		)
	}

	// Protocols
	for _, name := range protocols {
		val, ok := f.Protocols[name]
		if !ok {
			continue
		}
		entries = append(entries, struct{ k, v string }{name, fmt.Sprintf("%v", val)})
		if includeErrors {
			if emsg, ok := f.ErrorMsgs[name+"ErrorMsg"]; ok {
				entries = append(entries, struct{ k, v string }{name + "ErrorMsg", quote(emsg)})
			}
		}
	}

	// Cipher suite
	if f.NegotiatedCipherSuite != "" {
		entries = append(entries, struct{ k, v string }{"negotiatedCipherSuite", quote(f.NegotiatedCipherSuite)})
	}
	if f.FIPSCompliant != nil {
		entries = append(entries, struct{ k, v string }{"fipsCompliant", fmt.Sprintf("%v", *f.FIPSCompliant)})
	}

	for i, e := range entries {
		comma := ","
		if i == len(entries)-1 {
			comma = ""
		}
		fmt.Fprintf(&b, "  %s: %s%s\n", quote(e.k), e.v, comma)
	}

	b.WriteString("}")
	return []byte(b.String())
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// WriteJSON writes results as JSON to the writer.
func WriteJSON(w io.Writer, results []ScanResult, protocols []string, includeErrors bool) error {
	if len(results) == 1 {
		f := Flatten(results[0], includeErrors)
		_, err := w.Write(orderedMap(f, protocols, includeErrors))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(w)
		return err
	}

	fmt.Fprintln(w, "[")
	for i, r := range results {
		f := Flatten(r, includeErrors)
		data := orderedMap(f, protocols, includeErrors)
		if i < len(results)-1 {
			fmt.Fprintf(w, "  %s,\n", string(data))
		} else {
			fmt.Fprintf(w, "  %s\n", string(data))
		}
	}
	fmt.Fprintln(w, "]")
	return nil
}

// WriteText writes results in human-readable key:value format.
func WriteText(w io.Writer, results []ScanResult, protocols []string, includeErrors bool) {
	for i, r := range results {
		if i > 0 {
			fmt.Fprintln(w)
		}
		f := Flatten(r, includeErrors)

		maxKey := 4 // "FQDN"
		keys := []string{"FQDN", "IP", "Port"}

		if f.CertificateThumbprint != "" {
			keys = append(keys, "CertificateThumbprint", "CertificateSubject", "CertificateIssuer",
				"CertificateIssued", "CertificateExpires", "SignatureAlgorithm")
		}

		for _, name := range protocols {
			if _, ok := f.Protocols[name]; ok {
				keys = append(keys, name)
				if includeErrors {
					if _, ok := f.ErrorMsgs[name+"ErrorMsg"]; ok {
						keys = append(keys, name+"ErrorMsg")
					}
				}
			}
		}

		if f.NegotiatedCipherSuite != "" {
			keys = append(keys, "NegotiatedCipherSuite")
		}
		if f.FIPSCompliant != nil {
			keys = append(keys, "FIPSCompliant")
		}

		for _, k := range keys {
			if len(k) > maxKey {
				maxKey = len(k)
			}
		}

		pad := fmt.Sprintf("%%-%ds", maxKey)

		for _, k := range keys {
			label := fmt.Sprintf(pad, k)
			var val string
			switch k {
			case "FQDN":
				val = f.FQDN
			case "IP":
				val = f.IP
			case "Port":
				val = fmt.Sprintf("%d", f.Port)
			case "CertificateThumbprint":
				val = f.CertificateThumbprint
			case "CertificateSubject":
				val = f.CertificateSubject
			case "CertificateIssuer":
				val = f.CertificateIssuer
			case "CertificateIssued":
				val = f.CertificateIssued
			case "CertificateExpires":
				val = f.CertificateExpires
			case "SignatureAlgorithm":
				val = f.SignatureAlgorithm
			case "NegotiatedCipherSuite":
				val = f.NegotiatedCipherSuite
			case "FIPSCompliant":
				if f.FIPSCompliant != nil {
					val = fmt.Sprintf("%v", *f.FIPSCompliant)
				}
			default:
				if v, ok := f.Protocols[k]; ok {
					val = fmt.Sprintf("%v", v)
				} else if v, ok := f.ErrorMsgs[k]; ok {
					val = v
				}
			}
			fmt.Fprintf(w, "%s : %s\n", label, val)
		}
	}
}

// WriteCSV writes results as CSV to the writer.
func WriteCSV(w io.Writer, results []ScanResult, protocols []string, includeErrors bool) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Build header
	header := []string{"FQDN", "IP", "Port"}

	hasCert := false
	for _, r := range results {
		if r.Cert != nil {
			hasCert = true
			break
		}
	}
	if hasCert {
		header = append(header, "CertificateThumbprint", "CertificateSubject", "CertificateIssuer",
			"CertificateIssued", "CertificateExpires", "SignatureAlgorithm")
	}

	for _, name := range protocols {
		header = append(header, name)
		if includeErrors {
			header = append(header, name+"ErrorMsg")
		}
	}

	hasCipher := false
	for _, r := range results {
		if r.Cipher != nil {
			hasCipher = true
			break
		}
	}
	if hasCipher {
		header = append(header, "NegotiatedCipherSuite", "FIPSCompliant")
	}

	if err := cw.Write(header); err != nil {
		return err
	}

	// Write rows
	for _, r := range results {
		f := Flatten(r, includeErrors)
		row := []string{f.FQDN, f.IP, fmt.Sprintf("%d", f.Port)}

		if hasCert {
			row = append(row, f.CertificateThumbprint, f.CertificateSubject, f.CertificateIssuer,
				f.CertificateIssued, f.CertificateExpires, f.SignatureAlgorithm)
		}

		for _, name := range protocols {
			if v, ok := f.Protocols[name]; ok {
				row = append(row, fmt.Sprintf("%v", v))
			} else {
				row = append(row, "")
			}
			if includeErrors {
				if v, ok := f.ErrorMsgs[name+"ErrorMsg"]; ok {
					row = append(row, v)
				} else {
					row = append(row, "")
				}
			}
		}

		if hasCipher {
			row = append(row, f.NegotiatedCipherSuite)
			if f.FIPSCompliant != nil {
				row = append(row, fmt.Sprintf("%v", *f.FIPSCompliant))
			} else {
				row = append(row, "")
			}
		}

		if err := cw.Write(row); err != nil {
			return err
		}
	}

	return nil
}
