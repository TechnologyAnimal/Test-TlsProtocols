package main

import "testing"

func TestParseServer(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort int
	}{
		{"github.com", "github.com", 0},
		{"10.0.0.1", "10.0.0.1", 0},
		{"https://github.com", "github.com", 0},
		{"https://github.com:443", "github.com", 443},
		{"https://github.com:443/path/to/repo", "github.com", 443},
		{"https://myservice.com:900/youhoo/you", "myservice.com", 900},
		{"myservice.com:900/youhoo/you", "myservice.com", 900},
		{"myservice.com:8443", "myservice.com", 8443},
		{"http://example.com:8080/api", "example.com", 8080},
		{"  github.com  ", "github.com", 0},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, port := parseServer(tt.input)
			if host != tt.wantHost {
				t.Errorf("parseServer(%q) host = %q, want %q", tt.input, host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("parseServer(%q) port = %d, want %d", tt.input, port, tt.wantPort)
			}
		})
	}
}
