// Package tlscheck inspects the TLS configuration of a host: negotiated
// protocol version, cipher suite, and the presented certificate chain.
package tlscheck

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// Result holds everything learned from a single TLS handshake with a host.
type Result struct {
	Host              string    `json:"host"`
	Port              string    `json:"port"`
	NegotiatedVersion string    `json:"negotiated_version"`
	CipherSuite       string    `json:"cipher_suite"`
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	DaysUntilExpiry   int       `json:"days_until_expiry"`
	DNSNames          []string  `json:"dns_names"`
	SignatureAlgo     string    `json:"signature_algorithm"`
	ChainLength       int       `json:"chain_length"`
	// SupportedVersions lists the TLS versions the server accepted when probed
	// individually (e.g. "TLS 1.0", "TLS 1.2"). Legacy versions here are a finding.
	SupportedVersions []string `json:"supported_versions"`
}

// probeVersions is the set of TLS versions we attempt one by one so we can
// report exactly which ones a server still accepts.
var probeVersions = []struct {
	name string
	id   uint16
}{
	{"TLS 1.0", tls.VersionTLS10},
	{"TLS 1.1", tls.VersionTLS11},
	{"TLS 1.2", tls.VersionTLS12},
	{"TLS 1.3", tls.VersionTLS13},
}

// Analyze performs a TLS handshake against host:port and returns a Result.
// timeout bounds each connection attempt. host may include a port; if not,
// defaultPort is used.
func Analyze(host, defaultPort string, timeout time.Duration) (*Result, error) {
	h, port := splitHostPort(host, defaultPort)

	// Main handshake: let Go negotiate the best version so we capture what a
	// normal client would actually get.
	conn, err := dial(h, port, &tls.Config{
		ServerName:         h,
		InsecureSkipVerify: true, // we inspect the cert ourselves rather than trust it
		MinVersion:         tls.VersionTLS10,
	}, timeout)
	if err != nil {
		return nil, fmt.Errorf("tls handshake with %s:%s failed: %w", h, port, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("server %s:%s presented no certificate", h, port)
	}
	leaf := state.PeerCertificates[0]

	res := &Result{
		Host:              h,
		Port:              port,
		NegotiatedVersion: versionName(state.Version),
		CipherSuite:       tls.CipherSuiteName(state.CipherSuite),
		Subject:           leaf.Subject.CommonName,
		Issuer:            leaf.Issuer.CommonName,
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
		DaysUntilExpiry:   int(time.Until(leaf.NotAfter).Hours() / 24),
		DNSNames:          leaf.DNSNames,
		SignatureAlgo:     leaf.SignatureAlgorithm.String(),
		ChainLength:       len(state.PeerCertificates),
		SupportedVersions: supportedVersions(h, port, timeout),
	}
	return res, nil
}

// supportedVersions probes each TLS version individually. Errors mean the
// version was refused, which is the desired outcome for legacy versions.
func supportedVersions(host, port string, timeout time.Duration) []string {
	var found []string
	for _, v := range probeVersions {
		conn, err := dial(host, port, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			MinVersion:         v.id,
			MaxVersion:         v.id,
		}, timeout)
		if err == nil {
			found = append(found, v.name)
			conn.Close()
		}
	}
	return found
}

func dial(host, port string, cfg *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	return tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), cfg)
}

// splitHostPort returns host and port, applying defaultPort when host carries none.
func splitHostPort(host, defaultPort string) (string, string) {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimSuffix(host, "/")
	if h, p, err := net.SplitHostPort(host); err == nil {
		return h, p
	}
	return host, defaultPort
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", v)
	}
}

// IsSelfSigned reports whether the leaf certificate is its own issuer.
func (r *Result) IsSelfSigned() bool {
	return r.Subject != "" && r.Subject == r.Issuer
}
