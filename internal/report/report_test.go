package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/h3m/tls-header-auditor/internal/headers"
	"github.com/h3m/tls-header-auditor/internal/tlscheck"
)

func TestBuild_ScoreAndGrade(t *testing.T) {
	tlsRes := &tlscheck.Result{
		Host:              "example.com",
		NegotiatedVersion: "TLS 1.3",
		SupportedVersions: []string{"TLS 1.2", "TLS 1.3"},
		NotAfter:          time.Now().Add(90 * 24 * time.Hour),
		DaysUntilExpiry:   90,
		SignatureAlgo:     "SHA256-RSA",
		Subject:           "example.com",
		Issuer:            "Some CA",
	}
	hdrRes := &headers.Result{
		URL: "https://example.com",
		Findings: []headers.Finding{
			{Header: "Strict-Transport-Security", Present: true, Severity: headers.SeverityOK},
			{Header: "Content-Security-Policy", Present: true, Severity: headers.SeverityOK},
			{Header: "X-Frame-Options", Present: true, Severity: headers.SeverityOK},
			{Header: "X-Content-Type-Options", Present: true, Severity: headers.SeverityOK},
			{Header: "Referrer-Policy", Present: true, Severity: headers.SeverityOK},
			{Header: "Permissions-Policy", Present: true, Severity: headers.SeverityOK},
		},
	}

	r := Build("example.com", tlsRes, hdrRes)
	if r.Score != 100 {
		t.Errorf("clean target should score 100, got %d", r.Score)
	}
	if r.Grade() != "A" {
		t.Errorf("score 100 should be grade A, got %s", r.Grade())
	}
	if len(r.Issues) != 0 {
		t.Errorf("clean target should have 0 issues, got %d", len(r.Issues))
	}
}

func TestBuild_LegacyTLSAndExpiry(t *testing.T) {
	tlsRes := &tlscheck.Result{
		Host:              "legacy.example",
		NegotiatedVersion: "TLS 1.2",
		SupportedVersions: []string{"TLS 1.0", "TLS 1.1", "TLS 1.2"},
		NotAfter:          time.Now().Add(-5 * 24 * time.Hour),
		DaysUntilExpiry:   -5,
		SignatureAlgo:     "SHA1-RSA",
		Subject:           "legacy.example",
		Issuer:            "legacy.example", // self-signed
	}

	r := Build("legacy.example", tlsRes, nil)

	var high int
	for _, iss := range r.Issues {
		if iss.Severity == headers.SeverityHigh {
			high++
		}
	}
	// Expect at least: TLS 1.0, TLS 1.1, expired cert, SHA-1 => 4 HIGH issues.
	if high < 4 {
		t.Errorf("expected >=4 HIGH issues, got %d (issues: %d)", high, len(r.Issues))
	}
	if r.Score > 40 {
		t.Errorf("badly configured target should score low, got %d", r.Score)
	}

	// Issues must be sorted with HIGH first.
	if len(r.Issues) > 0 && r.Issues[0].Severity != headers.SeverityHigh {
		t.Errorf("first issue should be HIGH, got %s", r.Issues[0].Severity)
	}
}

func TestWriteJSON(t *testing.T) {
	r := Build("example.com", nil, nil)
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	if !strings.Contains(buf.String(), `"target": "example.com"`) {
		t.Errorf("JSON output missing target field: %s", buf.String())
	}
}

func TestWriteText(t *testing.T) {
	r := Build("example.com", nil, nil)
	var buf bytes.Buffer
	if err := r.WriteText(&buf, false); err != nil {
		t.Fatalf("WriteText error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "TLS & Header Audit") {
		t.Errorf("text output missing header: %s", out)
	}
	if !strings.Contains(out, "Score:") {
		t.Errorf("text output missing score line")
	}
}

func TestGradeBoundaries(t *testing.T) {
	cases := []struct {
		score int
		grade string
	}{
		{100, "A"}, {90, "A"}, {89, "B"}, {75, "B"}, {74, "C"},
		{60, "C"}, {59, "D"}, {40, "D"}, {39, "F"}, {0, "F"},
	}
	for _, c := range cases {
		r := &Report{Score: c.score}
		if got := r.Grade(); got != c.grade {
			t.Errorf("score %d: grade = %s, want %s", c.score, got, c.grade)
		}
	}
}
