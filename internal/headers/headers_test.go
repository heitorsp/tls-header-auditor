package headers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNormalizeURL(t *testing.T) {
	cases := map[string]string{
		"example.com":         "https://example.com",
		"http://example.com":  "http://example.com",
		"https://example.com": "https://example.com",
		"  example.com  ":     "https://example.com",
	}
	for in, want := range cases {
		if got := normalizeURL(in); got != want {
			t.Errorf("normalizeURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAnalyze_MissingHeaders(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Intentionally send no security headers, plus a leaky Server header.
		w.Header().Set("Server", "TestStack/9.9")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := Analyze(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	bySeverity := map[string]Finding{}
	for _, f := range res.Findings {
		bySeverity[f.Header] = f
	}

	hsts, ok := bySeverity["Strict-Transport-Security"]
	if !ok || hsts.Present {
		t.Errorf("expected HSTS to be reported missing, got %+v", hsts)
	}
	if hsts.Severity != SeverityHigh {
		t.Errorf("expected missing HSTS to be HIGH, got %s", hsts.Severity)
	}

	server, ok := bySeverity["Server"]
	if !ok || server.Severity != SeverityInfo {
		t.Errorf("expected Server header INFO finding, got %+v", server)
	}
}

func TestAnalyze_StrongHeaders(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "geolocation=()")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res, err := Analyze(srv.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("Analyze returned error: %v", err)
	}

	for _, f := range res.Findings {
		if f.Severity != SeverityOK && f.Severity != SeverityInfo {
			t.Errorf("header %s should be OK with strong config, got %s", f.Header, f.Severity)
		}
	}
}

func TestEvaluateHSTS(t *testing.T) {
	var hstsCheck headerCheck
	for _, c := range checks {
		if c.name == "Strict-Transport-Security" {
			hstsCheck = c
		}
	}
	if sev, _ := hstsCheck.evaluate("includeSubDomains"); sev != SeverityMedium {
		t.Errorf("HSTS without max-age should be MEDIUM, got %s", sev)
	}
	if sev, _ := hstsCheck.evaluate("max-age=0"); sev != SeverityMedium {
		t.Errorf("HSTS max-age=0 should be MEDIUM, got %s", sev)
	}
	if sev, _ := hstsCheck.evaluate("max-age=63072000"); sev != SeverityOK {
		t.Errorf("valid HSTS should be OK, got %s", sev)
	}
}

func TestEvaluateCSP(t *testing.T) {
	var cspCheck headerCheck
	for _, c := range checks {
		if c.name == "Content-Security-Policy" {
			cspCheck = c
		}
	}
	if sev, _ := cspCheck.evaluate("default-src 'self' 'unsafe-inline'"); sev != SeverityLow {
		t.Errorf("CSP with unsafe-inline should be LOW, got %s", sev)
	}
	if sev, advice := cspCheck.evaluate("default-src 'self'"); sev != SeverityOK {
		t.Errorf("strict CSP should be OK, got %s (%s)", sev, advice)
	}
}
