// Package headers fetches a URL and evaluates its HTTP security headers,
// producing one Finding per header of interest.
package headers

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Severity ranks a finding by how much it matters.
type Severity string

const (
	SeverityHigh   Severity = "HIGH"
	SeverityMedium Severity = "MEDIUM"
	SeverityLow    Severity = "LOW"
	SeverityInfo   Severity = "INFO"
	SeverityOK     Severity = "OK"
)

// Finding is the result of checking a single security header.
type Finding struct {
	Header         string   `json:"header"`
	Present        bool     `json:"present"`
	Value          string   `json:"value,omitempty"`
	Severity       Severity `json:"severity"`
	Recommendation string   `json:"recommendation"`
}

// Result bundles the findings for one URL.
type Result struct {
	URL        string    `json:"url"`
	StatusCode int       `json:"status_code"`
	Findings   []Finding `json:"findings"`
}

// headerCheck describes one security header and how to judge it.
type headerCheck struct {
	name          string
	missingSev    Severity
	missingAdvice string
	// evaluate inspects a present value and may downgrade/annotate the finding.
	// It returns the severity and recommendation for the value as found.
	evaluate func(value string) (Severity, string)
}

// checks is the catalogue of security headers we audit. Each entry encodes the
// rationale so the recommendation travels with the finding.
var checks = []headerCheck{
	{
		name:          "Strict-Transport-Security",
		missingSev:    SeverityHigh,
		missingAdvice: "Add HSTS to force HTTPS and prevent protocol downgrade. Suggested: max-age=31536000; includeSubDomains.",
		evaluate: func(v string) (Severity, string) {
			if !strings.Contains(strings.ToLower(v), "max-age") {
				return SeverityMedium, "HSTS present but missing max-age; the directive has no effect without it."
			}
			if strings.Contains(v, "max-age=0") {
				return SeverityMedium, "HSTS is explicitly disabled (max-age=0)."
			}
			return SeverityOK, "HSTS is configured."
		},
	},
	{
		name:          "Content-Security-Policy",
		missingSev:    SeverityHigh,
		missingAdvice: "Add a CSP to mitigate XSS and data injection. Start in Report-Only mode to tune it before enforcing.",
		evaluate: func(v string) (Severity, string) {
			if strings.Contains(v, "unsafe-inline") || strings.Contains(v, "unsafe-eval") {
				return SeverityLow, "CSP present but uses unsafe-inline/unsafe-eval, which weakens XSS protection."
			}
			return SeverityOK, "CSP is configured."
		},
	},
	{
		name:          "X-Frame-Options",
		missingSev:    SeverityMedium,
		missingAdvice: "Add X-Frame-Options: DENY (or SAMEORIGIN), or a CSP frame-ancestors directive, to prevent clickjacking.",
		evaluate: func(v string) (Severity, string) {
			return SeverityOK, "Clickjacking protection is set."
		},
	},
	{
		name:          "X-Content-Type-Options",
		missingSev:    SeverityMedium,
		missingAdvice: "Add X-Content-Type-Options: nosniff to stop browsers from MIME-sniffing responses.",
		evaluate: func(v string) (Severity, string) {
			if strings.EqualFold(strings.TrimSpace(v), "nosniff") {
				return SeverityOK, "MIME-sniffing is disabled."
			}
			return SeverityLow, "Value should be exactly 'nosniff'."
		},
	},
	{
		name:          "Referrer-Policy",
		missingSev:    SeverityLow,
		missingAdvice: "Add a Referrer-Policy (e.g. strict-origin-when-cross-origin) to limit referrer leakage.",
		evaluate: func(v string) (Severity, string) {
			return SeverityOK, "Referrer policy is set."
		},
	},
	{
		name:          "Permissions-Policy",
		missingSev:    SeverityLow,
		missingAdvice: "Add a Permissions-Policy to restrict powerful browser features (camera, geolocation, etc.).",
		evaluate: func(v string) (Severity, string) {
			return SeverityOK, "Permissions policy is set."
		},
	},
}

// infoLeakHeaders are headers whose mere presence leaks stack details.
var infoLeakHeaders = []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"}

// Analyze fetches url and evaluates its security headers. It does not follow
// the response body; only headers and status are used.
func Analyze(url string, timeout time.Duration) (*Result, error) {
	url = normalizeURL(url)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// We audit headers regardless of cert validity; tlscheck handles the cert.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", "tls-header-auditor/1.0 (+https://github.com/h3m/tls-header-auditor)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	res := &Result{URL: url, StatusCode: resp.StatusCode}

	for _, c := range checks {
		val := resp.Header.Get(c.name)
		if val == "" {
			res.Findings = append(res.Findings, Finding{
				Header:         c.name,
				Present:        false,
				Severity:       c.missingSev,
				Recommendation: c.missingAdvice,
			})
			continue
		}
		sev, advice := c.evaluate(val)
		res.Findings = append(res.Findings, Finding{
			Header:         c.name,
			Present:        true,
			Value:          val,
			Severity:       sev,
			Recommendation: advice,
		})
	}

	for _, h := range infoLeakHeaders {
		if val := resp.Header.Get(h); val != "" {
			res.Findings = append(res.Findings, Finding{
				Header:         h,
				Present:        true,
				Value:          val,
				Severity:       SeverityInfo,
				Recommendation: fmt.Sprintf("%s discloses implementation details; consider removing or obscuring it.", h),
			})
		}
	}

	return res, nil
}

// normalizeURL ensures the URL has a scheme, defaulting to https.
func normalizeURL(url string) string {
	url = strings.TrimSpace(url)
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return "https://" + url
	}
	return url
}
