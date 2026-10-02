// Package report turns TLS and header results into a prioritized, human- or
// machine-readable report.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/h3m/tls-header-auditor/internal/headers"
	"github.com/h3m/tls-header-auditor/internal/tlscheck"
)

// Report is the top-level structure for one audited target.
type Report struct {
	Target    string           `json:"target"`
	Timestamp time.Time        `json:"timestamp"`
	TLS       *tlscheck.Result `json:"tls,omitempty"`
	Headers   *headers.Result  `json:"headers,omitempty"`
	Issues    []Issue          `json:"issues"`
	Score     int              `json:"score"` // 0-100, higher is better
}

// Issue is a single prioritized problem surfaced by the audit.
type Issue struct {
	Severity headers.Severity `json:"severity"`
	Area     string           `json:"area"` // "TLS" or "Headers"
	Title    string           `json:"title"`
	Detail   string           `json:"detail"`
}

// severityWeight maps a severity to the points deducted from a perfect score.
var severityWeight = map[headers.Severity]int{
	headers.SeverityHigh:   20,
	headers.SeverityMedium: 10,
	headers.SeverityLow:    4,
	headers.SeverityInfo:   1,
}

// severityRank orders severities for sorting (lower = more severe).
var severityRank = map[headers.Severity]int{
	headers.SeverityHigh:   0,
	headers.SeverityMedium: 1,
	headers.SeverityLow:    2,
	headers.SeverityInfo:   3,
	headers.SeverityOK:     4,
}

// Build assembles a Report from TLS and header results, deriving issues and a score.
func Build(target string, tlsRes *tlscheck.Result, hdrRes *headers.Result) *Report {
	r := &Report{
		Target:    target,
		Timestamp: time.Now().UTC(),
		TLS:       tlsRes,
		Headers:   hdrRes,
	}
	r.deriveTLSIssues()
	r.deriveHeaderIssues()
	r.sortAndScore()
	return r
}

func (r *Report) deriveTLSIssues() {
	if r.TLS == nil {
		return
	}
	t := r.TLS

	for _, v := range t.SupportedVersions {
		if v == "TLS 1.0" || v == "TLS 1.1" {
			r.Issues = append(r.Issues, Issue{
				Severity: headers.SeverityHigh,
				Area:     "TLS",
				Title:    fmt.Sprintf("Legacy protocol %s accepted", v),
				Detail:   "Disable TLS 1.0/1.1; they are deprecated and vulnerable. Require TLS 1.2 or higher.",
			})
		}
	}

	switch {
	case t.DaysUntilExpiry < 0:
		r.Issues = append(r.Issues, Issue{
			Severity: headers.SeverityHigh,
			Area:     "TLS",
			Title:    "Certificate expired",
			Detail:   fmt.Sprintf("Certificate expired %d day(s) ago (%s).", -t.DaysUntilExpiry, t.NotAfter.Format("2006-01-02")),
		})
	case t.DaysUntilExpiry < 15:
		r.Issues = append(r.Issues, Issue{
			Severity: headers.SeverityHigh,
			Area:     "TLS",
			Title:    "Certificate expiring very soon",
			Detail:   fmt.Sprintf("Certificate expires in %d day(s) (%s).", t.DaysUntilExpiry, t.NotAfter.Format("2006-01-02")),
		})
	case t.DaysUntilExpiry < 30:
		r.Issues = append(r.Issues, Issue{
			Severity: headers.SeverityMedium,
			Area:     "TLS",
			Title:    "Certificate expiring soon",
			Detail:   fmt.Sprintf("Certificate expires in %d day(s) (%s).", t.DaysUntilExpiry, t.NotAfter.Format("2006-01-02")),
		})
	}

	if t.IsSelfSigned() {
		r.Issues = append(r.Issues, Issue{
			Severity: headers.SeverityMedium,
			Area:     "TLS",
			Title:    "Self-signed certificate",
			Detail:   "The leaf certificate is self-signed; clients will not trust it by default.",
		})
	}

	if strings.Contains(strings.ToLower(t.SignatureAlgo), "sha1") {
		r.Issues = append(r.Issues, Issue{
			Severity: headers.SeverityHigh,
			Area:     "TLS",
			Title:    "Weak signature algorithm (SHA-1)",
			Detail:   "SHA-1 is collision-prone; reissue the certificate with SHA-256 or stronger.",
		})
	}
}

func (r *Report) deriveHeaderIssues() {
	if r.Headers == nil {
		return
	}
	for _, f := range r.Headers.Findings {
		if f.Severity == headers.SeverityOK {
			continue
		}
		title := f.Header + " missing"
		if f.Present {
			title = f.Header + " weak configuration"
		}
		r.Issues = append(r.Issues, Issue{
			Severity: f.Severity,
			Area:     "Headers",
			Title:    title,
			Detail:   f.Recommendation,
		})
	}
}

func (r *Report) sortAndScore() {
	sort.SliceStable(r.Issues, func(i, j int) bool {
		return severityRank[r.Issues[i].Severity] < severityRank[r.Issues[j].Severity]
	})

	score := 100
	for _, iss := range r.Issues {
		score -= severityWeight[iss.Severity]
	}
	if score < 0 {
		score = 0
	}
	r.Score = score
}

// Grade converts the numeric score to a letter grade.
func (r *Report) Grade() string {
	switch {
	case r.Score >= 90:
		return "A"
	case r.Score >= 75:
		return "B"
	case r.Score >= 60:
		return "C"
	case r.Score >= 40:
		return "D"
	default:
		return "F"
	}
}

// WriteJSON emits the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText emits a human-readable report. useColor adds ANSI color when true.
func (r *Report) WriteText(w io.Writer, useColor bool) error {
	p := func(format string, a ...any) {
		fmt.Fprintf(w, format, a...)
	}

	p("\n=== TLS & Header Audit: %s ===\n", r.Target)
	p("Scanned: %s\n", r.Timestamp.Format(time.RFC3339))
	p("Score:   %d/100  (Grade %s)\n", r.Score, r.Grade())

	if r.TLS != nil {
		p("\n-- TLS --\n")
		p("  Negotiated:        %s / %s\n", r.TLS.NegotiatedVersion, r.TLS.CipherSuite)
		p("  Accepted versions: %s\n", strings.Join(r.TLS.SupportedVersions, ", "))
		p("  Certificate:       %s\n", r.TLS.Subject)
		p("  Issuer:            %s\n", r.TLS.Issuer)
		p("  Expires:           %s (%d days)\n", r.TLS.NotAfter.Format("2006-01-02"), r.TLS.DaysUntilExpiry)
		p("  Signature:         %s\n", r.TLS.SignatureAlgo)
	}

	if r.Headers != nil {
		p("\n-- Security Headers --\n")
		for _, f := range r.Headers.Findings {
			status := "missing"
			if f.Present {
				status = "present"
			}
			p("  [%s] %-28s %s\n", colorize(string(f.Severity), useColor), f.Header, status)
		}
	}

	p("\n-- Prioritized Issues (%d) --\n", len(r.Issues))
	if len(r.Issues) == 0 {
		p("  None found. Clean result.\n")
	}
	for i, iss := range r.Issues {
		p("  %d. [%s] (%s) %s\n", i+1, colorize(string(iss.Severity), useColor), iss.Area, iss.Title)
		p("       %s\n", iss.Detail)
	}
	p("\n")
	return nil
}

// colorize wraps a severity label in ANSI color when enabled.
func colorize(sev string, useColor bool) string {
	if !useColor {
		return sev
	}
	const reset = "\033[0m"
	var code string
	switch headers.Severity(sev) {
	case headers.SeverityHigh:
		code = "\033[31m" // red
	case headers.SeverityMedium:
		code = "\033[33m" // yellow
	case headers.SeverityLow:
		code = "\033[36m" // cyan
	case headers.SeverityInfo:
		code = "\033[90m" // gray
	case headers.SeverityOK:
		code = "\033[32m" // green
	default:
		return sev
	}
	return code + sev + reset
}
