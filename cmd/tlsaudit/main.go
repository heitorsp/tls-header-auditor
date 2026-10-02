// Command tlsaudit audits the TLS configuration and HTTP security headers of
// one or more hosts and prints a prioritized report.
//
// Usage:
//
//	tlsaudit example.com
//	tlsaudit --json example.com https://sub.example.org
//	tlsaudit --timeout 5s --no-color example.com
//
// Only inspect hosts you are authorized to test.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/heitorsp/tls-header-auditor/internal/headers"
	"github.com/heitorsp/tls-header-auditor/internal/report"
	"github.com/heitorsp/tls-header-auditor/internal/tlscheck"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	var (
		jsonOut     bool
		noColor     bool
		timeout     time.Duration
		showVersion bool
		failUnder   int
	)
	flag.BoolVar(&jsonOut, "json", false, "output JSON instead of text")
	flag.BoolVar(&noColor, "no-color", false, "disable ANSI colors in text output")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "per-connection timeout")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.IntVar(&failUnder, "fail-under", -1, "exit non-zero if any target scores below this (0-100)")
	flag.Usage = usage
	flag.Parse()

	if showVersion {
		fmt.Printf("tlsaudit %s\n", version)
		return 0
	}

	targets := flag.Args()
	if len(targets) == 0 {
		usage()
		return 2
	}

	exitCode := 0
	for _, target := range targets {
		rep := auditTarget(target, timeout)

		if jsonOut {
			if err := rep.WriteJSON(os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "error writing JSON: %v\n", err)
				exitCode = 1
			}
		} else {
			if err := rep.WriteText(os.Stdout, !noColor); err != nil {
				fmt.Fprintf(os.Stderr, "error writing report: %v\n", err)
				exitCode = 1
			}
		}

		if failUnder >= 0 && rep.Score < failUnder {
			exitCode = 1
		}
	}
	return exitCode
}

// auditTarget runs both checks for one target and builds a report. Failures in
// either check are recorded in the report rather than aborting the run.
func auditTarget(target string, timeout time.Duration) *report.Report {
	tlsRes, tlsErr := tlscheck.Analyze(target, "443", timeout)
	if tlsErr != nil {
		fmt.Fprintf(os.Stderr, "warning: TLS check failed for %s: %v\n", target, tlsErr)
	}

	hdrRes, hdrErr := headers.Analyze(target, timeout)
	if hdrErr != nil {
		fmt.Fprintf(os.Stderr, "warning: header check failed for %s: %v\n", target, hdrErr)
	}

	return report.Build(target, tlsRes, hdrRes)
}

func usage() {
	fmt.Fprintf(os.Stderr, `tlsaudit %s - TLS & HTTP security header auditor

Usage:
  tlsaudit [flags] <host> [host...]

Flags:
`, version)
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Examples:
  tlsaudit example.com
  tlsaudit --json example.com sub.example.org
  tlsaudit --fail-under 75 example.com

Only test hosts you own or are explicitly authorized to assess.
`)
}
