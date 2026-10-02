# tls-header-auditor

A small, fast command-line auditor for the two things that quietly decide how
exposed a web host is: its **TLS configuration** and its **HTTP security
headers**. It connects like a normal browser, grades what it finds, and prints a
prioritized list of what to fix first.

Single static binary, no dependencies, written in Go.

> ⚠️ **Authorized use only.** This tool makes ordinary TLS handshakes and HTTP
> GET requests — it does not exploit anything — but you should only point it at
> hosts you own or are explicitly authorized to assess.

## Why

Most "is my site secure?" checklists bury the few findings that matter under
dozens that don't. `tls-header-auditor` collapses a scan into a single score and
an ordered worklist: legacy TLS versions, expiring or weak certificates, and
missing or misconfigured security headers, each with a one-line fix. It is built
to drop into a pipeline (`--json`, `--fail-under`) as easily as it runs by hand.

## What it checks

**TLS**
- Negotiated protocol version and cipher suite
- Which TLS versions the server still accepts (TLS 1.0 / 1.1 are flagged)
- Certificate subject, issuer, chain length and validity window
- Expiry warnings (expired, &lt;15 days, &lt;30 days)
- Self-signed certificates and weak (SHA-1) signatures

**HTTP security headers**
- `Strict-Transport-Security` (HSTS), `Content-Security-Policy`
- `X-Frame-Options`, `X-Content-Type-Options`
- `Referrer-Policy`, `Permissions-Policy`
- Information-leaking headers (`Server`, `X-Powered-By`, …)

Each finding carries a severity (HIGH / MEDIUM / LOW / INFO) and a concrete
recommendation. The target gets a score from 0–100 and a letter grade.

## Install

Requires Go 1.25 or newer (a currently supported release).

```bash
go install github.com/h3m/tls-header-auditor/cmd/tlsaudit@latest
```

Or build from source:

```bash
git clone https://github.com/h3m/tls-header-auditor.git
cd tls-header-auditor
go build -o tlsaudit ./cmd/tlsaudit
```

## Usage

```bash
# Audit a single host
tlsaudit example.com

# Audit several at once
tlsaudit example.com sub.example.org https://example.net

# Machine-readable output for pipelines
tlsaudit --json example.com

# Fail the command (exit 1) if the score drops below a threshold — useful in CI
tlsaudit --fail-under 75 example.com
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | `false` | Emit JSON instead of the text report |
| `--no-color` | `false` | Disable ANSI colors in text output |
| `--timeout` | `10s` | Per-connection timeout |
| `--fail-under N` | off | Exit non-zero if any target scores below N (0–100) |
| `--version` | | Print version and exit |

### Example output

```
=== TLS & Header Audit: example.com ===
Scanned: 2026-10-02T00:20:54Z
Score:   22/100  (Grade F)

-- TLS --
  Negotiated:        TLS 1.3 / TLS_AES_128_GCM_SHA256
  Accepted versions: TLS 1.2, TLS 1.3
  Certificate:       example.com
  Expires:           2026-11-01 (29 days)
  Signature:         SHA256-RSA

-- Prioritized Issues (7) --
  1. [HIGH] (Headers) Strict-Transport-Security missing
       Add HSTS to force HTTPS and prevent protocol downgrade...
  2. [HIGH] (Headers) Content-Security-Policy missing
       Add a CSP to mitigate XSS and data injection...
  3. [MEDIUM] (TLS) Certificate expiring soon
       Certificate expires in 29 day(s) (2026-11-01).
  ...
```

## Scoring

Starts at 100; each issue deducts points by severity (HIGH −20, MEDIUM −10,
LOW −4, INFO −1), floored at 0. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, else F.
It is a heuristic to rank hosts and spot regressions, not an industry standard.

## Development

```bash
go test ./...        # run tests
go vet ./...         # static checks
go test -race ./...  # race detector
```

CI runs build, vet, tests (with the race detector), `golangci-lint` and
`govulncheck` on every push and pull request.

## License

[MIT](LICENSE) © Heitor Henrique Hernandez Matos
