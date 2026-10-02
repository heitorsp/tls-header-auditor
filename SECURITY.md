# Security Policy

## Reporting a Vulnerability

Please report security issues privately via GitHub's
[Private Vulnerability Reporting](https://github.com/heitorsp/tls-header-auditor/security/advisories/new)
rather than opening a public issue.

You can expect an acknowledgement within a few days. Please include steps to
reproduce and the affected version or commit.

## Scope and Responsible Use

`tls-header-auditor` is a defensive assessment tool. It performs standard TLS
handshakes and HTTP GET requests — the same traffic a browser makes — and does
not exploit anything.

**Only scan hosts you own or are explicitly authorized to assess.** Unauthorized
scanning may be illegal in your jurisdiction. The authors accept no liability
for misuse.
