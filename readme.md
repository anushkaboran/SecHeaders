# SecHeaders — HTTP Security Headers Analyzer

A lightweight Python CLI tool that audits any website for missing or misconfigured HTTP security headers, scores its security posture, and generates a JSON report with prioritized remediation recommendations.

## What It Checks

| Header | Severity | Attack it prevents |
|---|---|---|
| Strict-Transport-Security (HSTS) | HIGH | Protocol downgrade, cookie hijacking |
| Content-Security-Policy (CSP) | HIGH | XSS, data injection |
| X-Frame-Options | MEDIUM | Clickjacking |
| X-Content-Type-Options | MEDIUM | MIME sniffing |
| Referrer-Policy | LOW | Information leakage |
| Permissions-Policy | LOW | Feature abuse |
| X-XSS-Protection | LOW | Legacy XSS (older browsers) |
| Cache-Control | LOW | Sensitive data caching |

## Installation

```bash
git clone https://github.com/yourusername/secheaders.git
cd secheaders
pip install requests
```

## Usage

```bash
python scanner.py --url example.com
python scanner.py --url https://yoursite.com
```

## Example Output

```
============================================================
  SecHeaders Scanner
  Target : https://example.com
  Time   : 2026-04-27 14:32:01
============================================================

HEADER                              STATUS                    VALUE
----------------------------------- ------------------------- ------------------------------
Strict-Transport-Security           OK                        max-age=31536000
Content-Security-Policy             MISSING [HIGH]            -
X-Frame-Options                     OK                        DENY
X-Content-Type-Options              OK                        nosniff
...

============================================================
  SECURITY SCORE: 55/100  [NEEDS IMPROVEMENT]
============================================================

RECOMMENDATIONS:

  [HIGH] Content-Security-Policy
  Why: Prevents XSS attacks by controlling which resources the browser is allowed to load.
  Fix: Add: Content-Security-Policy: default-src 'self'
```

A full JSON report is saved automatically after each scan.

## Why This Matters

HTTP security headers are one of the most commonly misconfigured — and most easily fixed — layers of web security. Missing headers like CSP and HSTS are responsible for a large percentage of real-world XSS and MITM vulnerabilities. This tool makes it easy to audit any site and understand exactly what needs to be fixed and why.

## Roadmap

- [ ] Multi-URL batch scanning from a file
- [ ] HTML report output
- [ ] Historical comparison between scans
- [ ] Cloudflare Workers integration for automated scanning

## Related OWASP References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [OWASP Top 10 - A05: Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)