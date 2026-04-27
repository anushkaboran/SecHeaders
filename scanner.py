import requests
import argparse
import json
from datetime import datetime

# Security headers to check with descriptions and severity
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Enforces HTTPS connections. Prevents protocol downgrade attacks and cookie hijacking.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Prevents XSS attacks by controlling which resources the browser is allowed to load.",
        "recommendation": "Add a CSP header tailored to your application. Start with: Content-Security-Policy: default-src 'self'"
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Prevents clickjacking attacks by controlling if the page can be embedded in iframes.",
        "recommendation": "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME-type sniffing attacks.",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls how much referrer information is sent with requests.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Controls which browser features and APIs can be used.",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()"
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Legacy XSS filter for older browsers (CSP is preferred).",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block"
    },
    "Cache-Control": {
        "severity": "LOW",
        "description": "Controls caching behavior. Sensitive pages should not be cached.",
        "recommendation": "Add: Cache-Control: no-store for sensitive pages"
    },
}

SEVERITY_SCORE = {"HIGH": 30, "MEDIUM": 15, "LOW": 5}
SEVERITY_COLOR = {"HIGH": "MISSING (HIGH)", "MEDIUM": "MISSING (MEDIUM)", "LOW": "MISSING (LOW)", "PRESENT": "PRESENT"}


def scan(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print(f"\n{'='*60}")
    print(f"  SecHeaders Scanner")
    print(f"  Target : {url}")
    print(f"  Time   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not reach {url}: {e}")
        return

    headers = {k.lower(): v for k, v in response.headers.items()}
    results = []
    total_deductions = 0
    max_score = 100

    for header, meta in SECURITY_HEADERS.items():
        present = header.lower() in headers
        value = headers.get(header.lower(), None)
        deduction = 0 if present else SEVERITY_SCORE[meta["severity"]]
        total_deductions += deduction

        results.append({
            "header": header,
            "present": present,
            "value": value,
            "severity": meta["severity"],
            "description": meta["description"],
            "recommendation": meta["recommendation"],
            "deduction": deduction
        })

    score = max(0, max_score - total_deductions)

    # Print results
    print(f"{'HEADER':<35} {'STATUS':<25} {'VALUE'}")
    print(f"{'-'*35} {'-'*25} {'-'*30}")

    for r in results:
        status = "OK" if r["present"] else f"MISSING [{r['severity']}]"
        value_display = (r["value"][:40] + "...") if r["value"] and len(r["value"]) > 40 else (r["value"] or "-")
        print(f"{r['header']:<35} {status:<25} {value_display}")

    print(f"\n{'='*60}")
    print(f"  SECURITY SCORE: {score}/100", end="  ")
    if score >= 80:
        print("[GOOD]")
    elif score >= 50:
        print("[NEEDS IMPROVEMENT]")
    else:
        print("[AT RISK]")
    print(f"{'='*60}\n")

    # Print recommendations for missing headers
    missing = [r for r in results if not r["present"]]
    if missing:
        print("RECOMMENDATIONS:\n")
        for r in sorted(missing, key=lambda x: SEVERITY_SCORE[x["severity"]], reverse=True):
            print(f"  [{r['severity']}] {r['header']}")
            print(f"  Why: {r['description']}")
            print(f"  Fix: {r['recommendation']}")
            print()
    else:
        print("All security headers are present. Great job!\n")

    # Export JSON report
    report = {
        "target": url,
        "scanned_at": datetime.now().isoformat(),
        "score": score,
        "results": results
    }

    filename = f"secheaders_report_{url.replace('https://','').replace('http://','').replace('/','_')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Full report saved to: {filename}\n")


def main():
    parser = argparse.ArgumentParser(
        description="SecHeaders - HTTP Security Headers Analyzer",
        epilog="Example: python scanner.py --url example.com"
    )
    parser.add_argument("--url", required=True, help="Target URL to scan (e.g. example.com)")
    args = parser.parse_args()
    scan(args.url)


if __name__ == "__main__":
    main()