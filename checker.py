#!/usr/bin/env python3
"""Web App Security Header Checker - for authorized testing only."""
import argparse
import json
import sys
import requests

# header name -> (weight, description, fix)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (20, "Forces HTTPS",
        "Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "Content-Security-Policy": (25, "Mitigates XSS / data injection",
        "Content-Security-Policy: default-src 'self'"),
    "X-Frame-Options": (10, "Prevents clickjacking",
        "X-Frame-Options: DENY (or CSP frame-ancestors)"),
    "X-Content-Type-Options": (10, "Stops MIME sniffing",
        "X-Content-Type-Options: nosniff"),
    "Referrer-Policy": (10, "Controls referrer leakage",
        "Referrer-Policy: strict-origin-when-cross-origin"),
    "Permissions-Policy": (10, "Restricts browser features",
        "Permissions-Policy: geolocation=(), camera=(), microphone=()"),
    "Cross-Origin-Opener-Policy": (5, "Isolates browsing context",
        "Cross-Origin-Opener-Policy: same-origin"),
    "Cross-Origin-Resource-Policy": (5, "Limits cross-origin loads",
        "Cross-Origin-Resource-Policy: same-origin"),
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

def normalize(url: str) -> str:
    return url if url.startswith(("http://", "https://")) else "https://" + url

def check_value_quality(name: str, value: str) -> list[str]:
    """Flag weak configurations of headers that are present."""
    issues = []
    v = value.lower()
    if name == "Strict-Transport-Security":
        try:
            age = int(v.split("max-age=")[1].split(";")[0])
            if age < 15552000:
                issues.append("max-age is less than 180 days")
        except (IndexError, ValueError):
            issues.append("max-age missing or invalid")
    elif name == "Content-Security-Policy":
        if "unsafe-inline" in v:
            issues.append("uses 'unsafe-inline'")
        if "unsafe-eval" in v:
            issues.append("uses 'unsafe-eval'")
        if "*" in v.replace("*.", ""):
            issues.append("contains wildcard source")
    elif name == "X-Frame-Options":
        if v not in ("deny", "sameorigin"):
            issues.append("should be DENY or SAMEORIGIN")
    elif name == "X-Content-Type-Options":
        if v != "nosniff":
            issues.append("should be 'nosniff'")
    return issues

def check_cookies(resp) -> list[dict]:
    results = []
    try:
        cookies = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        cookies = []
    for c in cookies:
        lc = c.lower()
        name = c.split("=")[0]
        missing = []
        if "secure" not in lc:
            missing.append("Secure")
        if "httponly" not in lc:
            missing.append("HttpOnly")
        if "samesite" not in lc:
            missing.append("SameSite")
        results.append({"cookie": name, "missing_flags": missing})
    return results


def scan(url: str, timeout: int = 10) -> dict:
    url = normalize(url)
    resp = requests.get(url, timeout=timeout, allow_redirects=True,
                        headers={"User-Agent": "HeaderChecker/1.0 (educational)"})
    report = {"url": resp.url, "status": resp.status_code,
              "headers": {}, "leaks": {}, "cookies": [], "score": 0}
    score = 0

    for name, (weight, desc, fix) in SECURITY_HEADERS.items():
        value = resp.headers.get(name)
        if value:
            issues = check_value_quality(name, value)
            earned = weight if not issues else weight // 2
            score += earned
            report["headers"][name] = {"present": True, "value": value,
                                       "issues": issues}
        else:
            report["headers"][name] = {"present": False, "why": desc, "fix": fix}

    for h in LEAKY_HEADERS:
        if h in resp.headers:
            report["leaks"][h] = resp.headers[h]

    report["cookies"] = check_cookies(resp)
    report["score"] = score
    report["grade"] = ("A" if score >= 90 else "B" if score >= 75 else
                       "C" if score >= 55 else "D" if score >= 35 else "F")
    return report


def print_report(r: dict) -> None:
    print(f"\nTarget : {r['url']}  (HTTP {r['status']})")
    print(f"Score  : {r['score']}/100   Grade: {r['grade']}\n")
    for name, info in r["headers"].items():
        if info["present"]:
            flag = "WEAK" if info["issues"] else "OK  "
            print(f"[{flag}] {name}")
            for i in info["issues"]:
                print(f"         - {i}")
        else:
            print(f"[MISS] {name}  ({info['why']})")
            print(f"         Fix: {info['fix']}")
    if r["leaks"]:
        print("\nInformation disclosure:")
        for k, v in r["leaks"].items():
            print(f"  [LEAK] {k}: {v}")
    if r["cookies"]:
        print("\nCookies:")
        for c in r["cookies"]:
            status = "OK" if not c["missing_flags"] else "missing " + ", ".join(c["missing_flags"])
            print(f"  {c['cookie']}: {status}")


def main():
    p = argparse.ArgumentParser(description="Security header checker")
    p.add_argument("url", help="Target URL (authorized targets only)")
    p.add_argument("--json", action="store_true", help="Output JSON")
    args = p.parse_args()
    try:
        report = scan(args.url)
    except requests.RequestException as e:
        sys.exit(f"Request failed: {e}")
    print(json.dumps(report, indent=2) if args.json else "", end="")
    if not args.json:
        print_report(report)

if __name__ == "__main__":
    main()