"""Step 8a: URL pattern checks that need no reputation service.

Found by studying real phishing samples:
  * links on cheap, throwaway top-level domains (.store, .site, .art ...)
  * links hosted on free app/site platforms (run.app, github.io, blogspot.com ...)
  * hostnames that contain a raw IP address (251.242.109.208.host.example.net)

All three are MEDIUM on purpose: legitimate mail occasionally does one of them, so they
only push an email over the line when combined with other signals.

Usage:
    python -m phishscan.urlchecks samples/phishing/sample-10930.eml
"""
import argparse
import re
from urllib.parse import urlparse

from .parser import defang, extract_urls, load_eml

RISKY_TLDS = {
    "store", "site", "art", "top", "xyz", "click", "icu", "buzz",
    "cfd", "sbs", "rest", "cyou", "monster", "bond", "quest",
}

# Free platforms that anyone can publish a page on (often abused for fake login pages).
FREE_HOSTING = (
    "run.app", "web.app", "firebaseapp.com", "pages.dev", "netlify.app", "github.io",
    "blogspot.com", "weebly.com", "wixsite.com", "glitch.me", "herokuapp.com",
    "vercel.app", "workers.dev", "storage.googleapis.com", "forms.gle",
    "sites.google.com", "notion.site", "000webhostapp.com", "webflow.io",
    "carrd.co", "ngrok.io", "trycloudflare.com",
)

IP_IN_HOST = re.compile(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d])")


def _finding(check, hosts, message):
    shown = ", ".join(defang(h) for h in sorted(hosts)[:2])
    more = f" (+{len(hosts) - 2} more)" if len(hosts) > 2 else ""
    return {"check": check, "severity": "medium", "detail": f"{message}: {shown}{more}"}


def check_hosts(hosts):
    """Check a collection of hostnames. Returns at most one finding per check type."""
    risky_tld, free_host, ip_host = set(), set(), set()
    for host in hosts:
        if not host:
            continue
        if host.rsplit(".", 1)[-1] in RISKY_TLDS:
            risky_tld.add(host)
        if any(host == d or host.endswith("." + d) for d in FREE_HOSTING):
            free_host.add(host)
        if IP_IN_HOST.search(host):
            ip_host.add(host)

    findings = []
    if risky_tld:
        findings.append(_finding("risky_tld_link", risky_tld, "Link uses a throwaway top-level domain"))
    if free_host:
        findings.append(_finding("free_hosting_link", free_host, "Link points to a free hosting platform"))
    if ip_host:
        findings.append(_finding("ip_in_hostname", ip_host, "Link hostname contains a raw IP address"))
    return findings


def check_urls(msg):
    hosts = {(urlparse(url).hostname or "").lower() for url in extract_urls(msg)}
    return check_hosts(hosts)


def main():
    parser = argparse.ArgumentParser(description="URL pattern checks for one .eml file")
    parser.add_argument("eml_path")
    args = parser.parse_args()
    findings = check_urls(load_eml(args.eml_path))
    if not findings:
        print("no findings")
    for f in findings:
        print(f"[{f['severity'].upper()}] {f['check']}: {f['detail']}")


if __name__ == "__main__":
    main()
