"""Step 2: analyze the links inside an email's HTML.

Finds <a> tags, compares the text the reader SEES with where the link REALLY
goes, and flags URL shorteners.

Needs:  pip install beautifulsoup4 tldextract

Usage:
    python -m phishscan.links samples/test1.eml
"""
import argparse
import re
from urllib.parse import urlparse

import tldextract
from bs4 import BeautifulSoup

from .parser import defang, get_bodies, load_eml

# Use the public-suffix list bundled with the package (no network lookups).
_extract = tldextract.TLDExtract(suffix_list_urls=())

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
    "goo.su", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "v.gd",
}

# Does this visible text look like a URL or a domain name?
# Email-marketing services that wrap every link in a click-tracking redirect.
# A "text says my-site.com, link goes to a tracker" mismatch from one of these is
# normal for newsletters, but only trusted when the sender passed DMARC.
TRACKING_DOMAINS = {
    "sendconstant.email", "constantcontact.com", "rs6.net", "list-manage.com",
    "mailchimp.com", "sendgrid.net", "mandrillapp.com", "mailgun.org",
    "klclick1.com", "klaviyomail.com", "hubspotlinks.com", "exct.net",
    "createsend.com", "sendibt3.com", "mjt.lu", "sparkpostmail.com",
}

LOOKS_LIKE_URL = re.compile(
    r"^(https?://|www\.)|^[\w-]+(\.[\w-]+)*\.[a-z]{2,}(/|$)", re.IGNORECASE
)


def registered_domain(url_or_text):
    """'https://login.paypal.com/x' -> 'paypal.com' (empty string if none)."""
    text = url_or_text.strip()
    if not re.match(r"^https?://", text, re.IGNORECASE):
        text = "http://" + text
    host = urlparse(text).hostname or ""
    parts = _extract(host)
    if not parts.domain or not parts.suffix:
        return ""
    return f"{parts.domain}.{parts.suffix}".lower()


def extract_links(msg):
    """Return one dict per <a href> in the HTML bodies: href, visible text, domains."""
    links = []
    for ctype, body in get_bodies(msg):
        if ctype != "text/html":
            continue
        soup = BeautifulSoup(body, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"].strip()
            if not href.lower().startswith(("http://", "https://")):
                continue  # skip mailto:, tel:, anchors, etc.
            text = tag.get_text(" ", strip=True)
            links.append(
                {
                    "href": href,
                    "text": text,
                    "href_domain": registered_domain(href),
                    "text_domain": registered_domain(text) if LOOKS_LIKE_URL.match(text) else "",
                }
            )
    return links


def check_links(links, trusted_sender=False):
    """Turn the raw links into a list of findings (check / severity / detail).

    trusted_sender=True means the email passed DMARC (it really came from the domain
    it claims), so click-tracking redirects are treated as normal newsletter behavior.
    """
    findings = []
    for link in links:
        # 1. Visible text claims one site, the link goes to another.
        if link["text_domain"] and link["text_domain"] != link["href_domain"]:
            if trusted_sender and link["href_domain"] in TRACKING_DOMAINS:
                findings.append(
                    {
                        "check": "tracked_link_redirect",
                        "severity": "low",
                        "detail": (
                            f"Link shows '{defang(link['text'])}' but goes through the "
                            f"email-service tracker {defang(link['href_domain'])} "
                            "(sender passed DMARC)"
                        ),
                    }
                )
                continue
            findings.append(
                {
                    "check": "link_text_mismatch",
                    "severity": "high",
                    "detail": (
                        f"Link shows '{defang(link['text'])}' but goes to "
                        f"{defang(link['href'])}"
                    ),
                }
            )
        # 2. Shortened links hide the real destination.
        if link["href_domain"] in SHORTENERS:
            findings.append(
                {
                    "check": "url_shortener",
                    "severity": "medium",
                    "detail": f"Shortened link hides its destination: {defang(link['href'])}",
                }
            )
    return findings


def main():
    parser = argparse.ArgumentParser(description="Check the links in a .eml file")
    parser.add_argument("eml_path", help="path to the .eml file")
    args = parser.parse_args()

    links = extract_links(load_eml(args.eml_path))
    print(f"== Links ({len(links)}) ==")
    for link in links:
        print(f"  text: {link['text']!r}")
        print(f"  href: {defang(link['href'])}")
    print("== Findings ==")
    findings = check_links(links)
    if not findings:
        print("  none")
    for f in findings:
        print(f"  [{f['severity'].upper()}] {f['check']}: {f['detail']}")


if __name__ == "__main__":
    main()
