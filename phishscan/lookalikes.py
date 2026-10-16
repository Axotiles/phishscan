"""Step 3: detect lookalike domains that imitate well-known brands.

Catches things like:
    paypa1.com                  (1 instead of l)
    arnazon.com                 (rn looks like m)
    paypal-secure-login.net     (brand name inside someone else's domain)
    paypal.com.account-verify.net  (brand used as a subdomain of a different site)
    xn--...                     (punycode, often used for lookalike characters)

Needs:  pip install tldextract rapidfuzz

Usage:
    python -m phishscan.lookalikes samples/test1.eml
"""
import argparse
from urllib.parse import urlparse

import tldextract
from rapidfuzz import fuzz

from .parser import defang, extract_urls, get_sender_info, load_eml

_extract = tldextract.TLDExtract(suffix_list_urls=())

# Brand name -> the real domains that brand legitimately uses.
# Add the brands YOU care about (your bank, your school, your employer...).
BRANDS = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "microsoftstore.com",
                  "live.com", "office.com", "outlook.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazonaws.com",
               "amazonses.com", "amazon-adsystem.com", "media-amazon.com",
               "images-amazon.com", "ssl-images-amazon.com"},
    "apple": {"apple.com", "icloud.com", "apple.news"},
    "google": {"google.com", "gmail.com", "googlemail.com", "googleapis.com",
               "google-analytics.com", "googleusercontent.com", "googletagmanager.com",
               "googlesyndication.com", "googleadservices.com", "googlevideo.com"},
    "netflix": {"netflix.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dropbox": {"dropbox.com", "dropboxmail.com", "dropboxusercontent.com"},
    "linkedin": {"linkedin.com"},
    "facebook": {"facebook.com", "facebookmail.com", "fb.com"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "fedex": {"fedex.com"},
    # Added after testing on real phishing samples (common impersonation targets):
    "mcafee": {"mcafee.com"},
    "norton": {"norton.com", "nortonlifelock.com"},
    "totalav": {"totalav.com"},
    "trustwallet": {"trustwallet.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "binance": {"binance.com"},
    "mercadopago": {"mercadopago.com", "mercadopago.com.br", "mercadopago.com.ar",
                    "mercadolibre.com", "mercadolivre.com.br"},
    "caixa": {"caixa.gov.br"},
    "chase": {"chase.com", "jpmorganchase.com", "jpmorgan.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
    "dhl": {"dhl.com", "dhl.de"},
}
LEGIT_DOMAINS = set().union(*BRANDS.values())

# Characters attackers swap in to imitate letters.
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a"})
FUZZY_THRESHOLD = 85  # 0-100; higher = stricter, fewer false positives


def normalize(label):
    """Undo common character swaps so 'paypa1' -> 'paypal', 'arnazon' -> 'amazon'."""
    return label.lower().replace("rn", "m").replace("vv", "w").translate(LEET)


def _imitates(text, brand):
    """True if the text uses the brand name as a whole word, or (for names of 5+ letters) at the start.

    Very short brands (ups, dhl, usps) only match as a whole word, otherwise 'upstream.com'
    would look like an impersonation of UPS.
    """
    return brand in text.split("-") or (len(brand) >= 5 and text.startswith(brand))


def brand_match(label, brand):
    """Return (check_name, reason) if this one DNS label imitates the brand, else None."""
    raw = label.lower()
    norm = normalize(raw)

    if _imitates(raw, brand):
        return "brand_in_domain", f"uses the brand name '{brand}'"
    if _imitates(norm, brand):
        return "lookalike_domain", f"imitates '{brand}' with swapped characters"
    for token in raw.split("-"):
        if len(token) >= 5 and fuzz.ratio(token, brand) >= FUZZY_THRESHOLD:
            return "lookalike_domain", f"is a near-miss of '{brand}' (possible typo-squat)"
    return None


def check_host(host, where):
    """Check one hostname (e.g. 'login.paypa1-secure.com'). Returns a list of findings."""
    parts = _extract(host)
    if not parts.domain or not parts.suffix:
        return []
    registered = f"{parts.domain}.{parts.suffix}".lower()
    if registered in LEGIT_DOMAINS:
        return []  # genuinely the brand's own domain

    findings = []
    labels = [part for part in parts.subdomain.split(".") if part] + [parts.domain]

    if any(label.lower().startswith("xn--") for label in labels):
        findings.append(
            {
                "check": "punycode_domain",
                "severity": "medium",
                "detail": f"{where}: {defang(host)} uses punycode (may hide lookalike characters)",
            }
        )

    seen_brands = set()
    for brand in BRANDS:
        for label in labels:
            match = brand_match(label, brand)
            if match and brand not in seen_brands:
                seen_brands.add(brand)
                check, reason = match
                findings.append(
                    {
                        "check": check,
                        "severity": "high",
                        "detail": f"{where}: {defang(host)} {reason}, but the real domain is {defang(registered)}",
                    }
                )
    return findings


def collect_hosts(msg):
    """Gather every hostname worth checking: From / Reply-To domains plus all URL hosts.

    The Return-Path (bounce) address is skipped on purpose: readers never see it, and
    legitimate bulk mailers use names like 'amazonses.com' there. Mismatches are already
    reported (at low weight) by check_sender() in checks.py.
    """
    hosts = {}  # host -> where we found it (first sighting wins)
    sender = get_sender_info(msg)
    for key, label in (
        ("from_domain", "From address"),
        ("reply_to_domain", "Reply-To address"),
    ):
        if sender[key]:
            hosts.setdefault(sender[key], label)
    for url in extract_urls(msg):
        host = urlparse(url).hostname
        if host:
            hosts.setdefault(host.lower(), "link")
    return hosts


def check_lookalikes(msg):
    findings = []
    for host, where in collect_hosts(msg).items():
        findings.extend(check_host(host, where))
    return findings


def main():
    parser = argparse.ArgumentParser(description="Find lookalike domains in a .eml file")
    parser.add_argument("eml_path", help="path to the .eml file")
    args = parser.parse_args()

    msg = load_eml(args.eml_path)
    hosts = collect_hosts(msg)
    print(f"== Hosts checked ({len(hosts)}) ==")
    for host, where in hosts.items():
        print(f"  {defang(host)}  [{where}]")
    print("== Findings ==")
    findings = check_lookalikes(msg)
    if not findings:
        print("  none")
    for f in findings:
        print(f"  [{f['severity'].upper()}] {f['check']}: {f['detail']}")


if __name__ == "__main__":
    main()
