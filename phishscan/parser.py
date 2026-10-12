"""Step 1: parse an .eml file and pull out the headers, URLs and attachments.

Usage:
    python -m phishscan.parser samples/test1.eml
"""
import argparse
import hashlib
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def load_eml(path):
    """Read an .eml file into an EmailMessage object (never executes anything)."""
    with open(path, "rb") as f:
        return BytesParser(policy=policy.default).parse(f)


def domain_of(address_header):
    """'Bob <bob@example.com>' -> 'example.com' (empty string if none)."""
    _, addr = parseaddr(str(address_header or ""))
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


def get_auth_results(msg):
    """Pull SPF / DKIM / DMARC verdicts from the Authentication-Results header."""
    raw = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    results = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{mechanism}=(\w+)", raw, re.IGNORECASE)
        results[mechanism] = match.group(1).lower() if match else "none"
    return results


def get_sender_info(msg):
    """Collect the sender-related headers we will compare against each other."""
    return {
        "subject": str(msg.get("Subject", "")),
        "from": str(msg.get("From", "")),
        "from_domain": domain_of(msg.get("From")),
        "reply_to_domain": domain_of(msg.get("Reply-To")),
        "return_path_domain": domain_of(msg.get("Return-Path")),
    }


def get_received_chain(msg):
    """The mail hops, as written (newest first). Whitespace is cleaned up."""
    return [" ".join(str(h).split()) for h in msg.get_all("Received", [])]


def get_bodies(msg):
    """Return a list of (content_type, text) for the text/plain and text/html parts."""
    bodies = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html"):
            try:
                bodies.append((ctype, part.get_content()))
            except (LookupError, UnicodeDecodeError):
                continue  # skip parts with broken encodings
    return bodies


def extract_urls(msg):
    """Every http(s) URL found in the message bodies, de-duplicated."""
    urls = set()
    for _, body in get_bodies(msg):
        urls.update(URL_RE.findall(body))
    return sorted(urls)


def defang(url):
    """Make a URL unclickable for reports: https://evil.com -> hxxps://evil[.]com"""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def list_attachments(msg):
    """Filename, type, size and SHA-256 of each attachment. We only hash them."""
    attachments = []
    for part in msg.iter_attachments():
        data = part.get_payload(decode=True) or b""
        attachments.append(
            {
                "filename": part.get_filename() or "(no name)",
                "content_type": part.get_content_type(),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return attachments


def analyze(path):
    """Run every extractor and return one dictionary (this becomes the report later)."""
    msg = load_eml(path)
    return {
        "sender": get_sender_info(msg),
        "auth": get_auth_results(msg),
        "received_chain": get_received_chain(msg),
        "urls": extract_urls(msg),
        "attachments": list_attachments(msg),
    }


def main():
    parser = argparse.ArgumentParser(description="Parse a suspicious .eml file")
    parser.add_argument("eml_path", help="path to the .eml file")
    args = parser.parse_args()

    result = analyze(args.eml_path)

    print("== Sender ==")
    for key, value in result["sender"].items():
        print(f"  {key}: {value}")
    print("== Authentication ==")
    for key, value in result["auth"].items():
        print(f"  {key}: {value}")
    print(f"== Received chain ({len(result['received_chain'])} hops) ==")
    for hop in result["received_chain"]:
        print(f"  {hop}")
    print(f"== URLs ({len(result['urls'])}) ==")
    for url in result["urls"]:
        print(f"  {defang(url)}")
    print(f"== Attachments ({len(result['attachments'])}) ==")
    for att in result["attachments"]:
        print(f"  {att['filename']} ({att['content_type']}, {att['size']} bytes)")
        print(f"    sha256: {att['sha256']}")


if __name__ == "__main__":
    main()
