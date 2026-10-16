"""Triage helper: summarize the emails phishscan scored LOW RISK so you can study the misses.

Usage:
    python -m phishscan.triage samples/phishing --limit 15
    python -m phishscan.triage samples/phishing --limit 15 --skip 15    (the next batch)
    python -m phishscan.triage samples/phishing --all                   (include flagged ones too)

Prints a short, safe summary per email: sender, subject, auth results, link domains,
attachment names and the first part of the body text. Nothing is opened or executed.
"""
import argparse
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from .__main__ import run_all
from .parser import (
    defang,
    extract_urls,
    get_auth_results,
    get_bodies,
    get_sender_info,
    list_attachments,
    load_eml,
)


def body_snippet(msg, width=170):
    """First bit of readable body text (plain text preferred, HTML stripped if needed)."""
    bodies = get_bodies(msg)
    text = next((body for ctype, body in bodies if ctype == "text/plain"), "")
    if not text.strip():
        for ctype, body in bodies:
            if ctype == "text/html":
                soup = BeautifulSoup(body, "html.parser")
                for tag in soup(["script", "style"]):
                    tag.decompose()
                text = soup.get_text(" ")
                break
    text = re.sub(r"https?://\S+", "<url>", text)
    return " ".join(text.split())[:width] or "(no readable body text)"


def summarize(path, score):
    msg = load_eml(path)
    sender = get_sender_info(msg)
    auth = get_auth_results(msg)
    hosts = Counter(urlparse(u).hostname or "?" for u in extract_urls(msg))
    attachments = [a["filename"] for a in list_attachments(msg)]
    top_hosts = ", ".join(f"{defang(h)}({n})" for h, n in hosts.most_common(3)) or "none"
    reply_to = defang(sender["reply_to_domain"]) if sender["reply_to_domain"] else "-"
    return "\n".join(
        [
            f"{Path(path).name}  (score {score})",
            f"  Subject:  {sender['subject'][:90]}",
            f"  From:     {defang(sender['from'])}   | Reply-To domain: {reply_to}",
            f"  Auth:     spf={auth['spf']} dkim={auth['dkim']} dmarc={auth['dmarc']}",
            f"  URLs:     {sum(hosts.values())} | top hosts: {top_hosts}",
            f"  Attached: {', '.join(attachments) if attachments else 'none'}",
            f"  Body:     {body_snippet(msg)}",
        ]
    )


def main():
    parser = argparse.ArgumentParser(description="Summarize missed emails for review")
    parser.add_argument("folder", help="folder of .eml files")
    parser.add_argument("--limit", type=int, default=15, help="how many emails to show")
    parser.add_argument("--skip", type=int, default=0, help="skip this many matches first")
    parser.add_argument("--all", action="store_true", help="show flagged emails too, not just LOW RISK")
    args = parser.parse_args()

    # Emojis and odd characters in subjects must not crash the Windows terminal.
    sys.stdout.reconfigure(errors="replace")

    shown = skipped = 0
    for path in sorted(Path(args.folder).glob("*.eml")):
        try:
            result = run_all(str(path))
        except Exception as error:  # keep going if one file is broken
            print(f"{path.name}: ERROR {type(error).__name__}: {error}\n")
            continue
        if not args.all and result["verdict"] != "LOW RISK":
            continue
        if skipped < args.skip:
            skipped += 1
            continue
        print(summarize(path, result["score"]))
        print()
        shown += 1
        if shown >= args.limit:
            break
    print(f"Showed {shown} email(s).")


if __name__ == "__main__":
    main()
