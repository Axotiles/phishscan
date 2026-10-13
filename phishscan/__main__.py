"""Step 4c: one command that runs every check.

Usage:
    python -m phishscan samples/test1.eml
    python -m phishscan samples/test1.eml --json
    python -m phishscan samples/test1.eml --vt      (adds VirusTotal lookups)
"""
import argparse
import json
from collections import Counter
from urllib.parse import urlparse

from .checks import check_attachments, check_authentication, check_sender, check_urgency
from .links import check_links, extract_links
from .lookalikes import check_lookalikes
from .parser import analyze, defang, get_auth_results, load_eml
from .scoring import dedupe, score


def run_all(path, use_vt=False):
    """Parse the email, run every check, and return one result dictionary."""
    msg = load_eml(path)

    findings = []
    findings += check_authentication(msg)
    findings += check_sender(msg)
    findings += check_urgency(msg)
    findings += check_attachments(msg)
    trusted = get_auth_results(msg)["dmarc"] == "pass"  # sender is who they claim to be
    findings += check_links(extract_links(msg), trusted_sender=trusted)
    findings += check_lookalikes(msg)
    if use_vt:
        from .lookups import check_virustotal  # imported here so --vt stays optional

        findings += check_virustotal(msg)
    findings = dedupe(findings)

    result = analyze(path)  # sender info, auth, received chain, urls, attachments
    hosts = Counter(urlparse(u).hostname or "" for u in result["urls"])
    result["url_hosts"] = [{"host": defang(h), "count": n} for h, n in hosts.most_common()]
    result["urls"] = [defang(u) for u in result["urls"]]  # never leave clickable URLs in a report
    result["findings"] = findings
    result.update(score(findings))
    return result


def print_report(path, result):
    print(f"=== phishscan report: {path} ===")
    print(f"Verdict: {result['verdict']}  (score {result['score']}/100)")
    print(f"From:    {result['sender']['from']}")
    print(f"Subject: {result['sender']['subject']}")
    print()
    print(f"Findings ({len(result['findings'])}):")
    if not result["findings"]:
        print("  none")
    for f in result["findings"]:
        print(f"  [{f['severity'].upper():6}] {f['check']}: {f['detail']}")
    print()
    print(f"URLs: {len(result['urls'])} across {len(result['url_hosts'])} domains (full list with --json)")
    for item in result["url_hosts"][:10]:
        print(f"  {item['host']} ({item['count']})")
    print(f"Attachments ({len(result['attachments'])}):")
    for att in result["attachments"]:
        print(f"  {att['filename']}  sha256={att['sha256']}")


def main():
    parser = argparse.ArgumentParser(prog="phishscan", description="Analyze a suspicious .eml file")
    parser.add_argument("eml_path", help="path to the .eml file")
    parser.add_argument("--json", action="store_true", help="print the full result as JSON")
    parser.add_argument("--vt", action="store_true", help="also look up hashes/URLs on VirusTotal")
    args = parser.parse_args()

    result = run_all(args.eml_path, use_vt=args.vt)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(args.eml_path, result)


if __name__ == "__main__":
    main()
