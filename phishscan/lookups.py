"""Step 6: optional VirusTotal reputation lookups (attachment hashes and URLs).

Setup:
    1. Make a free account at virustotal.com and copy your API key.
    2. In the project folder, create a file named .env containing one line:
           VT_API_KEY=paste-your-key-here
       (.env is already in your .gitignore. Never commit it.)
    3. pip install requests python-dotenv

Usage:
    python -m phishscan samples/test1.eml --vt

Notes:
  * Lookups only. We never upload files or submit URLs, we just ask VirusTotal
    whether it has already seen this hash / URL.
  * The free tier allows 4 requests per minute, so calls are spaced out and
    results are cached in .vt_cache.json.
  * URLs in real emails can contain personal tracking tokens. Don't use --vt
    on private emails you wouldn't want to share URLs from.
"""
import base64
import json
import os
import sys
import time
from pathlib import Path

import requests

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv is optional; a real environment variable also works
    pass

from .parser import defang, extract_urls, list_attachments

API = "https://www.virustotal.com/api/v3"
CACHE_PATH = Path(".vt_cache.json")
MIN_SECONDS_BETWEEN_CALLS = 15  # free tier = 4 requests/minute
MAX_URLS = 5  # keep within the free daily quota

_last_call = 0.0


def _load_cache():
    try:
        return json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(cache):
    try:
        CACHE_PATH.write_text(json.dumps(cache), encoding="utf-8")
    except OSError:
        pass  # caching is a convenience, never fatal


def _vt_get(endpoint, api_key):
    """One rate-limited GET request to the VirusTotal API."""
    global _last_call
    wait = MIN_SECONDS_BETWEEN_CALLS - (time.time() - _last_call)
    if wait > 0:
        time.sleep(wait)
    _last_call = time.time()
    return requests.get(f"{API}/{endpoint}", headers={"x-apikey": api_key}, timeout=20)


def lookup(endpoint, api_key, cache):
    """Return VirusTotal's detection stats for an endpoint, or None if it has never seen it."""
    if endpoint in cache:
        return cache[endpoint]
    response = _vt_get(endpoint, api_key)
    if response.status_code == 404:
        return None  # unknown to VirusTotal (not cached, it may be known later)
    if response.status_code == 429:
        raise RuntimeError("VirusTotal rate limit reached; wait a minute and try again")
    if response.status_code != 200:
        raise RuntimeError(f"VirusTotal returned HTTP {response.status_code}")
    stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    cache[endpoint] = stats
    return stats


def url_id(url):
    """VirusTotal identifies a URL by its URL-safe base64 form, without '=' padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def severity_for(stats):
    """Map detection counts to a finding severity (or None if the item looks clean)."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious >= 3:
        return "high"
    if malicious >= 1 or suspicious >= 3:
        return "medium"
    return None


def check_virustotal(msg):
    """Look up each attachment hash and up to MAX_URLS URLs. Returns findings."""
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("VirusTotal skipped: set VT_API_KEY in your .env file", file=sys.stderr)
        return []

    cache = _load_cache()
    findings = []
    try:
        for att in list_attachments(msg):
            if att["size"] == 0:
                continue
            stats = lookup(f"files/{att['sha256']}", api_key, cache)
            level = severity_for(stats) if stats else None
            if level:
                findings.append(
                    {
                        "check": "vt_malicious_attachment",
                        "severity": level,
                        "detail": (
                            f"VirusTotal: {stats.get('malicious', 0)} engines flag "
                            f"attachment '{att['filename']}' as malicious"
                        ),
                    }
                )
        for url in extract_urls(msg)[:MAX_URLS]:
            stats = lookup(f"urls/{url_id(url)}", api_key, cache)
            level = severity_for(stats) if stats else None
            if level:
                findings.append(
                    {
                        "check": "vt_malicious_url",
                        "severity": level,
                        "detail": (
                            f"VirusTotal: {stats.get('malicious', 0)} engines flag "
                            f"{defang(url)} as malicious"
                        ),
                    }
                )
    except (RuntimeError, requests.RequestException) as error:
        print(f"VirusTotal lookup stopped: {error}", file=sys.stderr)
    finally:
        _save_cache(cache)
    return findings
