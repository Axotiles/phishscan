"""Step 4a: header, sender, wording and attachment checks.

Every check returns a list of findings shaped like:
    {"check": "spf_fail", "severity": "high", "detail": "..."}
The link and lookalike checks (links.py, lookalikes.py) use the same shape,
so scoring.py can add them all up.
"""
import re
from email.utils import parseaddr

from .links import registered_domain
from .lookalikes import BRANDS
from .parser import get_auth_results, get_bodies, get_sender_info, list_attachments

URGENT_PHRASES = [
    "urgent", "immediately", "within 24 hours", "verify your account",
    "confirm your", "account has been", "suspended", "unusual activity",
    "action required", "has been limited",
]

EXECUTABLE_EXTS = {
    "exe", "scr", "js", "vbs", "bat", "cmd", "ps1", "jar", "lnk", "hta", "msi", "com",
}
DOCUMENT_EXTS = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt"}
MACRO_EXTS = {"docm", "xlsm", "pptm"}
ARCHIVE_EXTS = {"zip", "rar", "7z", "iso", "img"}


def finding(check, severity, detail):
    return {"check": check, "severity": severity, "detail": detail}


def check_authentication(msg):
    """SPF / DKIM / DMARC results recorded by the receiving mail server."""
    auth = get_auth_results(msg)
    found = []
    if auth["spf"] == "fail":
        found.append(finding("spf_fail", "high", "SPF failed: sending server is not authorized for this domain"))
    elif auth["spf"] == "softfail":
        found.append(finding("spf_softfail", "medium", "SPF soft-failed: sending server is probably not authorized"))
    if auth["dkim"] == "fail":
        found.append(finding("dkim_fail", "high", "DKIM signature failed verification"))
    if auth["dmarc"] == "fail":
        found.append(finding("dmarc_fail", "high", "DMARC failed: the message does not align with the sender domain's policy"))
    if set(auth.values()) == {"none"}:
        found.append(finding("no_auth_results", "low", "No SPF/DKIM/DMARC results found (headers may be missing or stripped)"))
    return found


def check_sender(msg):
    """Compare the From, Reply-To and Return-Path domains, and the display name."""
    sender = get_sender_info(msg)
    from_reg = registered_domain(sender["from_domain"]) if sender["from_domain"] else ""
    found = []

    reply_reg = registered_domain(sender["reply_to_domain"]) if sender["reply_to_domain"] else ""
    if reply_reg and from_reg and reply_reg != from_reg:
        found.append(finding(
            "reply_to_mismatch", "medium",
            f"Replies go to {reply_reg}, not the sender's domain {from_reg}"))

    path_reg = registered_domain(sender["return_path_domain"]) if sender["return_path_domain"] else ""
    if path_reg and from_reg and path_reg != from_reg:
        found.append(finding(
            "return_path_mismatch", "low",
            f"Bounce address domain {path_reg} differs from From domain {from_reg} "
            "(common for bulk mailers, so low weight)"))

    # Display name claims a brand, but the address is on a different domain.
    display_name, _ = parseaddr(sender["from"])
    words = re.findall(r"[a-z0-9]+", display_name.lower())
    for brand, legit_domains in BRANDS.items():
        if any(word.startswith(brand) for word in words) and from_reg not in legit_domains:
            found.append(finding(
                "display_name_spoof", "high",
                f"Display name says '{display_name}' but the address is on {from_reg or 'an unknown domain'}"))
            break
    return found


def check_urgency(msg):
    """Pressure language in the subject and body."""
    text = str(msg.get("Subject", "")).lower()
    for _, body in get_bodies(msg):
        text += " " + body.lower()
    hits = [phrase for phrase in URGENT_PHRASES if phrase in text]
    if not hits:
        return []
    shown = ", ".join(f"'{h}'" for h in hits[:4])
    return [finding("urgent_language", "low", f"Pressure wording found: {shown}")]


def check_attachments(msg):
    """Risky file types, double extensions and macro documents (names only, nothing is opened)."""
    found = []
    for att in list_attachments(msg):
        name = att["filename"]
        parts = name.lower().split(".")
        ext = parts[-1] if len(parts) > 1 else ""
        prev = parts[-2] if len(parts) > 2 else ""
        if ext in EXECUTABLE_EXTS and prev in DOCUMENT_EXTS:
            found.append(finding(
                "double_extension", "high",
                f"'{name}' pretends to be a .{prev} file but is really .{ext}"))
        elif ext in EXECUTABLE_EXTS:
            found.append(finding("executable_attachment", "high", f"'{name}' is an executable/script file type (.{ext})"))
        elif ext in MACRO_EXTS:
            found.append(finding("macro_attachment", "medium", f"'{name}' is a macro-enabled Office file"))
        elif ext in ARCHIVE_EXTS:
            found.append(finding("archive_attachment", "low", f"'{name}' is an archive/disk image (can hide malware)"))
    return found
