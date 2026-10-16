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
from .parser import defang, get_auth_results, get_bodies, get_sender_info, list_attachments

URGENT_PHRASES = [
    "urgent", "immediately", "within 24 hours", "verify your account",
    "confirm your", "account has been", "suspended", "unusual activity",
    "action required", "has been limited",
    "verify your wallet", "kyc", "seed phrase", "recovery phrase", "storage is full",
    "storage full", "password has expired", "payment method needs", "blocked your account",
    "subscription has expired", "will be deleted",
]

# Distinctive advance-fee / lottery scam wording. Two or more of these is a strong signal.
SCAM_PHRASES = [
    "i got your contact", "this will be a surprise", "my late husband", "next of kin",
    "unclaimed funds", "transfer the funds", "business proposal", "beneficiary of",
    "million united states dollars", "million usd", "you have won", "claim your prize",
    "god bless you", "inheritance fund", "lottery winner", "international lottery",
]

# phishing_pot replaces the honeypot's own address with phishing@pot. That is an
# artifact of how the samples were collected, not a signal, so it is ignored.
ARTIFACT_DOMAIN = "pot"

VALID_DOMAIN = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)

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


def mentions_brand(text, brand):
    """Does this text (a display name or subject) name the brand?

    Whole-word match always counts. Longer names also match as a word prefix (6+ letters)
    or run together like 'Trust Wallet' -> 'trustwallet' (7+ letters). Short names such as
    'ups' only match as a whole word, so 'upstream' or 'cups' don't count.
    """
    words = re.findall(r"[a-z0-9]+", text.lower())
    if brand in words:
        return True
    if len(brand) >= 6 and any(word.startswith(brand) for word in words):
        return True
    return len(brand) >= 7 and brand in "".join(words)


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
    display_name, address = parseaddr(sender["from"])
    name_text = display_name or (sender["from"] if "@" not in address else "")
    spoofed = False
    for brand, legit_domains in BRANDS.items():
        if mentions_brand(name_text, brand) and from_reg not in legit_domains:
            found.append(finding(
                "display_name_spoof", "high",
                f"Display name says '{name_text}' but the address is on {from_reg or 'an unknown domain'}"))
            spoofed = True
            break

    # Subject names a brand that the sender is not.
    if not spoofed:
        for brand, legit_domains in BRANDS.items():
            if mentions_brand(sender["subject"], brand) and from_reg not in legit_domains:
                found.append(finding(
                    "brand_in_subject_mismatch", "medium",
                    f"Subject mentions '{brand}' but the sender is {from_reg or 'an unknown domain'}"))
                break
    return found


def looks_random(label):
    """Does this domain label look machine-generated (long, digit-heavy or vowel-starved)?"""
    label = label.lower().replace("-", "")
    letters = sum(c.isalpha() for c in label)
    digits = sum(c.isdigit() for c in label)
    vowels = sum(c in "aeiou" for c in label)
    if len(label) >= 20 and digits >= 2 and letters >= 2:
        return True
    return len(label) >= 16 and letters > 0 and vowels / letters < 0.2


def check_sender_address(msg):
    """Is the From address real and plausible? Real senders have valid domains."""
    _, address = parseaddr(str(msg.get("From", "")).strip())
    if address.lower().endswith("@" + ARTIFACT_DOMAIN):
        return []
    if "@" not in address:
        return [finding("no_sender_address", "medium", "The From header has no email address")]

    domain = address.rsplit("@", 1)[1].lower()
    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_domain = ""
    if not VALID_DOMAIN.match(ascii_domain):
        return [finding("invalid_sender_domain", "high",
                        f"Sender domain '{defang(domain)}' is not a valid domain name")]

    if any(looks_random(label) for label in domain.split(".")[:-1]):
        return [finding("random_sender_domain", "high",
                        f"Sender domain '{defang(domain)}' looks randomly generated")]
    return []


def check_scam_language(msg):
    """Advance-fee / lottery scam wording (the Nigerian-prince style of email)."""
    text = " ".join(body.lower() for _, body in get_bodies(msg))
    hits = [phrase for phrase in SCAM_PHRASES if phrase in text]
    if not hits:
        return []
    severity = "high" if len(hits) >= 2 else "medium"
    shown = ", ".join(f"'{h}'" for h in hits[:3])
    return [finding("scam_language", severity, f"Advance-fee / prize scam wording: {shown}")]


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
