"""Step 4b: turn a list of findings into a single risk score and verdict."""

WEIGHTS = {"high": 30, "medium": 15, "low": 5}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Tune these as you test against real samples.
LIKELY_PHISHING_AT = 60
SUSPICIOUS_AT = 30


def dedupe(findings):
    """Drop exact duplicates and sort the most severe findings first."""
    seen = set()
    unique = []
    for f in findings:
        key = (f["check"], f["detail"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return sorted(unique, key=lambda f: SEVERITY_ORDER[f["severity"]])


def score(findings):
    """Add up severity weights (capped at 100) and pick a verdict."""
    total = min(100, sum(WEIGHTS[f["severity"]] for f in findings))
    if total >= LIKELY_PHISHING_AT:
        verdict = "LIKELY PHISHING"
    elif total >= SUSPICIOUS_AT:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"
    return {"score": total, "verdict": verdict}
