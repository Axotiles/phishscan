"""Step 7: automated tests. Run from the project folder with:  python -m pytest -v

The VirusTotal tests use a fake response, so they never touch the network.
"""
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

from phishscan import lookups
from phishscan.__main__ import run_all
from phishscan.checks import (
    check_attachments,
    check_authentication,
    check_scam_language,
    check_sender,
    check_sender_address,
    mentions_brand,
)
from phishscan.links import check_links, extract_links
from phishscan.lookalikes import check_host, check_lookalikes, collect_hosts
from phishscan.parser import defang, get_auth_results, get_sender_info, list_attachments, load_eml
from phishscan.scoring import dedupe, score
from phishscan.urlchecks import check_hosts

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
TEST1 = SAMPLES / "test1.eml"
TEST2 = SAMPLES / "test2.eml"
TEST3 = SAMPLES / "test3_legit_newsletter.eml"


def checks_of(findings):
    return {f["check"] for f in findings}


# ---------- parser ----------

def test_sender_domains_are_extracted():
    sender = get_sender_info(load_eml(TEST1))
    assert sender["from_domain"] == "paypa1-secure.example.com"
    assert sender["reply_to_domain"] == "free-mail-inbox.example.org"


def test_auth_results_are_extracted():
    auth = get_auth_results(load_eml(TEST1))
    assert auth == {"spf": "fail", "dkim": "none", "dmarc": "fail"}


def test_attachment_is_hashed_not_opened():
    attachments = list_attachments(load_eml(TEST1))
    assert attachments[0]["filename"] == "invoice.pdf.exe"
    assert len(attachments[0]["sha256"]) == 64


def test_defang_makes_urls_unclickable():
    assert defang("https://evil.com/x") == "hxxps://evil[.]com/x"


# ---------- links ----------

def test_link_text_mismatch_is_flagged():
    findings = check_links(extract_links(load_eml(TEST1)))
    assert "link_text_mismatch" in checks_of(findings)


# ---------- lookalikes ----------

def test_character_swap_is_flagged():
    assert "lookalike_domain" in checks_of(check_host("paypa1.com", "link"))


def test_rn_for_m_is_flagged():
    assert "lookalike_domain" in checks_of(check_host("arnazon.com", "link"))


def test_brand_as_subdomain_of_other_site_is_flagged():
    assert "brand_in_domain" in checks_of(check_host("paypal.com.account-verify.net", "link"))


def test_real_brand_domain_is_not_flagged():
    assert check_host("www.amazon.com", "link") == []
    assert check_host("email.paypal.com", "link") == []


def test_unrelated_domain_is_not_flagged():
    assert check_host("github.com", "link") == []


def test_lookalikes_found_in_second_sample():
    assert len(check_lookalikes(load_eml(TEST2))) >= 3


# ---------- header / sender / attachment checks ----------

def test_spf_and_dmarc_failures_are_high_severity():
    findings = check_authentication(load_eml(TEST1))
    assert {"spf_fail", "dmarc_fail"} <= checks_of(findings)
    assert all(f["severity"] == "high" for f in findings)


def test_display_name_spoof_is_flagged():
    assert "display_name_spoof" in checks_of(check_sender(load_eml(TEST1)))


def test_double_extension_attachment_is_flagged():
    assert "double_extension" in checks_of(check_attachments(load_eml(TEST1)))


# ---------- scoring ----------

def finding(severity, name="x"):
    return {"check": name, "severity": severity, "detail": name}


def test_no_findings_is_low_risk():
    assert score([])["verdict"] == "LOW RISK"


def test_one_high_finding_is_suspicious():
    assert score([finding("high")])["verdict"] == "SUSPICIOUS"


def test_two_high_findings_is_likely_phishing():
    assert score([finding("high", "a"), finding("high", "b")])["verdict"] == "LIKELY PHISHING"


def test_score_is_capped_at_100():
    assert score([finding("high", str(i)) for i in range(10)])["score"] == 100


def test_dedupe_removes_duplicates_and_sorts_by_severity():
    result = dedupe([finding("low", "a"), finding("high", "b"), finding("high", "b")])
    assert [f["severity"] for f in result] == ["high", "low"]


# ---------- false-positive regressions (found by testing on real legit email) ----------

def test_google_analytics_domain_is_not_flagged():
    assert check_host("www.google-analytics.com", "link") == []


def test_amazon_ses_and_cdn_domains_are_not_flagged():
    assert check_host("amazonses.com", "link") == []
    assert check_host("cdninstagram.com", "link") == []


def test_return_path_is_not_checked_for_lookalikes():
    assert "mailer-xk29.example.net" not in collect_hosts(load_eml(TEST1))


def tracked_link(href_domain):
    return [{"href": f"https://www.{href_domain}/l/x", "text": "www.shop.com",
             "href_domain": href_domain, "text_domain": "shop.com"}]


def test_tracking_redirect_is_low_when_sender_passes_dmarc():
    findings = check_links(tracked_link("sendconstant.email"), trusted_sender=True)
    assert [f["severity"] for f in findings] == ["low"]


def test_tracking_redirect_is_still_high_without_dmarc_pass():
    findings = check_links(tracked_link("sendconstant.email"), trusted_sender=False)
    assert [f["severity"] for f in findings] == ["high"]


def test_unknown_redirect_domain_is_high_even_with_dmarc_pass():
    findings = check_links(tracked_link("totally-new-site.net"), trusted_sender=True)
    assert [f["severity"] for f in findings] == ["high"]


def test_legit_newsletter_sample_is_low_risk():
    assert run_all(str(TEST3))["verdict"] == "LOW RISK"


# ---------- rules added after studying real phishing samples ----------

def make_msg(from_header="", subject="", body="hello"):
    msg = EmailMessage()
    if from_header:
        msg["From"] = from_header
    msg["Subject"] = subject
    msg.set_content(body)
    return msg


def test_domain_without_a_tld_is_invalid():
    msg = make_msg("Comunicado <correntistas@caixacefcomunicados095696>")
    assert "invalid_sender_domain" in checks_of(check_sender_address(msg))


def test_randomly_generated_sender_domain_is_flagged():
    msg = make_msg("UPS <CV5PDFZ9@jycml6pceot2bjoduxrbwcyi5eee.com>")
    assert "random_sender_domain" in checks_of(check_sender_address(msg))


def test_normal_sender_domains_are_not_flagged():
    for sender in ("news@maplehillwinery.com", "a@my-company.co.uk", "info@m\u00fcnchen.de",
                   "orders@jonesfamilyfarms.com"):
        assert check_sender_address(make_msg(sender)) == [], sender


def test_missing_sender_address_is_flagged():
    assert "no_sender_address" in checks_of(check_sender_address(make_msg("Total AV")))
    assert "no_sender_address" in checks_of(check_sender_address(make_msg("")))


def test_honeypot_placeholder_address_is_ignored():
    assert check_sender_address(make_msg("phishing@pot")) == []


def test_brand_in_display_name_with_wrong_domain_is_flagged():
    for header in ('"Trust Wallet" <notifications@sg.graphy.com>',
                   '"UPS." <abc@somewhere-else.com>',
                   '"Total AV" <abc@somewhere-else.com>',
                   'Mercado Pago <aviso@atendimento.com>'):
        assert "display_name_spoof" in checks_of(check_sender(make_msg(header))), header


def test_similar_looking_words_are_not_brand_matches():
    assert not mentions_brand("Pineapple Supplies", "apple")
    assert not mentions_brand("Upstream Cups Ltd", "ups")
    assert mentions_brand("Trust Wallet", "trustwallet")
    assert mentions_brand("UPS.", "ups")


def test_brand_in_subject_from_other_domain_is_flagged_but_not_from_the_brand():
    subject = "Urgent: Your McAfee protection is at risk"
    assert "brand_in_subject_mismatch" in checks_of(check_sender(make_msg("Billing <a@evil-sender.com>", subject)))
    assert "brand_in_subject_mismatch" not in checks_of(check_sender(make_msg("McAfee <a@mcafee.com>", subject)))


def test_advance_fee_scam_wording_is_high_with_two_phrases():
    body = "Good-Day! This will be a surprise to you. I got your contact through a directory."
    findings = check_scam_language(make_msg("Mrs W <w@gmail.com>", "hello", body))
    assert [f["severity"] for f in findings] == ["high"]
    assert check_scam_language(make_msg("a@b.com", "hi", "Lunch tomorrow?")) == []


def test_throwaway_tld_free_hosting_and_ip_hosts_are_flagged():
    assert "risky_tld_link" in checks_of(check_hosts({"hqkm49mwe2n.dirttax.store"}))
    assert "free_hosting_link" in checks_of(check_hosts({"cx-4899.southamerica-east1.run.app"}))
    assert "ip_in_hostname" in checks_of(check_hosts({"251.242.109.208.host.secureserver.net"}))


def test_ordinary_hosts_are_not_flagged_by_url_checks():
    assert check_hosts({"www.quora.com", "fonts.googleapis.com", "ultrasabers.com",
                        "d3k81ch9hvuctc.cloudfront.net", "1123669900.sdkmedia.net"}) == []


def test_trust_wallet_lookalike_domain_and_short_brand_safety():
    assert "brand_in_domain" in checks_of(check_host("support-trustwallet.com", "link"))
    assert check_host("upstream.com", "link") == []
    assert check_host("ups.com", "link") == []
    assert "brand_in_domain" in checks_of(check_host("ups-delivery-notice.com", "link"))


# ---------- end to end ----------

def test_both_samples_are_likely_phishing():
    assert run_all(str(TEST1))["verdict"] == "LIKELY PHISHING"
    assert run_all(str(TEST2))["verdict"] == "LIKELY PHISHING"


# ---------- VirusTotal (no network: responses are faked) ----------

class FakeResponse:
    def __init__(self, status_code, malicious=0):
        self.status_code = status_code
        self._malicious = malicious

    def json(self):
        stats = {"malicious": self._malicious, "suspicious": 0, "harmless": 60}
        return {"data": {"attributes": {"last_analysis_stats": stats}}}


def test_url_id_has_no_padding():
    assert "=" not in lookups.url_id("http://example.com/a")


def test_severity_thresholds():
    assert lookups.severity_for({"malicious": 5}) == "high"
    assert lookups.severity_for({"malicious": 1}) == "medium"
    assert lookups.severity_for({"malicious": 0, "suspicious": 0}) is None


def test_unknown_to_virustotal_returns_none():
    with patch.object(lookups, "_vt_get", return_value=FakeResponse(404)):
        assert lookups.lookup("files/abc", "key", {}) is None


def test_malicious_attachment_becomes_a_high_finding(tmp_path):
    msg = load_eml(TEST1)
    with patch.object(lookups, "_vt_get", return_value=FakeResponse(200, malicious=12)), \
         patch.object(lookups, "CACHE_PATH", tmp_path / "cache.json"), \
         patch.dict("os.environ", {"VT_API_KEY": "fake-key"}):
        findings = lookups.check_virustotal(msg)
    assert "vt_malicious_attachment" in checks_of(findings)
    assert all(f["severity"] == "high" for f in findings)


def test_missing_api_key_is_skipped_quietly():
    with patch.dict("os.environ", {}, clear=True):
        assert lookups.check_virustotal(load_eml(TEST1)) == []
