"""Unit tests for credential_scanner. No network — pure logic + mocked fetch."""

import json
from types import SimpleNamespace

import pytest
from bs4 import BeautifulSoup

import credential_scanner as cs
from credential_scanner import CredentialScanner


@pytest.fixture
def scanner():
    return CredentialScanner("http://x.test", max_depth=2)


def _analyze(scanner, html, url="http://x.test/a"):
    scanner._analyze_content(BeautifulSoup(html, "html.parser"), html, url)


# --------------------------------------------------------------------------- #
# Luhn (L2)
# --------------------------------------------------------------------------- #
class TestLuhn:
    @pytest.mark.parametrize("card", [
        "4111 1111 1111 1111",   # Visa test
        "4111-1111-1111-1111",
        "5500005555555559",      # Mastercard test
    ])
    def test_valid_cards_pass(self, card):
        assert CredentialScanner._luhn_valid(card) is True

    @pytest.mark.parametrize("card", [
        "1234123412341234",      # fails checksum
        "0000000000000000",      # 16 zeros: valid Luhn but see note
        "4111 1111 1111 1112",   # off by one
    ])
    def test_bad_checksum_rejected(self, card):
        # 0000... actually passes Luhn (sum 0) — assert only the true failures
        if card == "0000000000000000":
            assert CredentialScanner._luhn_valid(card) is True
        else:
            assert CredentialScanner._luhn_valid(card) is False

    def test_wrong_length_rejected(self):
        assert CredentialScanner._luhn_valid("4111 1111") is False
        assert CredentialScanner._luhn_valid("41111111111111111111") is False

    def test_credit_card_finding_filtered_by_luhn(self, scanner):
        html = "<p>card 1234 1234 1234 1234 and 4111 1111 1111 1111</p>"
        _analyze(scanner, html)
        cc = [r for r in scanner.findings.values() if r["type"] == "credit_card"]
        assert len(cc) == 1
        assert "4111" in cc[0]["match"]


# --------------------------------------------------------------------------- #
# Entropy
# --------------------------------------------------------------------------- #
class TestEntropy:
    def test_empty_is_zero(self):
        assert CredentialScanner._entropy("") == 0.0

    def test_uniform_char_low(self):
        assert CredentialScanner._entropy("aaaaaaaa") == 0.0

    def test_random_string_high(self):
        assert CredentialScanner._entropy("aB3xK9mQ2pL7wR5tZ8nV") > 3.0

    def test_dictionary_word_below_threshold(self):
        assert CredentialScanner._entropy("password") < 3.0


# --------------------------------------------------------------------------- #
# Noise filter (denylist + entropy gate)
# --------------------------------------------------------------------------- #
class TestNoiseFilter:
    def test_denylist_exact_match_dropped(self, scanner):
        assert scanner._is_noise("password", "changeme") is True
        assert scanner._is_noise("api_key", "your_api_key") is True

    def test_denylist_case_insensitive(self, scanner):
        assert scanner._is_noise("password", "PASSWORD") is True

    def test_denylist_strips_quotes(self, scanner):
        assert scanner._is_noise("password", '"admin"') is True

    def test_low_entropy_secret_dropped(self, scanner):
        assert scanner._is_noise("api_key", "aaaaaaaaaaaaaaaaaaaa") is True

    def test_high_entropy_secret_kept(self, scanner):
        assert scanner._is_noise("api_key", "aB3xK9mQ2pL7wR5tZ8nV") is False

    def test_entropy_gate_only_for_entropy_types(self, scanner):
        # email is not an entropy type -> low entropy value still kept
        assert scanner._is_noise("email", "aaaa@aaaa.com") is False


# --------------------------------------------------------------------------- #
# Deduplication + recording
# --------------------------------------------------------------------------- #
class TestDedup:
    def test_same_secret_two_urls_single_record(self, scanner):
        scanner._record("api_key", 'api_key="aB3xK9mQ2pL7wR5tZ8nV"',
                        "aB3xK9mQ2pL7wR5tZ8nV", "http://x.test/a", "JavaScript")
        scanner._record("api_key", 'api_key="aB3xK9mQ2pL7wR5tZ8nV"',
                        "aB3xK9mQ2pL7wR5tZ8nV", "http://x.test/b", "HTML")
        assert len(scanner.findings) == 1
        rec = next(iter(scanner.findings.values()))
        assert rec["count"] == 2
        assert rec["urls"] == {"http://x.test/a", "http://x.test/b"}
        assert rec["sources"] == {"JavaScript", "HTML"}

    def test_noise_not_recorded(self, scanner):
        scanner._record("password", 'password="password"', "password",
                        "http://x.test/a", "HTML")
        assert scanner.findings == {}

    def test_bad_credit_card_not_recorded(self, scanner):
        scanner._record("credit_card", "1234 1234 1234 1234",
                        "1234 1234 1234 1234", "http://x.test/a", "HTML")
        assert scanner.findings == {}


# --------------------------------------------------------------------------- #
# Confidence assignment + filtering
# --------------------------------------------------------------------------- #
class TestConfidence:
    def test_types_get_expected_confidence(self, scanner):
        cases = {
            "aws_key": "high",
            "api_key": "high",
            "credit_card": "high",
            "password": "medium",
            "database_url": "medium",
            "email": "low",
            "username": "low",
        }
        for ptype, expected in cases.items():
            assert scanner.CONFIDENCE[ptype] == expected

    def test_min_confidence_filters_low(self):
        s = CredentialScanner("http://x.test", min_confidence="high")
        # inject one of each confidence directly
        s.findings[("aws_key", "AKIAABCDEFGHIJKLMNOP")] = {
            "type": "aws_key", "match": "AKIAABCDEFGHIJKLMNOP",
            "confidence": "high", "count": 1, "urls": {"u"}, "sources": {"HTML"}}
        s.findings[("email", "a@b.com")] = {
            "type": "email", "match": "a@b.com",
            "confidence": "low", "count": 1, "urls": {"u"}, "sources": {"HTML"}}
        out = s._filtered_findings()
        assert len(out) == 1
        assert out[0]["type"] == "aws_key"

    def test_filtered_sorted_high_first(self):
        s = CredentialScanner("http://x.test", min_confidence="low")
        s.findings[("email", "a@b.com")] = {
            "type": "email", "match": "a@b.com", "confidence": "low",
            "count": 1, "urls": {"u"}, "sources": {"HTML"}}
        s.findings[("aws_key", "AKIAABCDEFGHIJKLMNOP")] = {
            "type": "aws_key", "match": "AKIAABCDEFGHIJKLMNOP", "confidence": "high",
            "count": 1, "urls": {"u"}, "sources": {"HTML"}}
        out = s._filtered_findings()
        assert [r["confidence"] for r in out] == ["high", "low"]


# --------------------------------------------------------------------------- #
# Content extraction (M3: bs4)
# --------------------------------------------------------------------------- #
class TestContentExtraction:
    def test_script_with_angle_bracket_not_truncated(self, scanner):
        # Old regex <script>([^<]*)</script> would miss content after '<'
        html = ('<script>if (a < b) { var api_key="aB3xK9mQ2pL7wR5tZ8nV"; }</script>')
        _analyze(scanner, html)
        assert any(r["type"] == "api_key" for r in scanner.findings.values())

    def test_secret_in_html_comment_detected(self, scanner):
        html = "<!-- api_key: aB3xK9mQ2pL7wR5tZ8nV -->"
        _analyze(scanner, html)
        recs = [r for r in scanner.findings.values() if r["type"] == "api_key"]
        assert recs and "HTML Comment" in recs[0]["sources"]

    def test_aws_key_detected(self, scanner):
        _analyze(scanner, "key=AKIAABCDEFGHIJKLMNOP")
        assert any(r["type"] == "aws_key" for r in scanner.findings.values())

    def test_clean_page_no_findings(self, scanner):
        _analyze(scanner, "<html><body><h1>Hello</h1></body></html>")
        assert scanner.findings == {}


# --------------------------------------------------------------------------- #
# Crawl link extraction (mocked fetch, no network)
# --------------------------------------------------------------------------- #
class TestCrawl:
    def test_only_same_domain_links_returned(self, scanner, monkeypatch):
        html = ('<a href="/page1">1</a>'
                '<a href="http://x.test/page2">2</a>'
                '<a href="http://evil.test/page3">3</a>')
        fake = SimpleNamespace(status_code=200, text=html)
        monkeypatch.setattr(scanner.session, "get", lambda *a, **k: fake)
        links = scanner._process_url("http://x.test/", depth=0)
        assert "http://x.test/page1" in links
        assert "http://x.test/page2" in links
        assert all("evil.test" not in link for link in links)

    def test_non_200_returns_no_links(self, scanner, monkeypatch):
        fake = SimpleNamespace(status_code=404, text="nope")
        monkeypatch.setattr(scanner.session, "get", lambda *a, **k: fake)
        assert scanner._process_url("http://x.test/", depth=0) == []

    def test_max_depth_stops_link_extraction(self, scanner, monkeypatch):
        fake = SimpleNamespace(status_code=200, text='<a href="/deep">d</a>')
        monkeypatch.setattr(scanner.session, "get", lambda *a, **k: fake)
        # depth == max_depth -> analyze but return no links
        assert scanner._process_url("http://x.test/", depth=scanner.max_depth) == []

    def test_request_exception_swallowed(self, scanner, monkeypatch):
        import requests

        def boom(*a, **k):
            raise requests.exceptions.ConnectionError("down")

        monkeypatch.setattr(scanner.session, "get", boom)
        assert scanner._process_url("http://x.test/", depth=0) == []


# --------------------------------------------------------------------------- #
# Export
# --------------------------------------------------------------------------- #
class TestExport:
    def test_export_json_structure(self, scanner, tmp_path):
        scanner._record("aws_key", "AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP",
                        "http://x.test/a", "HTML")
        out = tmp_path / "findings.json"
        scanner.export_json(str(out))
        data = json.loads(out.read_text())
        assert "aws_key" in data
        entry = data["aws_key"][0]
        assert entry["confidence"] == "high"
        assert entry["urls"] == ["http://x.test/a"]

    def test_export_bad_path_does_not_raise(self, scanner):
        # directory that does not exist -> OSError swallowed, no crash
        scanner.export_json("/nonexistent_dir_xyz/findings.json")


# --------------------------------------------------------------------------- #
# Reporting output
# --------------------------------------------------------------------------- #
class TestReporting:
    def test_empty_prints_no_data(self, scanner, capsys):
        scanner._print_results()
        assert "No sensitive data found" in capsys.readouterr().out

    def test_findings_printed_with_badges_and_counts(self, scanner, capsys):
        scanner._record("aws_key", "AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP",
                        "http://x.test/a", "HTML")
        scanner._record("aws_key", "AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP",
                        "http://x.test/b", "HTML")
        scanner._record("email", "a@b.com", "a@b.com", "http://x.test/a", "HTML")
        scanner._print_results()
        out = capsys.readouterr().out
        assert "HIGH" in out and "LOW" in out
        assert "AWS_KEY" in out
        assert "x2" in out          # dedup count
        assert "+1 more" in out     # two urls collapsed

    def test_banner_prints(self, capsys):
        cs.print_banner()
        assert "SCANNER" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# CLI / main() — CredentialScanner mocked, no network
# --------------------------------------------------------------------------- #
class _FakeScanner:
    instances = []

    def __init__(self, url, max_depth=3, verbose=False, min_confidence="low"):
        self.url = url
        self.max_depth = max_depth
        self.verbose = verbose
        self.min_confidence = min_confidence
        self.scanned = False
        self.exported = None
        _FakeScanner.instances.append(self)

    def scan(self):
        self.scanned = True

    def export_json(self, filename):
        self.exported = filename


@pytest.fixture
def fake_main(monkeypatch):
    _FakeScanner.instances = []
    monkeypatch.setattr(cs, "CredentialScanner", _FakeScanner)

    def run(argv):
        monkeypatch.setattr(cs.sys, "argv", ["credential_scanner.py", *argv])
        cs.main()
        return _FakeScanner.instances[-1]

    return run


class TestMain:
    def test_no_args_exits(self, monkeypatch):
        monkeypatch.setattr(cs.sys, "argv", ["credential_scanner.py"])
        with pytest.raises(SystemExit) as e:
            cs.main()
        assert e.value.code == 1

    def test_prefixes_protocol(self, fake_main):
        s = fake_main(["example.com"])
        assert s.url == "http://example.com"
        assert s.scanned is True

    def test_all_flags_parsed(self, fake_main):
        s = fake_main(["http://x.test", "--depth", "5", "--verbose",
                       "--min-confidence", "high", "--export", "out.json"])
        assert s.max_depth == 5
        assert s.verbose is True
        assert s.min_confidence == "high"
        assert s.exported == "out.json"

    def test_invalid_depth_exits(self, fake_main):
        with pytest.raises(SystemExit) as e:
            fake_main(["http://x.test", "--depth", "abc"])
        assert e.value.code == 1

    def test_invalid_min_confidence_exits(self, fake_main):
        with pytest.raises(SystemExit) as e:
            fake_main(["http://x.test", "--min-confidence", "bogus"])
        assert e.value.code == 1

    def test_unknown_arg_ignored(self, fake_main):
        s = fake_main(["http://x.test", "--nope"])
        assert s.max_depth == 3
