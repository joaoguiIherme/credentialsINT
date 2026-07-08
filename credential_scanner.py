#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║         CREDENTIAL & SENSITIVE DATA SCANNER                   ║
║  Crawls websites and finds exposed credentials, API keys, etc.║
╚═══════════════════════════════════════════════════════════════╝

Author: Mynd$
"""

import requests
import re
import math
import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from bs4.element import Comment
from collections import defaultdict, deque, Counter
import json
import sys
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("credential_scanner")

REQUEST_TIMEOUT = 5  # seconds
MIN_ENTROPY = 3.0    # Shannon bits/char threshold for high-entropy secrets

# Confidence ranking (higher = more likely a real secret)
CONFIDENCE_ORDER = {'low': 1, 'medium': 2, 'high': 3}


class CredentialScanner:
    # Raw regex sources; compiled once in __init__ (M2)
    RAW_PATTERNS = {
        'api_key': [
            r'(?i)(api[_-]?key|apikey|api_token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_]{20,})["\']?',
            r'(?i)(api[_-]?key)["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)["\']?',
        ],
        'password': [
            r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'\s,}]{6,})["\']?',
            r'(?i)(pass)["\']?\s*[:=]\s*["\']?([^"\'\s,}]{6,})["\']?',
            r'(?i)\.value\s*==\s*["\']([^"\']{6,})["\']',  # Catch hardcoded value checks
        ],
        'username': [
            r'(?i)(username|user|login|uname)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.@]{3,})["\']?',
            r'(?i)(admin|root|user)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_]{3,})["\']?',
            r'(?i)\.value\s*==\s*["\']([a-zA-Z0-9_\-\.@]{3,})["\']',  # Catch hardcoded value checks
        ],
        'bearer_token': [
            r'(?i)(bearer|token|auth)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9\-_.]{20,})["\']?',
        ],
        'database_url': [
            r'(?i)(database[_-]?url|db[_-]?url|mongo[_-]?uri|sql[_-]?url)["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)["\']?',
        ],
        'private_key': [
            r'-----BEGIN[A-Z\s]+PRIVATE KEY-----[^-]+-----END[A-Z\s]+PRIVATE KEY-----',
        ],
        'aws_key': [
            r'AKIA[0-9A-Z]{16}',
        ],
        'email': [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        ],
        'credit_card': [
            r'\b\d{4}[_\-\s]?\d{4}[_\-\s]?\d{4}[_\-\s]?\d{4}\b',
        ],
        'webhook_url': [
            r'(?i)(webhook|hook)[_-]?url["\']?\s*[:=]\s*["\']?([^"\'\s,}]+)["\']?',
        ],
        'obfuscated_string': [
            r'(?i)(ReverseString|reverse|atob|btoa|decode|encode)\s*\(\s*["\']([^"\']+)["\']\s*\)',
        ],
    }

    # Confidence per finding type
    CONFIDENCE = {
        'aws_key': 'high',
        'private_key': 'high',
        'api_key': 'high',
        'bearer_token': 'high',
        'credit_card': 'high',
        'database_url': 'medium',
        'password': 'medium',
        'webhook_url': 'medium',
        'email': 'low',
        'username': 'low',
        'obfuscated_string': 'low',
    }

    # Types where a real secret must have high entropy
    ENTROPY_TYPES = {'api_key', 'bearer_token', 'password'}

    # Placeholder / example values to discard (exact match, lowercased)
    DENYLIST = {
        'password', 'passwd', 'pwd', 'changeme', 'change_me', 'example',
        'test', 'testing', 'xxx', 'xxxx', 'your_key_here', 'your_api_key',
        'your_password', 'null', 'undefined', 'none', 'false', 'true',
        'admin', 'root', 'user', 'username', 'email', 'placeholder',
        'secret', 'token', 'apikey', 'api_key', 'foo', 'bar', 'baz',
    }

    def __init__(self, base_url: str, max_depth: int = 3, verbose: bool = False,
                 min_confidence: str = 'low'):
        self.base_url = base_url
        self.max_depth = max_depth
        self.verbose = verbose
        self.min_confidence = min_confidence
        self.visited_urls: set[str] = set()
        self.domain = urlparse(base_url).netloc
        # Deduplicated: keyed by (type, match) -> aggregated record (M2/dedup)
        self.findings: dict[tuple[str, str], dict] = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # Compile patterns once (M2)
        self.patterns: dict[str, list[re.Pattern]] = {
            ptype: [re.compile(p) for p in sources]
            for ptype, sources in self.RAW_PATTERNS.items()
        }

    @staticmethod
    def _luhn_valid(card: str) -> bool:
        """Luhn checksum to reject false-positive 16-digit runs (L2)."""
        digits = [int(c) for c in card if c.isdigit()]
        if len(digits) != 16:
            return False
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    @staticmethod
    def _entropy(s: str) -> float:
        """Shannon entropy (bits/char)."""
        if not s:
            return 0.0
        counts = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    def _is_noise(self, ptype: str, value: str) -> bool:
        """Filter placeholders (denylist) and low-entropy secrets (entropy gate)."""
        v = value.strip().strip('"\'')
        if v.lower() in self.DENYLIST:
            return True
        if ptype in self.ENTROPY_TYPES and self._entropy(v) < MIN_ENTROPY:
            return True
        return False

    def scan(self):
        """Iteratively crawl (BFS) from base URL, then report (M4)."""
        print(f"\n{'='*60}")
        print(f"🔍 Starting scan on: {self.base_url}")
        print(f"{'='*60}\n")

        queue: deque[tuple[str, int]] = deque([(self.base_url, 0)])
        while queue:
            url, depth = queue.popleft()
            if depth > self.max_depth or url in self.visited_urls:
                continue
            self.visited_urls.add(url)
            for link in self._process_url(url, depth):
                queue.append((link, depth + 1))

        self._print_results()

    def _process_url(self, url: str, depth: int) -> list[str]:
        """Fetch, analyze, return same-domain links to enqueue."""
        logger.debug("[*] Crawling (%d): %s", depth, url)
        try:
            response = self.session.get(url, timeout=REQUEST_TIMEOUT, verify=False)
            if response.status_code != 200:
                return []

            soup = BeautifulSoup(response.text, 'html.parser')
            self._analyze_content(soup, response.text, url)

            if depth >= self.max_depth:
                return []

            links = []
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if not isinstance(href, str):
                    continue
                absolute_url = urljoin(url, href)
                if urlparse(absolute_url).netloc == self.domain:
                    links.append(absolute_url)
            return links

        except requests.exceptions.RequestException as e:
            logger.warning("[!] Error accessing %s: %s", url, e)
            return []

    def _analyze_content(self, soup: BeautifulSoup, content: str, url: str):
        """Analyze content for sensitive data patterns (M3: bs4, not regex)."""
        # Inline JavaScript
        for script in soup.find_all('script'):
            if script.string:
                self._check_patterns(script.string, url, 'JavaScript')

        # HTML comments
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            self._check_patterns(str(comment), url, 'HTML Comment')

        # Full raw HTML (meta tags, attributes, etc.)
        self._check_patterns(content, url, 'HTML')

    def _check_patterns(self, text: str, url: str, source: str):
        """Check text against all compiled patterns."""
        for pattern_type, patterns in self.patterns.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    matched = match.group(0)
                    groups = match.groups()
                    value = groups[-1] if groups else matched
                    self._record(pattern_type, matched, value, url, source)

    def _record(self, ptype: str, matched: str, value: str, url: str, source: str):
        """Validate, filter noise, and deduplicate a finding."""
        if ptype == 'credit_card' and not self._luhn_valid(matched):
            return
        if self._is_noise(ptype, value):
            return

        key = (ptype, matched)
        rec = self.findings.get(key)
        if rec is None:
            rec = {
                'type': ptype,
                'match': matched,
                'confidence': self.CONFIDENCE.get(ptype, 'low'),
                'count': 0,
                'urls': set(),
                'sources': set(),
            }
            self.findings[key] = rec
        rec['count'] += 1
        rec['urls'].add(url)
        rec['sources'].add(source)
        logger.info("[+] Found %s (%s) in %s: %s",
                    ptype, rec['confidence'], source, matched[:50])

    def _filtered_findings(self) -> list[dict]:
        """Records at or above min_confidence, sorted high→low then by type."""
        floor = CONFIDENCE_ORDER.get(self.min_confidence, 1)
        recs = [r for r in self.findings.values()
                if CONFIDENCE_ORDER[r['confidence']] >= floor]
        recs.sort(key=lambda r: (-CONFIDENCE_ORDER[r['confidence']], r['type']))
        return recs

    def _print_results(self):
        """Print formatted, deduplicated, confidence-ranked results."""
        findings = self._filtered_findings()
        if not findings:
            print("\n✅ No sensitive data found!\n")
            return

        badge = {'high': '🔴 HIGH', 'medium': '🟡 MEDIUM', 'low': '⚪ LOW'}
        print(f"\n{'='*60}")
        print("🚨 FINDINGS SUMMARY")
        print(f"{'='*60}")

        current_conf = None
        for rec in findings:
            if rec['confidence'] != current_conf:
                current_conf = rec['confidence']
                print(f"\n{badge[current_conf]} CONFIDENCE")
                print(f"{'-'*56}")
            urls = sorted(rec['urls'])
            more = f" (+{len(urls) - 1} more)" if len(urls) > 1 else ""
            print(f"\n  📌 {rec['type'].upper()}  [x{rec['count']}, {len(urls)} url(s)]")
            print(f"     Match:  {rec['match'][:100]}")
            print(f"     Source: {', '.join(sorted(rec['sources']))}")
            print(f"     URL:    {urls[0]}{more}")

        print(f"\n{'='*60}")
        print(f"📊 Unique findings: {len(findings)}  "
              f"(min confidence: {self.min_confidence})")
        print(f"{'='*60}\n")

    def export_json(self, filename: str = "findings.json"):
        """Export deduplicated findings to JSON."""
        data: dict[str, list[dict]] = defaultdict(list)
        for rec in self._filtered_findings():
            data[rec['type']].append({
                'match': rec['match'],
                'confidence': rec['confidence'],
                'count': rec['count'],
                'urls': sorted(rec['urls']),
                'sources': sorted(rec['sources']),
            })
        try:
            with open(filename, 'w') as f:
                json.dump(dict(data), f, indent=2)
            print(f"  Results exported to {filename}")
        except OSError as e:
            logger.warning("[!] Could not export to %s: %s", filename, e)


def print_banner():
    """Print scanner banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║          🔍  CREDENTIAL & SENSITIVE DATA SCANNER  🔍             ║
║                                                                  ║
║  Author: Mynd$                                                   ║
║  Finds: API Keys | Passwords | Tokens | Private Keys             ║
║         Database URLs | Credit Cards | Emails | Webhooks         ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    if len(sys.argv) < 2:
        print_banner()
        print("Usage: python credential_scanner.py <url> [--depth <max_depth>] "
              "[--verbose] [--export <filename>] [--min-confidence low|medium|high]")
        print("\nExamples:")
        print("  python credential_scanner.py http://example.com")
        print("  python credential_scanner.py http://example.com --depth 5 --verbose")
        print("  python credential_scanner.py http://example.com --min-confidence high")
        print("  python credential_scanner.py http://example.com --export findings.json")
        sys.exit(1)

    url = sys.argv[1]
    max_depth = 3
    verbose = False
    export_file = None
    min_confidence = 'low'

    # Parse arguments
    i = 2
    while i < len(sys.argv):
        if sys.argv[i] == '--depth' and i + 1 < len(sys.argv):
            try:
                max_depth = int(sys.argv[i + 1])
            except ValueError:
                print(f"[!] Invalid --depth value: {sys.argv[i + 1]!r} (must be integer)")
                sys.exit(1)
            i += 2
        elif sys.argv[i] == '--verbose':
            verbose = True
            i += 1
        elif sys.argv[i] == '--export' and i + 1 < len(sys.argv):
            export_file = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == '--min-confidence' and i + 1 < len(sys.argv):
            min_confidence = sys.argv[i + 1].lower()
            if min_confidence not in CONFIDENCE_ORDER:
                print(f"[!] Invalid --min-confidence: {sys.argv[i + 1]!r} "
                      f"(use low, medium, or high)")
                sys.exit(1)
            i += 2
        else:
            i += 1

    # Configure logging based on verbosity (M5)
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(message)s",
    )

    # Ensure URL has protocol
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    print_banner()
    scanner = CredentialScanner(url, max_depth=max_depth, verbose=verbose,
                                min_confidence=min_confidence)
    scanner.scan()

    if export_file:
        scanner.export_json(export_file)


if __name__ == '__main__':
    main()
