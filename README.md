# credentialsINT

[![CI](https://github.com/joaoguiIherme/credentialsINT/actions/workflows/ci.yml/badge.svg)](https://github.com/joaoguiIherme/credentialsINT/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen.svg)](#tests)

🔍 **Credential & Sensitive-Data Web Scanner** — an OSINT tool that crawls a target website and flags exposed credentials, API keys, tokens, and other secrets in HTML, inline JavaScript, and comments.

> ⚠️ **Authorized use only.** Run this only against systems you own or have explicit written permission to test.

## Features

- **BFS crawler** — same-domain, depth-limited, deduplicated URL frontier.
- **Detects** — API keys, passwords, bearer tokens, DB URLs, private keys, AWS keys, emails, credit cards, webhooks, obfuscated strings.
- **Low-noise findings** — three noise filters keep signal high without dropping detections:
  - **Luhn check** on credit-card matches.
  - **Shannon-entropy gate** (≥ 3.0 bits/char) for high-entropy secret types.
  - **Denylist** of common placeholder values (`changeme`, `your_api_key`, …).
- **Confidence ranking** — every finding tagged `high` / `medium` / `low`; filter output with `--min-confidence`.
- **Deduplication** — identical secrets across pages collapse into one record with a URL/source count.
- **JSON export** for reporting.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Usage

```bash
python credential_scanner.py http://example.com
python credential_scanner.py http://example.com --depth 5 --verbose
python credential_scanner.py http://example.com --min-confidence high
python credential_scanner.py http://example.com --export findings.json
```

| Flag | Description |
|------|-------------|
| `--depth N` | Max crawl depth (default 3) |
| `--verbose` | Debug logging (crawl trace + hits) |
| `--min-confidence low\|medium\|high` | Hide findings below this confidence (default `low`) |
| `--export FILE` | Write findings to a JSON file |

## Tests

```bash
.venv/bin/pytest        # runs suite + coverage gate (80% min)
```

43 tests, 90% coverage. No network — the crawler fetch is mocked.

## License

MIT

## Author

Mynd$
