# iocextract

Pull the **Indicators of Compromise** out of raw logs, emails and threat
reports - and defang them so you can paste them into a ticket without anyone
fat-fingering a live malware URL.

`iocextract` is a small, offline, dependency-light (stdlib + `pydantic`)
blue-team utility. Give it text, get back a deduplicated, classified,
JSON-serialisable set of indicators: IPv4/IPv6, domains, URLs, emails and
MD5/SHA1/SHA256 hashes. It refangs common analyst notations (`hxxp`, `[.]`,
`[at]`) on the way in and can defang on the way out.

## Why it exists

Analysts spend a surprising amount of time copy-pasting IOCs between an EDR
console, a SIEM, a ticket, and a Slack channel. Two things go wrong:

1. **False positives.** Naive `\d+\.\d+\.\d+\.\d+` grabs version strings and
   build tags. `iocextract` structurally rejects three-part versions
   (`1.2.3`), five-octet tags (`10.20.30.40.50`), letter-adjacent versions
   (`v1.2.3.4rc1`) and out-of-range octets (`999.1.1.1`), and treats
   `invoice.exe` as a filename rather than a domain.
2. **Live indicators in shared text.** Pasting `http://evil.com` into a chat
   makes it clickable. `iocextract` defangs to `hxxp://evil[.]com` and refangs
   back losslessly.

## Quickstart (from a fresh clone)

```bash
git clone <this-repo> && cd 09b-security-iocextract
uv sync                       # creates .venv, installs pydantic + dev tools

uv run iocextract extract tests/fixtures/sample.log      # JSON to stdout
uv run pytest -q                                         # 38 tests, all offline
```

No network, no services, no keys, no Docker. `uv` is the only prerequisite.

## Usage

The shipped fixture `tests/fixtures/sample.log` has planted IOCs (and planted
*non*-IOCs to prove the guards). Running the extractor over it:

```
$ uv run iocextract extract tests/fixtures/sample.log -f table
url     http://malware-c2.evil-domain.com/beacon?id=7
url     https://evil.example.org/upload?token=42
email   attacker@bad-actor.net
sha256  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
sha1    da39a3ee5e6b4b0d3255bfef95601890afd80709
md5     d41d8cd98f00b204e9800998ecf8427e
ipv6    2001:db8::1
ipv4    10.0.0.7
ipv4    192.168.1.15
ipv4    203.0.113.45
ipv4    93.184.216.34
domain  cdn.legit-service.com
```

The default JSON output carries a summary header (asserted in the test suite):

```json
{
  "total": 12,
  "counts": {
    "domain": 1,
    "email": 1,
    "ipv4": 4,
    "ipv6": 1,
    "md5": 1,
    "sha1": 1,
    "sha256": 1,
    "url": 2
  }
}
```

Note what is **absent**: the log contains `version 1.2.3`,
`build tag 10.20.30.40.50`, and the filename `invoice.exe` - none are reported.
The malware domain and email are folded into their parent URL / email rather
than double-counted.

### Defang / refang

```
$ uv run iocextract defang "go to http://evil.com now"
go to hxxp://evil[.]com now

$ uv run iocextract refang "hxxp://evil[.]com and user[at]bad[.]com"
http://evil.com and user@bad.com
```

`refang` is deliberately liberal and accepts many house styles -
`hxxp`, `hXXp`, `[.]`, `(.)`, `{.}`, `[dot]`, `[at]` - so you can point it at
whatever a colleague pasted.

### Piping and filtering

```bash
cat incident.txt | uv run iocextract extract            # read stdin
uv run iocextract extract *.log -t ipv4 -t sha256       # only these types
uv run iocextract extract report.txt --compact          # single-line JSON
```

## Library API

```python
from iocextract import extract, defang, refang
from iocextract.models import IOCType

result = extract("beacon to hxxp://bad[.]net/panel from 1[.]2[.]3[.]4")
result.total                      # 2
result.counts                     # {'ipv4': 1, 'url': 1}
result.values(IOCType.IPV4)       # ['1.2.3.4']
result.iocs[0].defanged           # safe-to-share form
print(result.to_json())           # summary + indicators
```

Every result object is built from `pydantic` models, so it validates and
serialises cleanly.

## How it works

1. **Refang** the whole input first, so live *and* defanged indicators are
   caught by the same pass.
2. **Gather** candidate matches per type, each with its character span, using
   look-around-guarded regexes (`src/iocextract/patterns.py`).
3. **Resolve overlaps** by priority (URL > email > hashes > IPv6 > IPv4 >
   domain), so a host inside a URL collapses into the URL.
4. **Dedupe, classify, and defang** each survivor.

## Development

```bash
uv run ruff check .     # lint (line 100; E,F,I,UP,B,SIM,RUF)
uv run mypy src         # strict type-check, clean
uv run pytest -q        # 38 tests
```

CI (`.github/workflows/ci.yml`) runs the same three gates on Ubuntu with
Python 3.12.

## What I'd build next

- **STIX 2.1 / MISP export** so results drop straight into a TIP.
- **CIDR-aware allowlisting** to suppress your own RFC1918 ranges and known-good
  infrastructure before an indicator is ever reported.
- **Confidence scoring** using context words (`src=`, `dst=`, `sha256=`) to rank
  indicators and further cut false positives.
- **Defanged IPv6 and file-path indicators**, plus CVE and Bitcoin-address
  extractors.
- **Streaming mode** for tailing large log files without loading them fully.

## About the Maintainer

This project is currently maintained by SAI DEEKSHITHA REDDY PALPUNOORI. With 3+ years of professional experience in data analysis and operational analytics, including proficiency in Python and SQL, SAI DEEKSHITHA REDDY PALPUNOORI focuses on developing robust and efficient tools for data processing and security operations.

- GitHub: [saideekshithareddypalpunoori-cloud](https://github.com/saideekshithareddypalpunoori-cloud)
- LinkedIn: [Sai Deekshitha Reddy Palpunoori](https://www.linkedin.com/in/sai-deekshitha-reddy-palpunoori-b38b60215/)
- Email: saideekshithareddypalpunoori@gmail.com