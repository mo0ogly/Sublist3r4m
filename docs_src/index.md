# Sublist3r4m

**Subdomain enumeration tool for penetration testers and security researchers.**

Sublist3r4m is a fork of [aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r) with enhanced modules for intelligence gathering, owner research, and an advanced GUI.

## Features

- **Multi-engine subdomain enumeration** via Google, Yahoo, Bing, Baidu, Ask, Netcraft, VirusTotal, ThreatCrowd, DNSdumpster, crt.sh
- **JARVIS Intelligence Scanner** with Certificate Transparency, SecurityTrails, retry logic, rate limiting, and multi-format export
- **Owner Research Engine** with fuzzy matching (Levenshtein, Soundex, Jaro-Winkler), WHOIS lookups, and SQLite caching
- **DNS bruteforce** via integrated subbrute module with optimized wordlists
- **Port scanning** on discovered subdomains
- **Advanced GUI** (Tkinter) with logging, filtering, statistics, and export
- **Multi-format export**: JSON, CSV, XML, HTML, TXT

## Quick Start

```bash
git clone https://github.com/mo0ogly/Sublist3r4m.git
cd Sublist3r4m
pip install -e ".[dev]"
python sublist3r.py -d example.com
```

For detailed setup instructions, see the [Installation](installation.md) guide.

## Project Overview

Sublist3r4m consists of several components:

| Component | Description |
|-----------|-------------|
| `sublist3r.py` | Core subdomain enumeration engine with multi-engine search |
| `jarvis_intelligence.py` | JARVIS Intelligence Scanner for advanced enumeration |
| `owner_research_engine.py` | Owner Research Engine with fuzzy matching and WHOIS |
| `subbrute/` | DNS bruteforce module with GUI options |

## API Configuration

Copy the example configuration and add your API keys:

```bash
cp config.json.example config.json
```

Supported APIs: Shodan, Censys, SecurityTrails, VirusTotal, PassiveTotal/RiskIQ.

## License

GNU General Public License v2.0. See [LICENSE](https://github.com/mo0ogly/Sublist3r4m/blob/master/LICENSE).

## Credits

- Original [Sublist3r](https://github.com/aboul3la/Sublist3r) by [Ahmed Aboul-Ela](https://github.com/aboul3la)
- [subbrute](https://github.com/TheRook/subbrute) by [TheRook](https://github.com/TheRook)
- [dnspop](https://github.com/bitquark/dnspop) wordlist by [Bitquark](https://github.com/bitquark)
