# Sublist3r4m

[![CI](https://github.com/mo0ogly/Sublist3r4m/actions/workflows/ci.yml/badge.svg)](https://github.com/mo0ogly/Sublist3r4m/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v2](https://img.shields.io/badge/license-GPL--2.0-green.svg)](LICENSE)
[![Code style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://docs.astral.sh/ruff/)

Subdomain enumeration tool for penetration testers and security researchers.

Fork of [aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r) with enhanced modules for intelligence gathering, owner research, and advanced GUI.

## Features

- **Multi-engine subdomain enumeration** via Google, Yahoo, Bing, Baidu, Ask, Netcraft, VirusTotal, ThreatCrowd, DNSdumpster, crt.sh
- **JARVIS Intelligence Scanner** with Certificate Transparency, SecurityTrails, retry logic, rate limiting, and multi-format export
- **Owner Research Engine** with fuzzy matching (Levenshtein, Soundex, Jaro-Winkler), WHOIS lookups, and SQLite caching
- **DNS bruteforce** via integrated subbrute module with optimized wordlists
- **Port scanning** on discovered subdomains
- **Advanced GUI** (Tkinter) with logging, filtering, statistics, and export
- **Multi-format export**: JSON, CSV, XML, HTML, TXT

## Installation

**Requires Python 3.9+**

```bash
git clone https://github.com/mo0ogly/Sublist3r4m.git
cd Sublist3r4m
pip install -e ".[dev]"
```

Or install runtime dependencies only:

```bash
pip install -r requirements.txt
```

## Usage

### Basic subdomain enumeration

```bash
python sublist3r.py -d example.com
```

### With bruteforce and port scanning

```bash
python sublist3r.py -d example.com -b -p 80,443
```

### Verbose mode (real-time results)

```bash
python sublist3r.py -v -d example.com
```

### Use specific engines

```bash
python sublist3r.py -e google,yahoo,virustotal -d example.com
```

### Save results to file

```bash
python sublist3r.py -d example.com -o results.txt
```

## CLI Options

| Flag | Long Form       | Description                                      |
|------|-----------------|--------------------------------------------------|
| `-d` | `--domain`      | Target domain to enumerate                       |
| `-b` | `--bruteforce`  | Enable subbrute bruteforce module                |
| `-p` | `--ports`       | Scan specific TCP ports (comma-separated)        |
| `-v` | `--verbose`     | Display results in real-time                     |
| `-t` | `--threads`     | Number of threads for bruteforce                 |
| `-e` | `--engines`     | Specific engines (comma-separated)               |
| `-o` | `--output`      | Save results to file                             |

## Using as a Python Module

```python
import sublist3r

subdomains = sublist3r.main(
    domain='example.com',
    no_threads=40,
    savefile='output.txt',
    ports=None,
    silent=False,
    verbose=False,
    enable_bruteforce=False,
    engines=None
)
```

## Additional Modules

### JARVIS Intelligence Scanner

```bash
python jarvis_intelligence.py -d example.com
```

Enhanced enumeration with Certificate Transparency logs, API integrations, and multi-format export.

### Owner Research Engine

```bash
python owner_research_engine.py --input domains.txt --output results.json
```

Domain owner research with fuzzy matching, WHOIS lookups, and SQLite caching.

### SubBrute GUI

```bash
python subbrute/launch_advanced_gui.py
```

Advanced Tkinter GUI for DNS bruteforce with real-time logging and statistics.

## API Configuration

Copy the example configuration and add your API keys:

```bash
cp config.json.example config.json
```

Supported APIs: Shodan, Censys, SecurityTrails, VirusTotal, PassiveTotal/RiskIQ.

## Development

```bash
# Install dev dependencies
make install

# Run tests
make test

# Run linter
make lint

# Auto-fix lint errors
make lint-fix
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

GNU General Public License v2.0. See [LICENSE](LICENSE).

## Credits

- Original [Sublist3r](https://github.com/aboul3la/Sublist3r) by [Ahmed Aboul-Ela](https://github.com/aboul3la)
- [subbrute](https://github.com/TheRook/subbrute) by [TheRook](https://github.com/TheRook)
- [dnspop](https://github.com/bitquark/dnspop) wordlist by [Bitquark](https://github.com/bitquark)
