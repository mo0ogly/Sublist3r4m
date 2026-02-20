# JARVIS Intelligence Scanner

**JARVIS** (Just Another Robust Vulnerability Intelligence System) is an advanced intelligence and security analysis platform built into Sublist3r4m. It extends the core subdomain enumeration with Certificate Transparency, API integrations, multi-format export, and intelligence gathering capabilities.

## Overview

JARVIS enhances the base Sublist3r4m engine with:

- **Certificate Transparency** enumeration via crt.sh
- **SecurityTrails** API integration for comprehensive DNS intelligence
- **VirusTotal** API integration for threat-correlated subdomain discovery
- **Wayback Machine** enumeration for historical subdomain data
- **ThreatCrowd** intelligence gathering
- **Email extraction** from WHOIS records and certificates
- **Owner/organization extraction** from domain registrations
- **Multi-format export**: TXT, CSV, JSON, XML, HTML
- **Rate limiting and retry logic** for reliable scanning
- **Session save/restore** for long-running scans
- **Detailed statistics** and performance metrics

## CLI Usage

### Basic Scan

```bash
python jarvis_intelligence.py -d example.com
```

### Full Options Reference

| Flag | Long Form | Default | Description |
|------|-----------|---------|-------------|
| `-d` | `--domain` | -- | Target domain (required) |
| `-b` | `--bruteforce` | `False` | Enable DNS bruteforce module |
| `-p` | `--ports` | -- | TCP ports to scan (comma-separated) |
| `-v` | `--verbose` | `False` | Enable verbose output with real-time results |
| `-t` | `--threads` | `30` | Number of threads for bruteforce |
| `-e` | `--engines` | all | Comma-separated list of search engines |
| | `--preset` | -- | Engine preset: `fast`, `complete`, `free`, `apis`, `exhaustive` |
| | `--extract-emails` | `False` | Extract emails from WHOIS and certificates |
| | `--extract-owners` | `False` | Extract owner/organization information |
| | `--stats-file` | -- | Save detailed statistics to file |
| | `--include-ips` | `False` | Include resolved IP addresses in output |
| | `--intelligence` | `False` | Collect full domain intelligence for AI analysis |
| | `--ai-export` | -- | Export data formatted for AI analysis |
| `-o` | `--output` | -- | Save results to file |
| | `--format` | `txt` | Output format: `txt`, `csv`, `json`, `xml`, `html` |
| | `--no-color` | `False` | Disable colored output |
| | `--timeout` | `25` | HTTP request timeout in seconds |
| | `--delay` | `0` | Delay between requests in seconds |
| | `--user-agent` | -- | Custom User-Agent string |
| | `--debug` | `False` | Enable debug logging |
| | `--silent` | `False` | Silent mode (results only) |
| | `--statistics` | `False` | Show detailed statistics at the end |
| | `--save-session` | `False` | Save session data for resuming |
| | `--load-session` | -- | Load previous session data |

## Examples

### JSON Export with Statistics

```bash
python jarvis_intelligence.py -d example.com -v -o results.json --format json --statistics
```

### Intelligence Gathering with AI Export

```bash
python jarvis_intelligence.py -d example.com --intelligence --ai-export intel_report.json
```

### Fast Preset with Email Extraction

```bash
python jarvis_intelligence.py -d example.com --preset fast --extract-emails -o results.csv --format csv
```

### Stealthy Scan with Rate Limiting

```bash
python jarvis_intelligence.py -d example.com --delay 2 --timeout 30 --user-agent "Mozilla/5.0" -v
```

### Resume a Previous Session

```bash
# Start a scan and save the session
python jarvis_intelligence.py -d example.com --save-session -v

# Later, resume the session
python jarvis_intelligence.py -d example.com --load-session session_data.json
```

## Engine Presets

JARVIS supports predefined engine combinations via the `--preset` flag:

| Preset | Description |
|--------|-------------|
| `fast` | Quick scan with the fastest engines |
| `complete` | All available engines |
| `free` | Only engines that do not require API keys |
| `apis` | Only API-based engines (requires configuration) |
| `exhaustive` | All engines with maximum depth |

## Output Formats

### TXT (default)

One subdomain per line, sorted alphabetically.

### CSV

Comma-separated values with headers, includes metadata when available.

### JSON

Structured JSON with subdomains, metadata, and scan information.

### XML

XML document with subdomain entries and scan metadata.

### HTML

Styled HTML report suitable for sharing and presentation.

## Architecture

JARVIS is built on several key classes:

| Class | Purpose |
|-------|---------|
| `EnhancedEnumeratorBase` | Base class for all enumeration engines |
| `CertificateTransparencyEnum` | crt.sh Certificate Transparency queries |
| `SecurityTrailsEnum` | SecurityTrails API integration |
| `VirusTotalEnum` | VirusTotal API integration |
| `WaybackMachineEnum` | Wayback Machine historical data |
| `ThreatCrowdEnum` | ThreatCrowd intelligence |
| `DNSBruteForceEnum` | DNS bruteforce via subbrute |
| `DomainIntelligenceCollector` | Full domain intelligence collection |
| `EmailExtractor` | Email extraction from various sources |
| `StatisticsCollector` | Scan metrics and statistics |
| `EnhancedPortScanner` | TCP port scanning on discovered subdomains |

## Python API

See the [Python API Reference](../api.md#jarvis_intelligenceenhanced_main) for programmatic usage.
