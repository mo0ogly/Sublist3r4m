# Python API Reference

Sublist3r4m can be used as a Python library in addition to the CLI. This page documents the public API.

## sublist3r.main()

The primary entry point for programmatic subdomain enumeration.

```python
import sublist3r

subdomains = sublist3r.main(
    domain='example.com',
    threads=40,
    savefile='output.txt',
    ports=None,
    silent=False,
    verbose=False,
    enable_bruteforce=False,
    engines=None,
)
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `domain` | `str` | Target domain to enumerate subdomains for (required) |
| `threads` | `int` | Number of threads for the bruteforce module |
| `savefile` | `str \| None` | Path to save results, or `None` to skip saving |
| `ports` | `str \| None` | Comma-separated port numbers to scan, or `None` |
| `silent` | `bool` | If `True`, suppress all console output |
| `verbose` | `bool` | If `True`, display results in real time |
| `enable_bruteforce` | `bool \| None` | If `True` or `None`, enable the subbrute bruteforce module |
| `engines` | `str \| None` | Comma-separated list of engine names, or `None` for all |

### Returns

`list[str]` -- A sorted list of unique discovered subdomains.

### Example: Silent Enumeration

```python
import sublist3r

subdomains = sublist3r.main(
    domain='example.com',
    threads=40,
    savefile=None,
    ports=None,
    silent=True,
    verbose=False,
    enable_bruteforce=False,
    engines=None,
)
print(f"Found {len(subdomains)} subdomains")
for sub in subdomains:
    print(sub)
```

### Example: Specific Engines with Port Scanning

```python
import sublist3r

subdomains = sublist3r.main(
    domain='example.com',
    threads=30,
    savefile='results.txt',
    ports='80,443',
    silent=False,
    verbose=True,
    enable_bruteforce=True,
    engines='google,virustotal,crtsh',
)
```

---

## jarvis_intelligence.enhanced_main()

The JARVIS Intelligence Scanner provides an enhanced API with additional capabilities including multi-format export, email extraction, and intelligence collection.

```python
from jarvis_intelligence import enhanced_main

subdomains = enhanced_main(
    domain='example.com',
    threads=30,
    output_file='results.json',
    output_format='json',
    ports=None,
    silent=False,
    verbose=True,
    enable_bruteforce=True,
    engines=None,
    timeout=25,
    delay=0,
    user_agent=None,
    statistics=False,
    debug=False,
    extract_emails=False,
    extract_owners=False,
    stats_file=None,
    include_ips=False,
    intelligence=False,
    ai_export=None,
)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domain` | `str` | -- | Target domain (required) |
| `threads` | `int` | `30` | Number of threads for bruteforce |
| `output_file` | `str \| None` | `None` | Output file path |
| `output_format` | `str` | `'txt'` | Output format: `txt`, `csv`, `json`, `xml`, `html` |
| `ports` | `str \| None` | `None` | Comma-separated ports to scan |
| `silent` | `bool` | `False` | Suppress console output |
| `verbose` | `bool` | `True` | Display real-time results |
| `enable_bruteforce` | `bool` | `True` | Enable DNS bruteforce |
| `engines` | `str \| None` | `None` | Comma-separated engine names |
| `timeout` | `int` | `25` | HTTP request timeout (seconds) |
| `delay` | `int` | `0` | Delay between requests (seconds) |
| `user_agent` | `str \| None` | `None` | Custom User-Agent string |
| `statistics` | `bool` | `False` | Show detailed statistics |
| `debug` | `bool` | `False` | Enable debug logging |
| `extract_emails` | `bool` | `False` | Extract emails from WHOIS/certificates |
| `extract_owners` | `bool` | `False` | Extract owner/organization info |
| `stats_file` | `str \| None` | `None` | File to save detailed statistics |
| `include_ips` | `bool` | `False` | Include resolved IP addresses in output |
| `intelligence` | `bool` | `False` | Collect full domain intelligence |
| `ai_export` | `str \| None` | `None` | Export data formatted for AI analysis |

### Returns

`list[str]` -- A sorted list of discovered subdomains.

---

## owner_research_engine.AdvancedOwnerResearchEngine

The Owner Research Engine can be used programmatically for domain ownership research.

```python
from owner_research_engine import AdvancedOwnerResearchEngine

engine = AdvancedOwnerResearchEngine(
    debug=False,
    config={
        'max_threads': 10,
        'cache_max_age_hours': 24,
    }
)

# Load domains from a list
domains = ['example.com', 'example.org']

# Run research
results = engine.research_domains(domains)
```

### Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `debug` | `bool` | `False` | Enable debug logging |
| `config` | `dict` | `{}` | Configuration dictionary |

### Config Options

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_threads` | `int` | `10` | Maximum concurrent threads |
| `cache_max_age_hours` | `int` | `24` | Cache expiry time in hours |
