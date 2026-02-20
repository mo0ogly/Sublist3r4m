# Owner Research Engine

The Owner Research Engine is an advanced domain ownership research tool that uses fuzzy matching algorithms, WHOIS lookups, and intelligent caching to identify and correlate domain owners.

## Overview

Key capabilities:

- **Fuzzy matching** with multiple algorithms: Levenshtein distance, Soundex, Jaro-Winkler similarity, and SequenceMatcher
- **WHOIS lookups** for domain registration data
- **SQLite caching** with configurable expiry for repeated lookups
- **Multi-threaded** operation for processing large domain lists
- **Advanced scoring** with weighted criteria
- **Export** in JSON and CSV formats

## CLI Usage

### Basic Usage

```bash
python owner_research_engine.py --input domains.txt --output results.json
```

### Full Options Reference

| Flag | Long Form | Default | Description |
|------|-----------|---------|-------------|
| `-i` | `--input` | -- | Input file with domains (required) |
| `-e` | `--expected` | -- | File with expected owners (`domain\|owner` format) |
| `-o` | `--output` | -- | Output file for results (required) |
| `-f` | `--format` | `json` | Output format: `json` or `csv` |
| | `--debug` | `False` | Enable debug logging |
| | `--threads` | `10` | Maximum concurrent threads |
| | `--cache-hours` | `24` | Cache max age in hours |

### Input File Format

The input file should contain one domain per line:

```text
example.com
example.org
example.net
```

### Expected Owners File Format

When using the `-e` / `--expected` flag, provide a pipe-delimited file with domain and expected owner:

```text
example.com|Example Inc.
example.org|Example Foundation
```

This enables the fuzzy matching engine to score results against known ownership data.

## Examples

### JSON Output with Debug Logging

```bash
python owner_research_engine.py -i domains.txt -o results.json --debug
```

### CSV Output with Custom Thread Count

```bash
python owner_research_engine.py -i domains.txt -o results.csv -f csv --threads 20
```

### With Expected Owners for Validation

```bash
python owner_research_engine.py -i domains.txt -e expected_owners.txt -o results.json
```

### Extended Cache Duration

```bash
python owner_research_engine.py -i domains.txt -o results.json --cache-hours 72
```

## Fuzzy Matching Algorithms

The engine uses multiple fuzzy matching algorithms to correlate domain ownership:

| Algorithm | Description |
|-----------|-------------|
| **SequenceMatcher** | Python's built-in sequence matching (difflib) |
| **Levenshtein Distance** | Edit distance between two strings |
| **Soundex** | Phonetic algorithm for matching similar-sounding names |
| **Jaro-Winkler** | String similarity metric optimized for short strings |

Results are scored using a weighted combination of these algorithms, producing a confidence score for each ownership match.

## Architecture

| Class | Purpose |
|-------|---------|
| `AdvancedOwnerResearchEngine` | Main engine coordinating research operations |
| `FuzzyMatcher` | Implements all fuzzy matching algorithms and scoring |
| `OwnerDatabase` | SQLite-backed persistent cache for lookup results |
| `AdvancedOwnerLogger` | Specialized logging with metrics tracking |

## Caching

The engine uses an SQLite database for caching WHOIS lookup results. This avoids redundant network requests when researching overlapping domain sets.

- Cache location: automatically managed in the working directory
- Default expiry: 24 hours (configurable via `--cache-hours`)
- Cache is transparent -- expired entries are automatically refreshed

## Python API

See the [Python API Reference](../api.md#owner_research_engineadvancedownerresearchengine) for programmatic usage.
