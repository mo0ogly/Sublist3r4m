# CLI Usage

Sublist3r4m provides two main command-line tools: the core `sublist3r.py` for subdomain enumeration and `jarvis_intelligence.py` for advanced intelligence gathering. This page covers the core CLI.

For JARVIS-specific usage, see [JARVIS Intelligence Scanner](modules/jarvis.md).

## Basic Subdomain Enumeration

Enumerate subdomains for a target domain using all available search engines:

```bash
python sublist3r.py -d example.com
```

## CLI Options

| Flag | Long Form | Description |
|------|-----------|-------------|
| `-d` | `--domain` | Target domain to enumerate (required) |
| `-b` | `--bruteforce` | Enable subbrute bruteforce module |
| `-p` | `--ports` | Scan specific TCP ports (comma-separated) |
| `-v` | `--verbose` | Display results in real-time |
| `-t` | `--threads` | Number of threads for bruteforce (default: 40) |
| `-e` | `--engines` | Specific search engines (comma-separated) |
| `-o` | `--output` | Save results to file |

## Examples

### Bruteforce with Port Scanning

Combine DNS bruteforce with TCP port scanning on common web ports:

```bash
python sublist3r.py -d example.com -b -p 80,443
```

### Verbose Mode (Real-Time Results)

Display discovered subdomains as they are found:

```bash
python sublist3r.py -v -d example.com
```

### Use Specific Search Engines

Limit enumeration to specific engines:

```bash
python sublist3r.py -e google,yahoo,virustotal -d example.com
```

Available engines: `google`, `yahoo`, `bing`, `baidu`, `ask`, `netcraft`, `virustotal`, `threatcrowd`, `dnsdumpster`, `crtsh`.

### Save Results to File

Write discovered subdomains to a text file:

```bash
python sublist3r.py -d example.com -o results.txt
```

### Custom Thread Count for Bruteforce

Increase thread count for faster bruteforce (at the cost of more network load):

```bash
python sublist3r.py -d example.com -b -t 100
```

### Combined Options

A comprehensive scan with verbose output, bruteforce, port scanning, and file output:

```bash
python sublist3r.py -d example.com -v -b -p 80,443,8080,8443 -t 50 -o results.txt
```

## Output Format

By default, results are printed to stdout as a sorted list of subdomains, one per line:

```
www.example.com
mail.example.com
api.example.com
dev.example.com
```

When using `-o`, the same list is written to the specified file.

!!! tip
    For advanced output formats (JSON, CSV, XML, HTML), use the [JARVIS Intelligence Scanner](modules/jarvis.md) which supports multi-format export via the `--format` flag.
