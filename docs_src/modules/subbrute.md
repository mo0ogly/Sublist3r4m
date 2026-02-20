# SubBrute Module

SubBrute is a DNS bruteforce module integrated into Sublist3r4m. It systematically resolves potential subdomains from wordlists using multiple DNS resolvers for fast, reliable enumeration.

## Overview

SubBrute provides:

- **DNS bruteforce** using customizable wordlists
- **Multi-process** architecture for high performance
- **Nameserver verification** to ensure resolver reliability
- **Advanced GUI** (Tkinter) with real-time logging and statistics
- **Optimized wordlists** included (`names.txt`)
- **Custom resolver lists** (`resolvers.txt`)

## Integration with Sublist3r4m

SubBrute is automatically invoked when you use the `-b` / `--bruteforce` flag with the core tool:

```bash
python sublist3r.py -d example.com -b
```

You can control the thread count for bruteforce:

```bash
python sublist3r.py -d example.com -b -t 100
```

## Standalone GUI

SubBrute includes several GUI options for interactive DNS bruteforce:

### Advanced GUI

```bash
python subbrute/launch_advanced_gui.py
```

Features:

- Real-time logging and progress display
- Domain and wordlist configuration
- Export results to file
- Port scanning integration
- Statistics dashboard

### Simple GUI

```bash
python subbrute/launch_gui.py
```

A streamlined interface for quick bruteforce operations.

## Architecture

| Class / Function | Purpose |
|------------------|---------|
| `SubBrute` | Main bruteforce engine coordinating workers |
| `NameServerVerifier` | Validates DNS resolvers before use (multiprocessing.Process) |
| `DNSLookupWorker` | Performs DNS lookups in parallel (multiprocessing.Process) |
| `run()` | High-level function to execute a bruteforce scan |
| `extract_hosts()` | Extract hostnames from raw DNS response data |
| `extract_subdomains()` | Parse subdomains from a results file |

## Wordlists

SubBrute ships with:

- **`names.txt`** -- Optimized subdomain wordlist based on the [dnspop](https://github.com/bitquark/dnspop) project by Bitquark
- **`resolvers.txt`** -- Curated list of public DNS resolvers

You can substitute your own wordlists when using SubBrute programmatically.

## GUI Files

| File | Description |
|------|-------------|
| `launch_advanced_gui.py` | Entry point for the advanced Tkinter GUI |
| `launch_gui.py` | Entry point for the simple GUI |
| `subbrute_gui.py` | Simple GUI implementation |
| `subbrute_gui_advanced.py` | Advanced GUI implementation with full features |
| `gui_simple.py` | Minimal GUI variant |
