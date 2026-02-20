# Installation

## Requirements

- **Python 3.9** or higher
- pip (Python package manager)
- Git (to clone the repository)

## Install from Source

### Clone the Repository

```bash
git clone https://github.com/mo0ogly/Sublist3r4m.git
cd Sublist3r4m
```

### Install with Development Dependencies

This installs the project in editable mode along with development tools (pytest, ruff, etc.):

```bash
pip install -e ".[dev]"
```

### Install Runtime Dependencies Only

If you only need to run the tool without development tools:

```bash
pip install -r requirements.txt
```

Or install the package without dev extras:

```bash
pip install -e .
```

## Dependencies

### Runtime Dependencies

| Package | Purpose |
|---------|---------|
| `dnspython` | DNS resolution and queries |
| `requests` | HTTP requests to search engines and APIs |

### Development Dependencies

| Package | Purpose |
|---------|---------|
| `pytest` | Test framework |
| `pytest-cov` | Code coverage reporting |
| `ruff` | Linting and code style enforcement |
| `jsonschema` | JSON schema validation for tests |

### Documentation Dependencies

To build the documentation site locally:

```bash
pip install -e ".[docs]"
```

This installs:

| Package | Purpose |
|---------|---------|
| `mkdocs` | Static site generator for documentation |
| `mkdocs-material` | Material Design theme for MkDocs |

## API Keys (Optional)

Some enumeration engines require API keys for full functionality. Copy the example configuration and add your keys:

```bash
cp config.json.example config.json
```

Edit `config.json` with your API keys for any of the following services:

- **Shodan** -- Internet device search engine
- **Censys** -- Internet-wide scanning data
- **SecurityTrails** -- DNS and domain intelligence
- **VirusTotal** -- File and URL analysis
- **PassiveTotal / RiskIQ** -- Threat intelligence

!!! note
    The tool works without API keys, but certain engines (SecurityTrails, VirusTotal API mode) will be unavailable.

## Verifying the Installation

Run the test suite to confirm everything is set up correctly:

```bash
make test
```

Or run the linter:

```bash
make lint
```

You can also verify the CLI is working:

```bash
python sublist3r.py -h
```
