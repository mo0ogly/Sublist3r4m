# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2025-07-25

### Added
- JARVIS Intelligence Scanner module for enhanced subdomain enumeration
- Owner Research Engine with fuzzy matching algorithms
- Advanced SubBrute GUI with logging, export, and port scanning
- Certificate Transparency (crt.sh) enumeration engine
- SecurityTrails and VirusTotal API integration
- Multi-format export (JSON, CSV, XML, HTML, TXT)
- Configuration file for API keys and settings

### Changed
- Fork from aboul3la/Sublist3r
- Modernized packaging with pyproject.toml
- Dropped Python 2 support (requires Python 3.9+)
- Replaced setup.py with pyproject.toml
- Comprehensive .gitignore

### Removed
- Python 2 compatibility code
- Debug and fix scripts
- Tracked log files, database, and result files

### Security
- API keys moved to gitignored config.json
- config.json.example provided as template
- Sensitive files removed from git history
