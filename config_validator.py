"""Configuration loader and validator for Sublist3r4m.

Loads config.json and validates it against config_schema.json.
Falls back to loading without validation when jsonschema is not installed.

Usage::

    from config_validator import load_config

    config = load_config()                       # default config.json
    config = load_config("path/to/config.json")  # custom path
"""

import json
import os
import sys

try:
    from jsonschema import ValidationError, validate

    _HAS_JSONSCHEMA = True
except ImportError:
    _HAS_JSONSCHEMA = False

# Resolve paths relative to *this* file so imports work from any cwd.
_HERE = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_CONFIG = os.path.join(_HERE, "config.json")
_SCHEMA_PATH = os.path.join(_HERE, "config_schema.json")


def _load_schema():
    """Load the JSON schema from config_schema.json.

    Returns ``None`` if the schema file is missing.
    """
    if not os.path.exists(_SCHEMA_PATH):
        print(f"Warning: Schema file not found at {_SCHEMA_PATH}. Skipping validation.")
        return None
    with open(_SCHEMA_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _validate(config, schema):
    """Validate *config* against *schema* using jsonschema.

    Prints human-readable error details when validation fails and then
    re-raises the ``ValidationError``.
    """
    try:
        validate(instance=config, schema=schema)
    except ValidationError as exc:
        path = " -> ".join(str(p) for p in exc.absolute_path) if exc.absolute_path else "(root)"
        print(f"Config validation error at '{path}': {exc.message}", file=sys.stderr)
        raise


def load_config(config_path=None):
    """Load and optionally validate the configuration file.

    Parameters
    ----------
    config_path : str or None
        Path to the JSON configuration file.  Defaults to
        ``config.json`` in the same directory as this module.

    Returns
    -------
    dict
        The parsed (and validated, if possible) configuration dictionary.

    Raises
    ------
    FileNotFoundError
        If the configuration file does not exist.
    json.JSONDecodeError
        If the configuration file contains invalid JSON.
    jsonschema.ValidationError
        If ``jsonschema`` is installed and the configuration does not
        conform to the schema.
    """
    if config_path is None:
        config_path = _DEFAULT_CONFIG

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as fh:
        config = json.load(fh)

    # --- Validation -----------------------------------------------------------
    if not _HAS_JSONSCHEMA:
        print(
            "Warning: jsonschema is not installed. "
            "Config loaded without validation. "
            "Install it with: pip install jsonschema"
        )
        return config

    schema = _load_schema()
    if schema is not None:
        _validate(config, schema)

    return config


# ---------------------------------------------------------------------------
# CLI entry-point: ``python config_validator.py [path]``
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        cfg = load_config(target)
        print("Config is valid.")
    except FileNotFoundError as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as err:
        print(f"Error: Invalid JSON — {err}", file=sys.stderr)
        sys.exit(1)
    except Exception as err:  # noqa: BLE001
        print(f"Validation failed: {err}", file=sys.stderr)
        sys.exit(1)
