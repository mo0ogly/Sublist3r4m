"""Configuration management for JARVIS Intelligence."""
from __future__ import annotations

import json
import os
import sys


class ConfigManager:
    """Gestionnaire de configuration pour les APIs et parametres."""

    def __init__(self, config_file: str = "config.json") -> None:
        """Initialize configuration manager from a JSON config file.

        Args:
            config_file: Path to the JSON configuration file.
        """
        self.config_file = config_file
        self.config = self._load_config()

    def _load_config(self):
        """Charge la configuration depuis le fichier JSON."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            else:
                print(f"Warning: Configuration file {self.config_file} not found. Using defaults.")
                return self._get_default_config()
        except Exception as e:
            print(f"Error loading config: {e}. Using defaults.")
            return self._get_default_config()

    def _get_default_config(self):
        """Configuration par defaut."""
        return {
            "api_keys": {},
            "endpoints": {
                "wayback_machine": {
                    "cdx_api": "https://web.archive.org/cdx/search/cdx",
                    "enabled": True
                }
            },
            "settings": {
                "timeout": 30,
                "max_retries": 3,
                "delay_between_requests": 1
            }
        }

    def get_api_key(self, service):
        """Recupere la cle API pour un service."""
        return self.config.get("api_keys", {}).get(service, {}).get("api_key", "")

    def is_service_enabled(self, service):
        """Verifie si un service est active."""
        api_config = self.config.get("api_keys", {}).get(service, {})
        endpoint_config = self.config.get("endpoints", {}).get(service, {})

        # Priorite aux endpoints (services gratuits)
        if endpoint_config:
            return endpoint_config.get("enabled", False)

        # Sinon verifier si API key est disponible et activee
        return api_config.get("enabled", False) and bool(api_config.get("api_key", ""))

    def get_endpoint(self, service):
        """Recupere l'endpoint pour un service."""
        return self.config.get("endpoints", {}).get(service, {}).get("api_url", "")

    def get_setting(self, key, default=None):
        """Recupere un parametre de configuration."""
        return self.config.get("settings", {}).get(key, default)


# Instance globale du gestionnaire de configuration
config_manager = ConfigManager()

# Platform detection
is_windows = sys.platform.startswith('win')
is_linux = sys.platform.startswith('linux')
is_macos = sys.platform.startswith('darwin')
