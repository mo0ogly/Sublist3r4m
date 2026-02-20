"""Security validation for JARVIS Intelligence."""
from __future__ import annotations

import os
import re
import urllib.parse as urlparse

from jarvis.logger import EnhancedLogger


class SecurityValidator:
    """
    Validateur de securite pour toutes les entrees utilisateur.

    Protege contre:
    - Injection de commandes
    - Directory traversal
    - Inputs malveillants
    - Domaines invalides
    """

    # Patterns dangereux
    DANGEROUS_PATTERNS = [
        r'[;&|`$()\\]',  # Caracteres d'injection shell
        r'<script[^>]*>',  # Injection XSS
        r'javascript:',  # URL javascript
        r'\.\.[/\\]',  # Directory traversal
        r'\x00',  # Null bytes
        r'\$(\{|\()',  # Variable expansion
    ]

    # Pattern pour domaines valides
    DOMAIN_PATTERN = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'

    def __init__(self, logger: EnhancedLogger | None = None) -> None:
        """Initialise le validateur."""
        self.logger = logger
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.DANGEROUS_PATTERNS]
        self.domain_regex = re.compile(self.DOMAIN_PATTERN)

        # Blacklist de domaines
        self.blocked_domains = {
            'localhost', '127.0.0.1', '0.0.0.0', '::1',
            'example.com', 'test.com', 'invalid.tld'
        }

    def _log_security_event(self, event_type, message, **kwargs):
        """Log d'evenement de securite."""
        if self.logger:
            self.logger.error("SECURITY_EVENT: {} - {}".format(event_type, message),
                           module="SecurityValidator", event_type=event_type, **kwargs)

    def validate_domain(self, domain):
        """
        Valide un nom de domaine.

        Returns:
            tuple: (is_valid, sanitized_domain, error_message)
        """
        try:
            if not domain or not isinstance(domain, str):
                return False, None, "Domain must be a non-empty string"

            # Nettoyer et normaliser
            sanitized = domain.strip().lower()

            # Supprimer http/https si present
            if sanitized.startswith(('http://', 'https://')):
                parsed = urlparse.urlparse(sanitized)
                sanitized = parsed.netloc or parsed.path

            # Verifier la longueur
            if len(sanitized) > 253:
                self._log_security_event("DOMAIN_TOO_LONG", "Domain exceeds max length", domain=sanitized[:50])
                return False, None, "Domain name too long (max 253 characters)"

            if len(sanitized) < 3:
                return False, None, "Domain name too short (min 3 characters)"

            # Verifier les patterns dangereux
            for pattern in self.compiled_patterns:
                if pattern.search(sanitized):
                    self._log_security_event("DANGEROUS_PATTERN", "Dangerous pattern in domain",
                                           domain=sanitized, pattern=pattern.pattern)
                    return False, None, "Domain contains dangerous characters"

            # Verifier le format avec regex
            if not self.domain_regex.match(sanitized):
                return False, None, "Invalid domain format"

            # Verifier la blacklist
            if sanitized in self.blocked_domains:
                self._log_security_event("BLOCKED_DOMAIN", "Blocked domain attempted", domain=sanitized)
                return False, None, "Domain is blocked for security reasons"

            # Verifier les parties du domaine
            parts = sanitized.split('.')
            if len(parts) < 2:
                return False, None, "Domain must have at least two parts"

            for part in parts:
                if not part or len(part) > 63:
                    return False, None, "Invalid domain part length"
                if part.startswith('-') or part.endswith('-'):
                    return False, None, "Domain parts cannot start or end with hyphen"

            return True, sanitized, None

        except Exception as e:
            self._log_security_event("VALIDATION_ERROR", "Exception during validation", error=str(e))
            return False, None, "Validation error: {}".format(str(e))

    def validate_file_path(self, file_path):
        """
        Valide un chemin de fichier.

        Returns:
            tuple: (is_valid, sanitized_path, error_message)
        """
        try:
            if not file_path or not isinstance(file_path, str):
                return False, None, "File path must be a non-empty string"

            # Nettoyer le chemin
            clean_path = file_path.strip()

            # Verifier les patterns dangereux
            for pattern in self.compiled_patterns:
                if pattern.search(clean_path):
                    self._log_security_event("DANGEROUS_PATH", "Dangerous pattern in path", path=clean_path)
                    return False, None, "File path contains dangerous characters"

            # Verifier directory traversal
            if ".." in clean_path:
                self._log_security_event("DIRECTORY_TRAVERSAL", "Directory traversal attempt", path=clean_path)
                return False, None, "Directory traversal not allowed"

            # Normaliser le chemin
            try:
                normalized_path = os.path.normpath(clean_path)
                if normalized_path.startswith('..'):
                    self._log_security_event("PATH_ESCAPE", "Path escape attempt", path=clean_path)
                    return False, None, "Path escape not allowed"
            except Exception as e:
                return False, None, "Path normalization failed: {}".format(str(e))

            return True, normalized_path, None

        except Exception as e:
            self._log_security_event("PATH_VALIDATION_ERROR", "Path validation exception", error=str(e))
            return False, None, "Path validation error: {}".format(str(e))

    def validate_port_list(self, ports_str):
        """
        Valide une liste de ports.

        Returns:
            tuple: (is_valid, port_list, error_message)
        """
        try:
            if not ports_str:
                return True, [], None

            if not isinstance(ports_str, str):
                return False, [], "Ports must be a string"

            # Verifier les patterns dangereux
            for pattern in self.compiled_patterns:
                if pattern.search(ports_str):
                    self._log_security_event("DANGEROUS_PORTS", "Dangerous pattern in ports", ports=ports_str)
                    return False, [], "Ports string contains dangerous characters"

            # Parser les ports
            ports = []
            for port_str in ports_str.split(','):
                port_str = port_str.strip()

                # Verifier si c'est un nombre
                if not port_str.isdigit():
                    return False, [], "Invalid port number: {}".format(port_str)

                port = int(port_str)

                # Verifier la plage valide
                if port < 1 or port > 65535:
                    return False, [], "Port {} out of valid range (1-65535)".format(port)

                ports.append(port)

            # Limiter le nombre de ports pour eviter les abus
            if len(ports) > 100:
                self._log_security_event("TOO_MANY_PORTS", "Too many ports requested", count=len(ports))
                return False, [], "Too many ports (max 100)"

            return True, ports, None

        except Exception as e:
            self._log_security_event("PORT_VALIDATION_ERROR", "Port validation exception", error=str(e))
            return False, [], "Port validation error: {}".format(str(e))
