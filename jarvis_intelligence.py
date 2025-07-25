#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🛡️  JARVIS - Just Another Robust Vulnerability Intelligence System
🧭 Advanced Intelligence & Security Analysis Platform v1.0

🚀 Professional Domain Intelligence & Configuration Analysis Tool
   Specialized in AWS, Active Directory, Exchange, Linux Security Assessment

Created by: m0ogly@proton.me
Version: 1.0 - Intelligence Edition
License: Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)

⚖️  LICENSE NOTICE:
   This work is licensed under Creative Commons Attribution-NonCommercial 4.0 International.
   You are free to share and adapt this work for NON-COMMERCIAL purposes only.
   Commercial use, including but not limited to selling, licensing, or using this tool 
   for commercial gain is strictly prohibited without explicit written permission.
   
   Contact m0ogly@proton.me for commercial licensing inquiries.

🎯 CORE CAPABILITIES:
- 🔍 Advanced Domain Intelligence Collection
- 🛡️  Security Configuration Analysis  
- 🧭 Multi-Source Intelligence Gathering
- 🤖 AI-Ready Data Export & Analysis
- 📊 Comprehensive Ownership Attribution
- 🌐 Cloud Infrastructure Assessment (AWS, Azure, GCP)
- 🔒 Active Directory Security Analysis
- 📧 Exchange Server Intelligence
- 🐧 Linux Security Configuration Review

🔧 TECHNICAL FEATURES:
- Certificate Transparency Integration
- WHOIS Intelligence Collection
- DNS Pattern Analysis
- Network Infrastructure Mapping
- SSL/TLS Security Assessment
- Multi-threaded Operations
- Rate Limiting & Stealth Mode
- Comprehensive Logging
- Multiple Export Formats

💡 INTELLIGENCE ANALYSIS:
   JARVIS collects and correlates data from multiple sources to provide
   comprehensive security intelligence for infrastructure assessment and
   vulnerability research. Perfect for cybersecurity professionals.

📞 Support: m0ogly@proton.me
🌐 Specialized in: AWS • AD • Exchange • Linux Security
"""

# Standard library imports
import sys
import os
import re
import argparse
import time
import hashlib
import random
import multiprocessing
import threading
import socket
import json
import traceback
import tempfile
import signal
from datetime import datetime, timedelta
from collections import Counter, defaultdict, OrderedDict

# Enhanced logging system
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

# Python 2/3 compatibility
if sys.version_info[0] >= 3:
    import urllib.parse as urlparse
    import urllib.parse as urllib
    import urllib.request as urllib_request
    import queue
    from urllib.parse import quote
else:
    import urlparse
    import urllib
    import urllib2 as urllib_request
    import Queue as queue
    from urllib import quote

# External modules with fallback handling
try:
    from subbrute import subbrute
except ImportError:
    print("Warning: subbrute module not found. Bruteforce functionality disabled.")
    subbrute = None

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    print("Warning: dnspython not available. Some DNS features disabled.")
    DNS_AVAILABLE = False

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQUESTS_AVAILABLE = True
except ImportError:
    print("Warning: requests module not available. HTTP enumeration disabled.")
    REQUESTS_AVAILABLE = False

# Configuration management
class ConfigManager:
    """Gestionnaire de configuration pour les APIs et paramètres."""
    
    def __init__(self, config_file="config.json"):
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
        """Configuration par défaut."""
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
        """Récupère la clé API pour un service."""
        return self.config.get("api_keys", {}).get(service, {}).get("api_key", "")
    
    def is_service_enabled(self, service):
        """Vérifie si un service est activé."""
        api_config = self.config.get("api_keys", {}).get(service, {})
        endpoint_config = self.config.get("endpoints", {}).get(service, {})
        
        # Priorité aux endpoints (services gratuits)
        if endpoint_config:
            return endpoint_config.get("enabled", False)
        
        # Sinon vérifier si API key est disponible et activée
        return api_config.get("enabled", False) and bool(api_config.get("api_key", ""))
    
    def get_endpoint(self, service):
        """Récupère l'endpoint pour un service."""
        return self.config.get("endpoints", {}).get(service, {}).get("api_url", "")
    
    def get_setting(self, key, default=None):
        """Récupère un paramètre de configuration."""
        return self.config.get("settings", {}).get(key, default)

# Instance globale du gestionnaire de configuration
config_manager = ConfigManager()

# Platform detection
is_windows = sys.platform.startswith('win')
is_linux = sys.platform.startswith('linux')
is_macos = sys.platform.startswith('darwin')

# Enhanced color system with fallback
class ColorSystem:
    """
    Système de couleurs avancé avec support multi-plateforme et fallback.
    """
    
    def __init__(self, enable_colors=True):
        """Initialise le système de couleurs."""
        self.enabled = enable_colors and self._supports_color()
        
        if self.enabled:
            self._setup_colors()
        else:
            self._disable_colors()
    
    def _supports_color(self):
        """Vérifie si les couleurs sont supportées."""
        try:
            # Windows color support
            if is_windows:
                try:
                    import win_unicode_console
                    import colorama
                    win_unicode_console.enable()
                    colorama.init()
                    return True
                except ImportError:
                    return False
            
            # Unix-like systems
            return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
            
        except Exception:
            return False
    
    def _setup_colors(self):
        """Configure les codes couleur."""
        self.GREEN = '\\033[92m'
        self.YELLOW = '\\033[93m'
        self.BLUE = '\\033[94m'
        self.RED = '\\033[91m'
        self.WHITE = '\\033[0m'
        self.CYAN = '\\033[96m'
        self.MAGENTA = '\\033[95m'
        self.BOLD = '\\033[1m'
        self.UNDERLINE = '\\033[4m'
        self.DIM = '\\033[2m'
    
    def _disable_colors(self):
        """Désactive les couleurs."""
        self.GREEN = ''
        self.YELLOW = ''
        self.BLUE = ''
        self.RED = ''
        self.WHITE = ''
        self.CYAN = ''
        self.MAGENTA = ''
        self.BOLD = ''
        self.UNDERLINE = ''
        self.DIM = ''
    
    def disable(self):
        """Désactive les couleurs."""
        self.enabled = False
        self._disable_colors()

# Instance globale du système de couleurs
colors = ColorSystem()

class EnhancedLogger:
    """
    Système de logging avancé pour JARVIS Intelligence.
    
    Features:
    - Niveaux de log détaillés
    - Rotation automatique des fichiers
    - Formatage personnalisé avec couleurs
    - Sauvegarde horodatée
    - Métriques intégrées
    """
    
    def __init__(self, name="JARVIS_Intelligence", log_dir="logs", debug=False):
        """Initialise le logger avancé."""
        try:
            self.name = name
            self.debug_enabled = debug
            self.log_dir = log_dir
            self.session_id = self._generate_session_id()
            
            # Créer le répertoire de logs
            self._ensure_log_directory()
            
            # Initialiser les loggers
            self._setup_loggers()
            
            # Métriques
            self.metrics = {
                'start_time': time.time(),
                'total_messages': 0,
                'messages_by_level': defaultdict(int),
                'errors_count': 0,
                'warnings_count': 0
            }
            
            self.info("Enhanced Logger initialized successfully", module="EnhancedLogger")
            
        except Exception as e:
            print("CRITICAL: Failed to initialize logger: {}".format(str(e)))
            print("Traceback: {}".format(traceback.format_exc()))
            raise
    
    def _generate_session_id(self):
        """Génère un ID unique pour cette session."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            random_part = str(hash(str(time.time())))[-6:]
            return "session_{}_{}_{}".format(timestamp, os.getpid(), random_part)
        except Exception:
            return "session_unknown"
    
    def _ensure_log_directory(self):
        """Assure que le répertoire de logs existe."""
        try:
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)
        except Exception as e:
            print("WARNING: Cannot create log directory {}: {}".format(self.log_dir, str(e)))
            self.log_dir = tempfile.gettempdir()
    
    def _setup_loggers(self):
        """Configure les loggers avec handlers appropriés."""
        try:
            # Logger principal
            self.logger = logging.getLogger(self.name)
            self.logger.setLevel(logging.DEBUG if self.debug_enabled else logging.INFO)
            self.logger.handlers.clear()
            
            # Format pour fichiers
            file_formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            # Format pour console
            console_formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(message)s',
                datefmt='%H:%M:%S'
            )
            
            # Handler pour fichier principal avec rotation
            main_log_file = os.path.join(self.log_dir, "sublist3r_main.log")
            main_handler = RotatingFileHandler(
                main_log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
            )
            main_handler.setLevel(logging.DEBUG)
            main_handler.setFormatter(file_formatter)
            self.logger.addHandler(main_handler)
            
            # Handler pour erreurs uniquement
            error_log_file = os.path.join(self.log_dir, "sublist3r_errors.log")
            error_handler = RotatingFileHandler(
                error_log_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
            )
            error_handler.setLevel(logging.WARNING)
            error_handler.setFormatter(file_formatter)
            self.logger.addHandler(error_handler)
            
            # Handler pour session horodatée
            session_log_file = os.path.join(self.log_dir, "session_{}.log".format(
                datetime.now().strftime("%Y%m%d_%H%M%S")
            ))
            session_handler = logging.FileHandler(session_log_file, encoding='utf-8')
            session_handler.setLevel(logging.INFO)
            session_handler.setFormatter(file_formatter)
            self.logger.addHandler(session_handler)
            
            # Handler pour console avec couleurs
            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setLevel(logging.INFO if not self.debug_enabled else logging.DEBUG)
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
            
        except Exception as e:
            print("CRITICAL: Failed to setup loggers: {}".format(str(e)))
            raise
    
    def _log_with_context(self, level, message, module=None, **kwargs):
        """Log avec contexte enrichi."""
        try:
            # Mettre à jour les métriques
            self.metrics['total_messages'] += 1
            self.metrics['messages_by_level'][level] += 1
            
            if level in ['ERROR', 'CRITICAL']:
                self.metrics['errors_count'] += 1
            elif level == 'WARNING':
                self.metrics['warnings_count'] += 1
            
            # Construire le message enrichi
            enriched_message = str(message)
            
            if module:
                enriched_message = "[{}] {}".format(module, enriched_message)
            
            if kwargs:
                extra_str = " | ".join("{}={}".format(k, v) for k, v in kwargs.items())
                enriched_message = "{} | {}".format(enriched_message, extra_str)
            
            # Logger selon le niveau
            logger_method = getattr(self.logger, level.lower(), self.logger.info)
            logger_method(enriched_message)
            
            # Affichage coloré dans le terminal si supporté
            if colors.enabled and hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
                color_map = {
                    'DEBUG': colors.CYAN,
                    'INFO': colors.GREEN,
                    'WARNING': colors.YELLOW,
                    'ERROR': colors.RED,
                    'CRITICAL': colors.MAGENTA
                }
                color = color_map.get(level, colors.WHITE)
                colored_message = "{}[{}]{} {}".format(color, level, colors.WHITE, enriched_message)
                print(colored_message, file=sys.stderr)
            
        except Exception as e:
            print("ERROR in _log_with_context: {}".format(str(e)))
    
    def debug(self, message, module=None, **kwargs):
        """Log debug avec contexte."""
        if self.debug_enabled:
            self._log_with_context('DEBUG', message, module, **kwargs)
    
    def info(self, message, module=None, **kwargs):
        """Log info avec contexte."""
        self._log_with_context('INFO', message, module, **kwargs)
    
    def warning(self, message, module=None, **kwargs):
        """Log warning avec contexte."""
        self._log_with_context('WARNING', message, module, **kwargs)
    
    def error(self, message, module=None, **kwargs):
        """Log error avec contexte."""
        self._log_with_context('ERROR', message, module, **kwargs)
    
    def critical(self, message, module=None, **kwargs):
        """Log critical avec contexte."""
        self._log_with_context('CRITICAL', message, module, **kwargs)
    
    def success(self, message, module=None, **kwargs):
        """Log success avec contexte."""
        self._log_with_context('INFO', "SUCCESS: {}".format(message), module, **kwargs)
    
    def get_metrics(self):
        """Retourne les métriques de logging."""
        try:
            uptime = time.time() - self.metrics['start_time']
            self.metrics['uptime_seconds'] = uptime
            return dict(self.metrics)
        except Exception as e:
            return {'error': str(e)}

class SecurityValidator:
    """
    Validateur de sécurité pour toutes les entrées utilisateur.
    
    Protège contre:
    - Injection de commandes
    - Directory traversal
    - Inputs malveillants
    - Domaines invalides
    """
    
    # Patterns dangereux
    DANGEROUS_PATTERNS = [
        r'[;&|`$()\\]',  # Caractères d'injection shell
        r'<script[^>]*>',  # Injection XSS
        r'javascript:',  # URL javascript
        r'\.\.[/\\]',  # Directory traversal
        r'\x00',  # Null bytes
        r'\$(\{|\()',  # Variable expansion
    ]
    
    # Pattern pour domaines valides
    DOMAIN_PATTERN = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    
    def __init__(self, logger=None):
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
        """Log d'événement de sécurité."""
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
            
            # Supprimer http/https si présent
            if sanitized.startswith(('http://', 'https://')):
                parsed = urlparse.urlparse(sanitized)
                sanitized = parsed.netloc or parsed.path
            
            # Vérifier la longueur
            if len(sanitized) > 253:
                self._log_security_event("DOMAIN_TOO_LONG", "Domain exceeds max length", domain=sanitized[:50])
                return False, None, "Domain name too long (max 253 characters)"
            
            if len(sanitized) < 3:
                return False, None, "Domain name too short (min 3 characters)"
            
            # Vérifier les patterns dangereux
            for pattern in self.compiled_patterns:
                if pattern.search(sanitized):
                    self._log_security_event("DANGEROUS_PATTERN", "Dangerous pattern in domain", 
                                           domain=sanitized, pattern=pattern.pattern)
                    return False, None, "Domain contains dangerous characters"
            
            # Vérifier le format avec regex
            if not self.domain_regex.match(sanitized):
                return False, None, "Invalid domain format"
            
            # Vérifier la blacklist
            if sanitized in self.blocked_domains:
                self._log_security_event("BLOCKED_DOMAIN", "Blocked domain attempted", domain=sanitized)
                return False, None, "Domain is blocked for security reasons"
            
            # Vérifier les parties du domaine
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
            
            # Vérifier les patterns dangereux
            for pattern in self.compiled_patterns:
                if pattern.search(clean_path):
                    self._log_security_event("DANGEROUS_PATH", "Dangerous pattern in path", path=clean_path)
                    return False, None, "File path contains dangerous characters"
            
            # Vérifier directory traversal
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
            
            # Vérifier les patterns dangereux
            for pattern in self.compiled_patterns:
                if pattern.search(ports_str):
                    self._log_security_event("DANGEROUS_PORTS", "Dangerous pattern in ports", ports=ports_str)
                    return False, [], "Ports string contains dangerous characters"
            
            # Parser les ports
            ports = []
            for port_str in ports_str.split(','):
                port_str = port_str.strip()
                
                # Vérifier si c'est un nombre
                if not port_str.isdigit():
                    return False, [], "Invalid port number: {}".format(port_str)
                
                port = int(port_str)
                
                # Vérifier la plage valide
                if port < 1 or port > 65535:
                    return False, [], "Port {} out of valid range (1-65535)".format(port)
                
                ports.append(port)
            
            # Limiter le nombre de ports pour éviter les abus
            if len(ports) > 100:
                self._log_security_event("TOO_MANY_PORTS", "Too many ports requested", count=len(ports))
                return False, [], "Too many ports (max 100)"
            
            return True, ports, None
            
        except Exception as e:
            self._log_security_event("PORT_VALIDATION_ERROR", "Port validation exception", error=str(e))
            return False, [], "Port validation error: {}".format(str(e))

class ProgressBar:
    """
    Barre de progression moderne et configurable.
    """
    
    def __init__(self, total=100, width=50, prefix="Progress", suffix="Complete", 
                 fill='█', empty='-', show_percent=True, show_count=True):
        """Initialise la barre de progression."""
        self.total = total
        self.width = width
        self.prefix = prefix
        self.suffix = suffix
        self.fill = fill
        self.empty = empty
        self.show_percent = show_percent
        self.show_count = show_count
        self.current = 0
        self.start_time = time.time()
        
    def update(self, current=None, increment=1):
        """Met à jour la barre de progression."""
        try:
            if current is not None:
                self.current = current
            else:
                self.current += increment
            
            # Assurer que current ne dépasse pas total
            self.current = min(self.current, self.total)
            
            # Calculer le pourcentage
            if self.total > 0:
                percent = (self.current / self.total) * 100
            else:
                percent = 0
            
            # Calculer le nombre de caractères remplis
            filled_length = int(self.width * self.current // self.total) if self.total > 0 else 0
            
            # Créer la barre
            bar = self.fill * filled_length + self.empty * (self.width - filled_length)
            
            # Construire le message
            message_parts = [self.prefix, "[{}]".format(bar)]
            
            if self.show_percent:
                message_parts.append("{:.1f}%".format(percent))
            
            if self.show_count:
                message_parts.append("({}/{})".format(self.current, self.total))
            
            # Calculer l'ETA
            elapsed = time.time() - self.start_time
            if self.current > 0 and self.current < self.total:
                eta = (elapsed * (self.total - self.current)) / self.current
                eta_str = "ETA: {:.0f}s".format(eta)
                message_parts.append(eta_str)
            
            message_parts.append(self.suffix)
            
            # Afficher
            message = " ".join(message_parts)
            
            # Effacer la ligne précédente et afficher la nouvelle
            sys.stdout.write('\\r' + ' ' * 80 + '\\r')  # Clear line
            sys.stdout.write(message)
            sys.stdout.flush()
            
            # Nouvelle ligne si terminé
            if self.current >= self.total:
                sys.stdout.write('\\n')
                sys.stdout.flush()
                
        except Exception as e:
            pass  # Ne pas interrompre le processus pour un problème d'affichage
    
    def finish(self):
        """Termine la barre de progression."""
        self.update(self.total)

# Instance globale des utilitaires
logger = None
security_validator = None

def initialize_globals(debug=False, no_color=False):
    """Initialise les instances globales."""
    global logger, security_validator, colors
    
    try:
        if no_color:
            colors.disable()
        
        logger = EnhancedLogger(debug=debug)
        security_validator = SecurityValidator(logger)
        
        logger.info("Global utilities initialized", module="Main")
        
    except Exception as e:
        print("CRITICAL: Failed to initialize globals: {}".format(str(e)))
        raise

def jarvis_banner():
    """Affiche le banner JARVIS avec bouclier et boussole."""
    banner_text = """{}{}
    🛡️                 _              _____   _____  🧭
    ⚔️               | |     /\\     |  __ \\ /  ___| 🗡️
      🔍           | |    /  \\    | |__) |\\ `--. 
                   | |   / /\\ \\   |  _  /  `--. \\
                  _| |_ / ____ \\  | | \\ \\ /\\__/ /
                 |_____/_/____\\_\\ |_|  \\_\\\\____/ 
                      
    {}🛡️  JARVIS - Just Another Robust Vulnerability Intelligence System{}
    {}🧭 Advanced Intelligence & Security Analysis Platform v1.0{}
    
    {}🚀 Professional Domain Intelligence & Configuration Analysis{}
    {}🔒 Specialized in: AWS • Active Directory • Exchange • Linux{}
    {}🤖 AI-Ready Intelligence Collection & Attribution Analysis{}
    {}📊 Multi-Source Data Correlation • WHOIS • DNS • Certificates{}
    
    {}⚖️  Non-Commercial License • Created by m0ogly@proton.me{}
    {}🎯 Cybersecurity Intelligence • Infrastructure Assessment{}
    
    """.format(
        colors.CYAN, colors.BOLD,
        colors.YELLOW, colors.WHITE,
        colors.GREEN, colors.WHITE,
        colors.BLUE, colors.WHITE,
        colors.MAGENTA, colors.WHITE,
        colors.RED, colors.WHITE,
        colors.CYAN, colors.WHITE,
        colors.DIM, colors.WHITE,
        colors.GREEN, colors.WHITE
    )
    
    print(banner_text)

def parser_error(errmsg):
    """Gestionnaire d'erreur personnalisé pour argparse."""
    try:
        jarvis_banner()
        print("{}Usage: python {} [Options] use -h for help{}".format(
            colors.YELLOW, sys.argv[0], colors.WHITE))
        print("{}Error: {}{}".format(colors.RED, errmsg, colors.WHITE))
        
        if logger:
            logger.error("Argument parsing error", module="ArgumentParser", error=errmsg)
        
        sys.exit(1)
        
    except Exception as e:
        print("CRITICAL: Error in parser_error: {}".format(str(e)))
        sys.exit(1)

def enhanced_parse_args():
    """Parser d'arguments amélioré avec validation."""
    try:
        parser = argparse.ArgumentParser(
            description="JARVIS Intelligence v1.0 - Professional Subdomain Enumeration Tool",
            epilog="Example: python {} -d google.com -v -o results.json --format json".format(sys.argv[0]),
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        parser.error = parser_error
        parser._optionals.title = "OPTIONS"
        
        # Options principales
        parser.add_argument('-d', '--domain', 
                          help="Domain name to enumerate subdomains (required)", 
                          required=True, metavar="DOMAIN")
        
        parser.add_argument('-b', '--bruteforce', 
                          help='Enable subbrute bruteforce module', 
                          action='store_true', default=False)
        
        parser.add_argument('-p', '--ports', 
                          help='Scan found subdomains against specified TCP ports (comma-separated)', 
                          metavar="PORTS")
        
        parser.add_argument('-v', '--verbose', 
                          help='Enable verbose output with real-time results', 
                          action='store_true', default=False)
        
        parser.add_argument('-t', '--threads', 
                          help='Number of threads for bruteforce (default: 30)', 
                          type=int, default=30, metavar="NUM")
        
        parser.add_argument('-e', '--engines', 
                          help='Comma-separated list of search engines to use or preset: fast, complete, free, apis', 
                          metavar="ENGINES")
        
        parser.add_argument('--preset', 
                          help='Use predefined engine combinations: fast, complete, free, apis, exhaustive', 
                          choices=['fast', 'complete', 'free', 'apis', 'exhaustive'], 
                          metavar="PRESET")
        
        parser.add_argument('--extract-emails', 
                          help='Extract emails from WHOIS and certificates', 
                          action='store_true', default=False)
        
        parser.add_argument('--extract-owners', 
                          help='Extract owner/organization information', 
                          action='store_true', default=False)
        
        parser.add_argument('--stats-file', 
                          help='Save detailed statistics to file', 
                          metavar="FILE")
        
        parser.add_argument('--include-ips', 
                          help='Include resolved IP addresses in output', 
                          action='store_true', default=False)
        
        parser.add_argument('--intelligence', 
                          help='Collect full domain intelligence for AI analysis (WHOIS, DNS, certificates, etc.)', 
                          action='store_true', default=False)
        
        parser.add_argument('--ai-export', 
                          help='Export data formatted for AI analysis', 
                          metavar="FILE")
        
        # Options de sortie améliorées
        parser.add_argument('-o', '--output', 
                          help='Save results to file', 
                          metavar="FILE")
        
        parser.add_argument('--format', 
                          help='Output format: txt, csv, json, xml, html (default: txt)', 
                          choices=['txt', 'csv', 'json', 'xml', 'html'], 
                          default='txt')
        
        parser.add_argument('--no-color', 
                          help='Disable colored output', 
                          action='store_true', default=False)
        
        # Options avancées
        parser.add_argument('--timeout', 
                          help='HTTP request timeout in seconds (default: 25)', 
                          type=int, default=25, metavar="SECONDS")
        
        parser.add_argument('--delay', 
                          help='Delay between requests in seconds (default: 0)', 
                          type=float, default=0, metavar="SECONDS")
        
        parser.add_argument('--user-agent', 
                          help='Custom User-Agent string', 
                          metavar="AGENT")
        
        parser.add_argument('--debug', 
                          help='Enable debug logging', 
                          action='store_true', default=False)
        
        parser.add_argument('--silent', 
                          help='Silent mode - only output results', 
                          action='store_true', default=False)
        
        parser.add_argument('--statistics', 
                          help='Show detailed statistics at the end', 
                          action='store_true', default=False)
        
        parser.add_argument('--save-session', 
                          help='Save session data for resuming', 
                          action='store_true', default=False)
        
        parser.add_argument('--load-session', 
                          help='Load previous session data', 
                          metavar="SESSION_FILE")
        
        return parser.parse_args()
        
    except SystemExit:
        raise
    except Exception as e:
        print("{}CRITICAL: Failed to parse arguments: {}{}".format(colors.RED, str(e), colors.WHITE))
        if logger:
            logger.critical("Argument parsing failed", module="ArgumentParser", error=str(e))
        sys.exit(1)

def write_file_enhanced(filename, subdomains, output_format='txt', metadata=None):
    """
    Écriture de fichier améliorée avec support multi-formats.
    
    Args:
        filename: Nom du fichier de sortie
        subdomains: Liste des sous-domaines
        output_format: Format de sortie (txt, csv, json, xml, html)
        metadata: Métadonnées à inclure
    """
    try:
        if not subdomains:
            logger.warning("No subdomains to write", module="FileWriter")
            return False
        
        # Validation du chemin de fichier
        is_valid, safe_filename, error_msg = security_validator.validate_file_path(filename)
        if not is_valid:
            logger.error("Invalid output filename", module="FileWriter", error=error_msg)
            return False
        
        logger.info("Writing {} subdomains to {} format".format(len(subdomains), output_format.upper()), 
                   module="FileWriter", filename=safe_filename)
        
        # Préparer les métadonnées par défaut
        default_metadata = {
            'timestamp': datetime.now().isoformat(),
            'total_subdomains': len(subdomains),
            'tool': 'JARVIS Intelligence v1.0',
            'format_version': '1.0'
        }
        
        if metadata:
            default_metadata.update(metadata)
        
        # Écriture selon le format
        if output_format == 'txt':
            return _write_txt(safe_filename, subdomains)
        elif output_format == 'csv':
            return _write_csv(safe_filename, subdomains, default_metadata)
        elif output_format == 'json':
            return _write_json(safe_filename, subdomains, default_metadata)
        elif output_format == 'xml':
            return _write_xml(safe_filename, subdomains, default_metadata)
        elif output_format == 'html':
            return _write_html(safe_filename, subdomains, default_metadata)
        else:
            logger.error("Unsupported output format", module="FileWriter", format=output_format)
            return False
            
    except Exception as e:
        logger.error("File writing failed", module="FileWriter", error=str(e))
        return False

def _write_txt(filename, subdomains):
    """Écriture au format texte."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for subdomain in subdomains:
                f.write(subdomain + os.linesep)
        return True
    except Exception as e:
        logger.error("TXT writing failed", module="FileWriter", error=str(e))
        return False

def _write_csv(filename, subdomains, metadata):
    """Écriture au format CSV."""
    try:
        import csv
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # En-têtes avec métadonnées
            writer.writerow(['# JARVIS Intelligence Results'])
            writer.writerow(['# Generated:', metadata.get('timestamp', 'Unknown')])
            writer.writerow(['# Total Subdomains:', metadata.get('total_subdomains', 0)])
            writer.writerow([])  # Ligne vide
            
            # En-têtes des données
            writer.writerow(['Subdomain', 'Discovery_Time', 'Status'])
            
            # Données
            for subdomain in subdomains:
                writer.writerow([subdomain, datetime.now().strftime('%H:%M:%S'), 'Found'])
        
        return True
    except Exception as e:
        logger.error("CSV writing failed", module="FileWriter", error=str(e))
        return False

def _write_json(filename, subdomains, metadata):
    """Écriture au format JSON."""
    try:
        data = {
            'metadata': metadata,
            'subdomains': [
                {
                    'domain': subdomain,
                    'discovered_at': datetime.now().isoformat(),
                    'status': 'active'
                }
                for subdomain in subdomains
            ]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        return True
    except Exception as e:
        logger.error("JSON writing failed", module="FileWriter", error=str(e))
        return False

def _write_xml(filename, subdomains, metadata):
    """Écriture au format XML."""
    try:
        import xml.etree.ElementTree as ET
        
        # Créer la structure XML
        root = ET.Element('sublist3r_results', version='2.1')
        
        # Métadonnées
        meta_elem = ET.SubElement(root, 'metadata')
        for key, value in metadata.items():
            elem = ET.SubElement(meta_elem, key)
            elem.text = str(value)
        
        # Résultats
        results_elem = ET.SubElement(root, 'subdomains')
        for subdomain in subdomains:
            subdomain_elem = ET.SubElement(results_elem, 'subdomain')
            subdomain_elem.set('discovered_at', datetime.now().isoformat())
            subdomain_elem.text = subdomain
        
        # Écriture avec indentation
        _indent_xml(root)
        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)
        
        return True
    except Exception as e:
        logger.error("XML writing failed", module="FileWriter", error=str(e))
        return False

def _write_html(filename, subdomains, metadata):
    """Écriture au format HTML."""
    try:
        html_template = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JARVIS Intelligence Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .metadata {{ background: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; 
                     box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .results {{ background: white; border-radius: 5px; overflow: hidden; 
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background-color: #4CAF50; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 12px; border-bottom: 1px solid #ddd; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #e8f5e8; }}
        .count {{ font-size: 24px; font-weight: bold; color: #4CAF50; }}
        .footer {{ text-align: center; margin-top: 20px; color: #666; }}
        .search-box {{ margin: 20px 0; }}
        .search-box input {{ padding: 10px; width: 300px; border: 1px solid #ddd; border-radius: 5px; }}
    </style>
    <script>
        function searchSubdomains() {{
            var input = document.getElementById('searchInput');
            var filter = input.value.toUpperCase();
            var table = document.getElementById('subdomainsTable');
            var rows = table.getElementsByTagName('tr');
            
            for (var i = 1; i < rows.length; i++) {{
                var cell = rows[i].getElementsByTagName('td')[0];
                if (cell) {{
                    var textValue = cell.textContent || cell.innerText;
                    if (textValue.toUpperCase().indexOf(filter) > -1) {{
                        rows[i].style.display = '';
                    }} else {{
                        rows[i].style.display = 'none';
                    }}
                }}
            }}
        }}
    </script>
</head>
<body>
    <div class="header">
        <h1>🎯 JARVIS Intelligence Results</h1>
        <p>Professional Subdomain Enumeration Report</p>
    </div>
    
    <div class="metadata">
        <h2>📊 Metadata</h2>
        <p><strong>Generated:</strong> {timestamp}</p>
        <p><strong>Total Subdomains:</strong> <span class="count">{total_subdomains}</span></p>
        <p><strong>Tool:</strong> {tool}</p>
    </div>
    
    <div class="search-box">
        <input type="text" id="searchInput" onkeyup="searchSubdomains()" 
               placeholder="🔍 Search subdomains...">
    </div>
    
    <div class="results">
        <table id="subdomainsTable">
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>Discovery Time</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    </div>
    
    <div class="footer">
        <p>Generated by <strong>JARVIS Intelligence v1.0</strong> - Enhanced Security Edition</p>
        <p>Original tool by Ahmed Aboul-Ela - Enhanced by Security Team</p>
    </div>
</body>
</html>"""
        
        # Générer les lignes du tableau
        table_rows = ""
        discovery_time = datetime.now().strftime('%H:%M:%S')
        
        for subdomain in subdomains:
            table_rows += "<tr><td>{}</td><td>{}</td><td>✅ Active</td></tr>\\n".format(
                subdomain, discovery_time)
        
        # Remplacer les variables dans le template
        html_content = html_template.format(
            timestamp=metadata.get('timestamp', 'Unknown'),
            total_subdomains=metadata.get('total_subdomains', 0),
            tool=metadata.get('tool', 'JARVIS Intelligence'),
            table_rows=table_rows
        )
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return True
    except Exception as e:
        logger.error("HTML writing failed", module="FileWriter", error=str(e))
        return False

def _indent_xml(elem, level=0):
    """Indente le XML pour un affichage lisible."""
    try:
        i = "\\n" + level * "  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
            for elem in elem:
                _indent_xml(elem, level + 1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i
    except Exception:
        pass  # Continue even if indentation fails

def subdomain_sorting_key_enhanced(hostname):
    """
    Clé de tri améliorée pour les sous-domaines.
    
    Trie par:
    1. Domaine de droite à gauche
    2. 'www' en premier dans chaque groupe
    3. Ordre alphabétique pour les autres
    """
    try:
        if not hostname or not isinstance(hostname, str):
            return ([], 999)  # Mettre les entrées invalides à la fin
        
        parts = hostname.lower().split('.')[::-1]  # Inverser pour trier de droite à gauche
        
        # Prioriser 'www' dans chaque niveau
        if len(parts) > 1 and parts[-1] == 'www':
            return (parts[:-1], 0, parts[-1])  # 'www' en premier
        
        return (parts, 1, '')  # Autres sous-domaines après 'www'
        
    except Exception as e:
        logger.error("Sorting key generation failed", module="Sorting", hostname=hostname, error=str(e))
        return ([], 999)  # Fallback pour les erreurs

class EnhancedEnumeratorBase(object):
    """
    Classe de base améliorée pour tous les énumérateurs.
    
    Améliorations:
    - Gestion d'erreurs robuste
    - Rate limiting intelligent
    - Retry avec backoff exponentiel
    - Métriques détaillées
    - User-Agent rotation
    - Timeout adaptatif
    """
    
    def __init__(self, base_url, engine_name, domain, subdomains=None, 
                 silent=False, verbose=True, timeout=25, delay=0, user_agent=None):
        """Initialise l'énumérateur de base."""
        try:
            subdomains = subdomains or []
            self.domain = self._extract_domain(domain)
            self.original_domain = domain
            
            # Configuration de session
            if REQUESTS_AVAILABLE:
                self.session = requests.Session()
                self.session.verify = True  # Vérification SSL par défaut
            else:
                self.session = None
                logger.warning("Requests not available, using urllib fallback", module=engine_name)
            
            self.subdomains = set()  # Utiliser un set pour éviter les doublons
            self.timeout = max(timeout, 5)  # Minimum 5 secondes
            self.base_url = base_url
            self.engine_name = engine_name
            self.silent = silent
            self.verbose = verbose
            self.delay = max(delay, 0)
            
            # User-Agent avec rotation
            self.user_agents = [
                user_agent if user_agent else 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
            ]
            self.current_ua_index = 0
            
            # Headers avec rotation
            self.base_headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0',
            }
            
            # Métriques
            self.metrics = {
                'requests_sent': 0,
                'requests_successful': 0,
                'requests_failed': 0,
                'subdomains_found': 0,
                'start_time': time.time(),
                'errors': [],
                'rate_limited': 0,
                'timeouts': 0
            }
            
            # Configuration rate limiting
            self.last_request_time = 0
            self.consecutive_failures = 0
            self.max_consecutive_failures = 5
            self.backoff_factor = 1.5
            self.current_delay = self.delay
            
            # Afficher le banner
            self.print_banner()
            
            logger.debug("Enumerator initialized", module=engine_name, 
                        domain=self.domain, timeout=self.timeout)
            
        except Exception as e:
            logger.error("Enumerator initialization failed", module=engine_name, error=str(e))
            raise
    
    def _extract_domain(self, domain):
        """Extrait le domaine propre depuis une URL ou domaine."""
        try:
            if not domain:
                return ""
            
            # Valider avec le security validator
            is_valid, clean_domain, error_msg = security_validator.validate_domain(domain)
            if not is_valid:
                raise ValueError("Invalid domain: {}".format(error_msg))
            
            # Parser l'URL si nécessaire
            if domain.startswith(('http://', 'https://')):
                parsed = urlparse.urlparse(domain)
                return parsed.netloc
            
            return clean_domain
            
        except Exception as e:
            logger.error("Domain extraction failed", module=self.engine_name, 
                        domain=domain, error=str(e))
            raise
    
    def _get_headers(self):
        """Retourne les headers avec User-Agent en rotation."""
        try:
            headers = self.base_headers.copy()
            headers['User-Agent'] = self.user_agents[self.current_ua_index]
            
            # Rotation du User-Agent
            self.current_ua_index = (self.current_ua_index + 1) % len(self.user_agents)
            
            return headers
            
        except Exception as e:
            logger.error("Header generation failed", module=self.engine_name, error=str(e))
            return self.base_headers
    
    def _apply_rate_limiting(self):
        """Applique le rate limiting intelligent."""
        try:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            
            # Délai adaptatif basé sur les échecs consécutifs
            required_delay = self.current_delay * (self.backoff_factor ** self.consecutive_failures)
            required_delay = min(required_delay, 10)  # Maximum 10 secondes
            
            if time_since_last < required_delay:
                sleep_time = required_delay - time_since_last
                if sleep_time > 0:
                    logger.debug("Rate limiting applied", module=self.engine_name, 
                               sleep_time=sleep_time, consecutive_failures=self.consecutive_failures)
                    time.sleep(sleep_time)
            
            self.last_request_time = time.time()
            
        except Exception as e:
            logger.error("Rate limiting failed", module=self.engine_name, error=str(e))
    
    def print_(self, text):
        """Affichage avec gestion des erreurs."""
        try:
            if not self.silent:
                print(text)
        except Exception as e:
            logger.error("Print failed", module=self.engine_name, error=str(e))
    
    def print_banner(self):
        """Affiche le banner du moteur."""
        try:
            if not self.silent:
                banner_text = "{}[{}] Searching in {}{}".format(
                    colors.GREEN, 
                    datetime.now().strftime("%H:%M:%S"),
                    self.engine_name, 
                    colors.WHITE
                )
                self.print_(banner_text)
        except Exception as e:
            logger.error("Banner printing failed", module=self.engine_name, error=str(e))
    
    def send_req(self, query, page_no=1, retries=3):
        """
        Envoi de requête amélioré avec retry et gestion d'erreurs.
        
        Args:
            query: Requête à envoyer
            page_no: Numéro de page
            retries: Nombre de tentatives
            
        Returns:
            Réponse ou None en cas d'échec
        """
        response = None
        last_error = None
        
        for attempt in range(retries + 1):
            try:
                # Appliquer le rate limiting
                self._apply_rate_limiting()
                
                # Construire l'URL
                url = self.base_url.format(domain=self.domain, query=quote(query), page_no=page_no)
                logger.debug("Sending request", module=self.engine_name, 
                           url=url[:100], attempt=attempt + 1)
                
                # Incrémenter le compteur de requêtes
                self.metrics['requests_sent'] += 1
                
                # Envoyer la requête
                if self.session and REQUESTS_AVAILABLE:
                    response = self.session.get(
                        url, 
                        headers=self._get_headers(),
                        timeout=self.timeout,
                        allow_redirects=True
                    )
                    
                    # Vérifier le code de statut
                    if response.status_code == 200:
                        self.metrics['requests_successful'] += 1
                        self.consecutive_failures = 0
                        return self.get_response(response)
                    elif response.status_code == 429:  # Too Many Requests
                        self.metrics['rate_limited'] += 1
                        self.consecutive_failures += 1
                        logger.warning("Rate limited by server", module=self.engine_name, 
                                     status_code=response.status_code)
                        if attempt < retries:
                            time.sleep(2 ** attempt)  # Backoff exponentiel
                            continue
                    else:
                        logger.warning("HTTP error", module=self.engine_name, 
                                     status_code=response.status_code, url=url[:50])
                else:
                    # Fallback urllib
                    req = urllib_request.Request(url, headers=self._get_headers())
                    response = urllib_request.urlopen(req, timeout=self.timeout)
                    self.metrics['requests_successful'] += 1
                    self.consecutive_failures = 0
                    return self.get_response(response)
                    
            except requests.exceptions.Timeout if REQUESTS_AVAILABLE else socket.timeout:
                self.metrics['timeouts'] += 1
                last_error = "Request timeout"
                logger.warning("Request timeout", module=self.engine_name, 
                             attempt=attempt + 1, timeout=self.timeout)
                
            except requests.exceptions.ConnectionError if REQUESTS_AVAILABLE else (socket.error, urllib_request.URLError):
                last_error = "Connection error"
                logger.warning("Connection error", module=self.engine_name, attempt=attempt + 1)
                
            except Exception as e:
                last_error = str(e)
                logger.error("Request failed", module=self.engine_name, 
                           attempt=attempt + 1, error=str(e))
            
            # Attendre avant la prochaine tentative
            if attempt < retries:
                wait_time = (2 ** attempt) + random.uniform(0, 1)
                time.sleep(wait_time)
        
        # Toutes les tentatives ont échoué
        self.metrics['requests_failed'] += 1
        self.consecutive_failures += 1
        self.metrics['errors'].append({
            'timestamp': datetime.now().isoformat(),
            'error': last_error,
            'query': query[:50] if query else 'None'
        })
        
        logger.error("All request attempts failed", module=self.engine_name, 
                   retries=retries, last_error=last_error)
        
        return None
    
    def get_response(self, response):
        """Traite la réponse de la requête."""
        try:
            if response is None:
                return None
            
            # Pour requests
            if hasattr(response, 'text'):
                return response.text
            # Pour urllib
            elif hasattr(response, 'read'):
                content = response.read()
                if isinstance(content, bytes):
                    try:
                        return content.decode('utf-8')
                    except UnicodeDecodeError:
                        return content.decode('latin-1', errors='ignore')
                return content
            # Fallback
            else:
                return str(response)
                
        except Exception as e:
            logger.error("Response processing failed", module=self.engine_name, error=str(e))
            return None
    
    def add_subdomain(self, subdomain):
        """
        Ajoute un sous-domaine avec validation.
        
        Args:
            subdomain: Sous-domaine à ajouter
            
        Returns:
            bool: True si ajouté, False sinon
        """
        try:
            if not subdomain or not isinstance(subdomain, str):
                return False
            
            # Nettoyer le sous-domaine
            cleaned = subdomain.strip().lower()
            
            # Vérifier que c'est un sous-domaine valide du domaine cible
            if not cleaned.endswith('.' + self.domain) and cleaned != self.domain:
                return False
            
            # Éviter les caractères suspects
            if any(char in cleaned for char in ['*', '@', '<', '>', '[', ']']):
                return False
            
            # Vérifier si c'est nouveau
            if cleaned in self.subdomains or cleaned == self.domain:
                return False
            
            # Ajouter à la liste
            self.subdomains.add(cleaned)
            self.metrics['subdomains_found'] += 1
            
            # Affichage verbose
            if self.verbose and not self.silent:
                result_text = "{}[{}]{} {}Found:{} {}{}".format(
                    colors.BLUE,
                    datetime.now().strftime("%H:%M:%S"),
                    colors.WHITE,
                    colors.GREEN,
                    colors.WHITE,
                    cleaned,
                    colors.WHITE
                )
                self.print_(result_text)
            
            logger.debug("Subdomain added", module=self.engine_name, subdomain=cleaned)
            return True
            
        except Exception as e:
            logger.error("Subdomain addition failed", module=self.engine_name, 
                       subdomain=subdomain, error=str(e))
            return False
    
    def should_continue(self):
        """Détermine si l'énumération doit continuer."""
        try:
            # Arrêter si trop d'échecs consécutifs
            if self.consecutive_failures >= self.max_consecutive_failures:
                logger.warning("Too many consecutive failures, stopping", 
                             module=self.engine_name, failures=self.consecutive_failures)
                return False
            
            # Arrêter si le taux d'échec est trop élevé
            total_requests = self.metrics['requests_sent']
            if total_requests > 10:
                failure_rate = self.metrics['requests_failed'] / total_requests
                if failure_rate > 0.8:  # Plus de 80% d'échecs
                    logger.warning("High failure rate, stopping", 
                                 module=self.engine_name, failure_rate=failure_rate)
                    return False
            
            return True
            
        except Exception as e:
            logger.error("Continue check failed", module=self.engine_name, error=str(e))
            return False
    
    def get_metrics(self):
        """Retourne les métriques de l'énumérateur."""
        try:
            current_time = time.time()
            elapsed = current_time - self.metrics['start_time']
            
            metrics = self.metrics.copy()
            metrics['elapsed_time'] = elapsed
            metrics['requests_per_second'] = metrics['requests_sent'] / elapsed if elapsed > 0 else 0
            metrics['success_rate'] = (metrics['requests_successful'] / metrics['requests_sent'] 
                                     if metrics['requests_sent'] > 0 else 0)
            
            return metrics
            
        except Exception as e:
            logger.error("Metrics calculation failed", module=self.engine_name, error=str(e))
            return self.metrics
    
    # Méthodes virtuelles à surcharger
    def extract_domains(self, resp):
        """À surcharger par les classes enfant."""
        raise NotImplementedError("extract_domains must be implemented by subclass")
    
    def check_response_errors(self, resp):
        """À surcharger par les classes enfant."""
        return resp is not None
    
    def generate_query(self):
        """À surcharger par les classes enfant."""
        raise NotImplementedError("generate_query must be implemented by subclass")
    
    def enumerate(self):
        """Méthode d'énumération de base."""
        try:
            logger.info("Starting enumeration", module=self.engine_name, domain=self.domain)
            
            # Logique d'énumération basique - à surcharger par les classes enfant
            query = self.generate_query()
            if not query:
                logger.warning("No query generated", module=self.engine_name)
                return list(self.subdomains)
            
            resp = self.send_req(query)
            if resp and self.check_response_errors(resp):
                self.extract_domains(resp)
            
            result_list = list(self.subdomains)
            logger.info("Enumeration completed", module=self.engine_name, 
                       found=len(result_list))
            
            return result_list
            
        except Exception as e:
            logger.error("Enumeration failed", module=self.engine_name, error=str(e))
            return list(self.subdomains)

# Exemple d'implémentation pour Google (version simplifiée et sécurisée)
class EnhancedGoogleEnum(EnhancedEnumeratorBase):
    """
    Énumérateur Google amélioré et sécurisé.
    
    Note: L'utilisation de Google pour l'énumération automatisée peut violer
    leurs conditions d'utilisation. Cet exemple est à des fins éducatives.
    """
    
    def __init__(self, domain, **kwargs):
        try:
            base_url = "https://www.google.com/search?q=site:{domain}+-inurl:www&num=100&start={page_no}"
            super(EnhancedGoogleEnum, self).__init__(
                base_url, "Google", domain, **kwargs
            )
            self.MAX_PAGES = 5  # Limiter pour éviter d'être bloqué
            self.domain_pattern = re.compile(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', re.IGNORECASE)
            
        except Exception as e:
            logger.error("Google enumerator initialization failed", error=str(e))
            raise
    
    def generate_query(self):
        """Génère la requête de recherche."""
        try:
            return "site:{}".format(self.domain)
        except Exception as e:
            logger.error("Query generation failed", module=self.engine_name, error=str(e))
            return None
    
    def check_response_errors(self, resp):
        """Vérifie les erreurs dans la réponse."""
        try:
            if not resp:
                return False
            
            # Vérifier les indicateurs de blocage
            error_indicators = [
                "blocked", "captcha", "unusual traffic", 
                "automated queries", "robot", "bot"
            ]
            
            resp_lower = resp.lower()
            for indicator in error_indicators:
                if indicator in resp_lower:
                    logger.warning("Possible blocking detected", module=self.engine_name, 
                                 indicator=indicator)
                    return False
            
            return True
            
        except Exception as e:
            logger.error("Response error check failed", module=self.engine_name, error=str(e))
            return False
    
    def extract_domains(self, resp):
        """Extrait les domaines de la réponse."""
        try:
            if not resp:
                return
            
            # Utiliser regex pour extraire les domaines
            matches = self.domain_pattern.findall(resp)
            
            for match in matches:
                subdomain = match.strip().lower()
                
                # Validation supplémentaire
                if (subdomain != self.domain and 
                    subdomain.endswith('.' + self.domain) and
                    not any(char in subdomain for char in ['<', '>', '"', "'"])):
                    
                    self.add_subdomain(subdomain)
            
        except Exception as e:
            logger.error("Domain extraction failed", module=self.engine_name, error=str(e))

class PlaywrightGoogleEnum(EnhancedEnumeratorBase):
    """
    Énumérateur Google utilisant Playwright pour contourner la détection de bot.
    """
    
    def __init__(self, domain, **kwargs):
        try:
            base_url = "https://www.google.com/search?q=site:{domain}+-inurl:www&num=100&start={page_no}"
            super(PlaywrightGoogleEnum, self).__init__(
                base_url, "GooglePlaywright", domain, **kwargs
            )
            self.MAX_PAGES = 3
            self.domain_pattern = re.compile(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', re.IGNORECASE)
            self.browser = None
            self.page = None
            
        except Exception as e:
            logger.error("Playwright Google enumerator initialization failed", error=str(e))
            raise
    
    def _init_browser(self):
        """Initialise le navigateur Playwright"""
        try:
            from playwright.sync_api import sync_playwright
            
            if not hasattr(self, 'playwright'):
                self.playwright = sync_playwright().start()
                
            if not self.browser:
                self.browser = self.playwright.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-blink-features=AutomationControlled',
                        '--disable-web-security',
                        '--disable-features=VizDisplayCompositor'
                    ]
                )
                
                context = self.browser.new_context(
                    user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                    viewport={'width': 1920, 'height': 1080}
                )
                
                self.page = context.new_page()
                
                # Masquer les signes d'automatisation
                self.page.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => false,
                    });
                """)
                
            return True
            
        except ImportError:
            logger.error("Playwright not available", module=self.engine_name)
            return False
        except Exception as e:
            logger.error("Browser initialization failed", module=self.engine_name, error=str(e))
            return False
    
    def _cleanup_browser(self):
        """Nettoie les ressources du navigateur"""
        try:
            if self.page:
                self.page.close()
                self.page = None
            if self.browser:
                self.browser.close()
                self.browser = None
            if hasattr(self, 'playwright'):
                self.playwright.stop()
                delattr(self, 'playwright')
        except Exception as e:
            logger.warning("Browser cleanup failed", module=self.engine_name, error=str(e))
    
    def send_req(self, query, page_no=1, retries=3):
        """Envoi de requête via Playwright"""
        try:
            if not self._init_browser():
                return None
                
            # Construire l'URL
            url = f"https://www.google.com/search?q=site:{self.domain}+{query}&num=100&start={(page_no-1)*10}"
            
            logger.info("Navigating to URL", module=self.engine_name, url=url[:100])
            
            # Naviguer vers la page
            response = self.page.goto(url, wait_until='networkidle', timeout=30000)
            
            if response and response.status == 200:
                # Attendre que la page soit chargée
                self.page.wait_for_selector('div#search', timeout=10000)
                
                # Obtenir le contenu HTML
                content = self.page.content()
                self.metrics['requests_successful'] += 1
                self.consecutive_failures = 0
                
                logger.info("Page loaded successfully", module=self.engine_name, 
                          content_length=len(content), title=self.page.title())
                
                return content
            else:
                logger.warning("HTTP error", module=self.engine_name, 
                             status_code=response.status if response else 'None')
                return None
                
        except Exception as e:
            logger.error("Playwright request failed", module=self.engine_name, error=str(e))
            self.metrics['requests_failed'] += 1
            self.consecutive_failures += 1
            return None
    
    def generate_query(self):
        """Génère la requête de recherche"""
        try:
            if self.subdomains:
                # Exclure les sous-domaines déjà trouvés
                excluded = ' -'.join([f'site:{sub}' for sub in list(self.subdomains)[:10]])
                return f"-www.{self.domain} -{excluded}"
            else:
                return f"-www.{self.domain}"
        except Exception as e:
            logger.error("Query generation failed", module=self.engine_name, error=str(e))
            return f"-www.{self.domain}"
    
    def check_response_errors(self, resp):
        """Vérifie les erreurs dans la réponse"""
        try:
            if not resp:
                return False
            
            # Vérifier les indicateurs de blocage
            error_indicators = [
                "unusual traffic", "captcha", "automated queries", 
                "our systems have detected", "please try again"
            ]
            
            resp_lower = resp.lower()
            for indicator in error_indicators:
                if indicator in resp_lower:
                    logger.warning("Possible blocking detected", 
                                 module=self.engine_name, indicator=indicator)
                    return False
            
            return True
            
        except Exception as e:
            logger.error("Response error check failed", module=self.engine_name, error=str(e))
            return False
    
    def extract_domains(self, resp):
        """Extrait les domaines de la réponse HTML Google"""
        try:
            if not resp:
                return
            
            # Parser avec BeautifulSoup si disponible, sinon regex
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp, 'html.parser')
                
                # Rechercher dans les liens de résultats
                for link in soup.find_all('a', href=True):
                    href = link.get('href', '')
                    if '/url?q=' in href:
                        # Extraire l'URL réelle
                        start = href.find('/url?q=') + 8
                        end = href.find('&', start)
                        if end == -1:
                            end = len(href)
                        url = href[start:end]
                        
                        # Extraire le domaine
                        try:
                            from urllib.parse import urlparse
                            parsed = urlparse(url)
                            domain = parsed.netloc.lower()
                            
                            if (domain.endswith('.' + self.domain) and 
                                domain != self.domain and 
                                domain not in self.subdomains):
                                self.add_subdomain(domain)
                        except:
                            pass
                            
            except ImportError:
                # Fallback regex si BeautifulSoup n'est pas disponible
                matches = self.domain_pattern.findall(resp)
                for match in matches:
                    subdomain = match.strip().lower()
                    if (subdomain != self.domain and 
                        subdomain.endswith('.' + self.domain) and
                        subdomain not in self.subdomains):
                        self.add_subdomain(subdomain)
            
        except Exception as e:
            logger.error("Domain extraction failed", module=self.engine_name, error=str(e))
    
    def enumerate(self):
        """Méthode d'énumération avec Playwright"""
        try:
            logger.info("Starting Playwright enumeration", module=self.engine_name, domain=self.domain)
            
            for page in range(1, self.MAX_PAGES + 1):
                if not self.should_continue():
                    break
                    
                query = self.generate_query()
                if not query:
                    break
                    
                resp = self.send_req(query, page_no=page)
                if resp and self.check_response_errors(resp):
                    self.extract_domains(resp)
                    
                    # Attendre entre les pages
                    if page < self.MAX_PAGES:
                        time.sleep(random.uniform(2, 4))
                else:
                    break
            
            result_list = list(self.subdomains)
            logger.info("Playwright enumeration completed", module=self.engine_name, 
                       found=len(result_list))
            
            return result_list
            
        except Exception as e:
            logger.error("Playwright enumeration failed", module=self.engine_name, error=str(e))
            return list(self.subdomains)
        finally:
            self._cleanup_browser()

class CertificateTransparencyEnum(EnhancedEnumeratorBase):
    """
    Énumérateur utilisant Certificate Transparency Logs (crt.sh)
    Très efficace car pas de détection de bot et données réelles
    """
    
    def __init__(self, domain, **kwargs):
        try:
            base_url = "https://crt.sh/?q=%.{domain}&output=json"
            super(CertificateTransparencyEnum, self).__init__(
                base_url, "CertificateTransparency", domain, **kwargs
            )
            self.api_endpoints = [
                "https://crt.sh/?q=%.{domain}&output=json",
                "https://crt.sh/?q={domain}&output=json",
                "https://crt.sh/?q=%.%.{domain}&output=json"  # Pour les sous-domaines profonds
            ]
            
        except Exception as e:
            logger.error("Certificate Transparency enumerator initialization failed", error=str(e))
            raise
    
    def send_req(self, query, page_no=1, retries=3):
        """Envoi de requête vers l'API Certificate Transparency"""
        try:
            # Construire l'URL de l'API
            url = query.format(domain=self.domain)
            
            logger.info("Querying Certificate Transparency", module=self.engine_name, url=url)
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive'
            }
            
            if self.session and REQUESTS_AVAILABLE:
                response = self.session.get(url, headers=headers, timeout=30)
                if response.status_code == 200:
                    self.metrics['requests_successful'] += 1
                    return response.json() if response.text.strip() else []
                else:
                    logger.warning("API error", module=self.engine_name, status_code=response.status_code)
                    return None
            else:
                # Fallback urllib
                req = urllib_request.Request(url, headers=headers)
                response = urllib_request.urlopen(req, timeout=30)
                import json
                data = response.read().decode('utf-8')
                return json.loads(data) if data.strip() else []
                
        except Exception as e:
            logger.error("Certificate Transparency request failed", module=self.engine_name, error=str(e))
            return None
    
    def extract_domains(self, cert_data):
        """Extrait les domaines des données de certificats"""
        try:
            if not cert_data:
                return
            
            found_count = 0
            for cert in cert_data:
                try:
                    # Extraire les noms du certificat
                    name_value = cert.get('name_value', '')
                    common_name = cert.get('common_name', '')
                    
                    # Traiter les noms multiples (séparés par \n)
                    names = []
                    if name_value:
                        names.extend([n.strip() for n in name_value.split('\n') if n.strip()])
                    if common_name:
                        names.append(common_name.strip())
                    
                    for name in names:
                        # Nettoyer le nom
                        name = name.lower().strip()
                        
                        # Supprimer les wildcards
                        if name.startswith('*.'):
                            name = name[2:]
                        
                        # Vérifier que c'est un sous-domaine valide
                        if (name.endswith('.' + self.domain) and 
                            name != self.domain and
                            '.' in name and
                            not any(char in name for char in ['<', '>', '"', "'", ' ', '\t']) and
                            len(name.split('.')) >= 2):  # Au moins un sous-domaine
                            
                            if self.add_subdomain(name):
                                found_count += 1
                                
                                # Extraire des informations supplémentaires du certificat
                                issuer = cert.get('issuer_name', '')
                                not_before = cert.get('not_before', '')
                                not_after = cert.get('not_after', '')
                                
                                logger.debug("Certificate found", module=self.engine_name,
                                           subdomain=name, issuer=issuer[:50] if issuer else '',
                                           valid_from=not_before, valid_to=not_after)
                
                except Exception as e:
                    logger.debug("Certificate parsing error", module=self.engine_name, error=str(e))
                    continue
            
            if found_count > 0:
                logger.info("Certificates processed", module=self.engine_name, 
                          total_certs=len(cert_data), domains_found=found_count)
            
        except Exception as e:
            logger.error("Certificate domain extraction failed", module=self.engine_name, error=str(e))
    
    def enumerate(self):
        """Énumération via Certificate Transparency"""
        try:
            logger.info("Starting Certificate Transparency enumeration", 
                       module=self.engine_name, domain=self.domain)
            
            all_domains = set()
            
            # Requêter tous les endpoints
            for endpoint in self.api_endpoints:
                try:
                    logger.info("Querying endpoint", module=self.engine_name, endpoint=endpoint)
                    
                    cert_data = self.send_req(endpoint)
                    if cert_data:
                        initial_count = len(self.subdomains)
                        self.extract_domains(cert_data)
                        new_count = len(self.subdomains) - initial_count
                        
                        logger.info("Endpoint completed", module=self.engine_name,
                                  endpoint=endpoint.split('/')[-1], 
                                  certificates=len(cert_data), new_domains=new_count)
                        
                        # Attendre entre les requêtes
                        time.sleep(1)
                    else:
                        logger.warning("No data from endpoint", module=self.engine_name, endpoint=endpoint)
                        
                except Exception as e:
                    logger.error("Endpoint query failed", module=self.engine_name, 
                               endpoint=endpoint, error=str(e))
                    continue
            
            result_list = list(self.subdomains)
            logger.info("Certificate Transparency enumeration completed", 
                       module=self.engine_name, found=len(result_list))
            
            return result_list
            
        except Exception as e:
            logger.error("Certificate Transparency enumeration failed", module=self.engine_name, error=str(e))
            return list(self.subdomains)

class SecurityTrailsEnum(EnhancedEnumeratorBase):
    """
    Énumérateur utilisant l'API SecurityTrails
    Nécessite une clé API mais très complet
    """
    
    def __init__(self, domain, api_key=None, **kwargs):
        try:
            base_url = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            super(SecurityTrailsEnum, self).__init__(
                base_url, "SecurityTrails", domain, **kwargs
            )
            self.api_key = api_key or kwargs.get('securitytrails_api_key')
            
        except Exception as e:
            logger.error("SecurityTrails enumerator initialization failed", error=str(e))
            raise
    
    def send_req(self, query, page_no=1, retries=3):
        """Envoi de requête vers l'API SecurityTrails"""
        try:
            if not self.api_key:
                logger.warning("SecurityTrails API key not provided", module=self.engine_name)
                return None
            
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            
            headers = {
                'APIKEY': self.api_key,
                'Content-Type': 'application/json',
                'User-Agent': 'JARVIS-Intelligence/2.1'
            }
            
            logger.info("Querying SecurityTrails API", module=self.engine_name)
            
            if self.session and REQUESTS_AVAILABLE:
                response = self.session.get(url, headers=headers, timeout=30)
                if response.status_code == 200:
                    self.metrics['requests_successful'] += 1
                    return response.json()
                elif response.status_code == 429:
                    logger.warning("SecurityTrails rate limit exceeded", module=self.engine_name)
                    return None
                elif response.status_code == 401:
                    logger.error("SecurityTrails API key invalid", module=self.engine_name)
                    return None
                else:
                    logger.warning("SecurityTrails API error", module=self.engine_name, 
                                 status_code=response.status_code)
                    return None
            
        except Exception as e:
            logger.error("SecurityTrails request failed", module=self.engine_name, error=str(e))
            return None
    
    def extract_domains(self, api_data):
        """Extrait les domaines des données SecurityTrails"""
        try:
            if not api_data or 'subdomains' not in api_data:
                return
            
            subdomains = api_data.get('subdomains', [])
            found_count = 0
            
            for subdomain in subdomains:
                try:
                    # Construire le FQDN
                    full_domain = f"{subdomain}.{self.domain}".lower()
                    
                    if self.add_subdomain(full_domain):
                        found_count += 1
                        
                except Exception as e:
                    logger.debug("Subdomain processing error", module=self.engine_name, error=str(e))
                    continue
            
            logger.info("SecurityTrails data processed", module=self.engine_name, 
                       total_subdomains=len(subdomains), domains_found=found_count)
            
        except Exception as e:
            logger.error("SecurityTrails domain extraction failed", module=self.engine_name, error=str(e))
    
    def enumerate(self):
        """Énumération via SecurityTrails"""
        try:
            logger.info("Starting SecurityTrails enumeration", module=self.engine_name, domain=self.domain)
            
            if not self.api_key:
                logger.warning("SecurityTrails skipped - no API key", module=self.engine_name)
                return list(self.subdomains)
            
            api_data = self.send_req("")
            if api_data:
                self.extract_domains(api_data)
            
            result_list = list(self.subdomains)
            logger.info("SecurityTrails enumeration completed", module=self.engine_name, found=len(result_list))
            
            return result_list
            
        except Exception as e:
            logger.error("SecurityTrails enumeration failed", module=self.engine_name, error=str(e))
            return list(self.subdomains)

class VirusTotalEnum(EnhancedEnumeratorBase):
    """
    Énumérateur utilisant l'API VirusTotal
    Nécessite une clé API gratuite
    """
    
    def __init__(self, domain, api_key=None, **kwargs):
        try:
            base_url = "https://www.virustotal.com/vtapi/v2/domain/report"
            super(VirusTotalEnum, self).__init__(
                base_url, "VirusTotal", domain, **kwargs
            )
            self.api_key = api_key or kwargs.get('virustotal_api_key')
            
        except Exception as e:
            logger.error("VirusTotal enumerator initialization failed", error=str(e))
            raise
    
    def send_req(self, query, page_no=1, retries=3):
        """Envoi de requête vers l'API VirusTotal"""
        try:
            if not self.api_key:
                logger.warning("VirusTotal API key not provided", module=self.engine_name)
                return None
            
            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': self.api_key,
                'domain': self.domain
            }
            
            logger.info("Querying VirusTotal API", module=self.engine_name)
            
            if self.session and REQUESTS_AVAILABLE:
                response = self.session.get(url, params=params, timeout=30)
                if response.status_code == 200:
                    self.metrics['requests_successful'] += 1
                    return response.json()
                elif response.status_code == 204:
                    logger.info("VirusTotal quota exceeded", module=self.engine_name)
                    return None
                else:
                    logger.warning("VirusTotal API error", module=self.engine_name, 
                                 status_code=response.status_code)
                    return None
            
        except Exception as e:
            logger.error("VirusTotal request failed", module=self.engine_name, error=str(e))
            return None
    
    def extract_domains(self, api_data):
        """Extrait les domaines des données VirusTotal"""
        try:
            if not api_data or api_data.get('response_code') != 1:
                return
            
            # Extraire les sous-domaines détectés
            subdomains = api_data.get('subdomains', [])
            found_count = 0
            
            for subdomain in subdomains:
                try:
                    subdomain = subdomain.lower().strip()
                    
                    if (subdomain.endswith('.' + self.domain) and 
                        subdomain != self.domain):
                        
                        if self.add_subdomain(subdomain):
                            found_count += 1
                            
                except Exception as e:
                    logger.debug("Subdomain processing error", module=self.engine_name, error=str(e))
                    continue
            
            logger.info("VirusTotal data processed", module=self.engine_name, 
                       total_subdomains=len(subdomains), domains_found=found_count)
            
        except Exception as e:
            logger.error("VirusTotal domain extraction failed", module=self.engine_name, error=str(e))
    
    def enumerate(self):
        """Énumération via VirusTotal"""
        try:
            logger.info("Starting VirusTotal enumeration", module=self.engine_name, domain=self.domain)
            
            if not self.api_key:
                logger.warning("VirusTotal skipped - no API key", module=self.engine_name)
                return list(self.subdomains)
            
            api_data = self.send_req("")
            if api_data:
                self.extract_domains(api_data)
            
            result_list = list(self.subdomains)
            logger.info("VirusTotal enumeration completed", module=self.engine_name, found=len(result_list))
            
            return result_list
            
        except Exception as e:
            logger.error("VirusTotal enumeration failed", module=self.engine_name, error=str(e))
            return list(self.subdomains)

class DNSBruteForceEnum(EnhancedEnumeratorBase):
    """
    Énumérateur DNS Brute Force intelligent avec wordlists optimisées
    """
    
    def __init__(self, domain, wordlist_file=None, **kwargs):
        try:
            base_url = ""  # Pas d'URL pour DNS brute force
            super(DNSBruteForceEnum, self).__init__(
                base_url, "DNSBruteForce", domain, **kwargs
            )
            
            # Wordlists par défaut (les plus communes)
            self.default_wordlist = [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'app', 'web',
                'blog', 'shop', 'store', 'mobile', 'm', 'secure', 'vpn', 'remote',
                'staging', 'stage', 'prod', 'production', 'beta', 'alpha', 'demo',
                'support', 'help', 'docs', 'portal', 'login', 'auth', 'sso',
                'cloud', 'cdn', 'media', 'static', 'assets', 'img', 'images',
                'video', 'files', 'download', 'uploads', 'backup', 'old',
                'new', 'v2', 'v3', 'test1', 'test2', 'dev1', 'dev2',
                'smtp', 'pop', 'imap', 'webmail', 'email', 'mx', 'ns1', 'ns2',
                'dns', 'gateway', 'router', 'firewall', 'proxy', 'lb', 'www1',
                'www2', 'mail1', 'mail2', 'db', 'database', 'mysql', 'postgres',
                'redis', 'mongo', 'elastic', 'search', 'log', 'logs', 'monitor',
                'status', 'health', 'metrics', 'grafana', 'kibana', 'jenkins',
                'git', 'svn', 'repo', 'code', 'source', 'ci', 'cd', 'build',
                'deploy', 'release', 'artifactory', 'nexus', 'registry'
            ]
            
            self.wordlist_file = wordlist_file
            self.max_threads = kwargs.get('dns_threads', 50)
            self.timeout = kwargs.get('dns_timeout', 3)
            
        except Exception as e:
            logger.error("DNS BruteForce enumerator initialization failed", error=str(e))
            raise
    
    def _load_wordlist(self):
        """Charge la wordlist depuis un fichier ou utilise celle par défaut"""
        try:
            wordlist = []
            
            if self.wordlist_file and os.path.exists(self.wordlist_file):
                logger.info("Loading custom wordlist", module=self.engine_name, file=self.wordlist_file)
                with open(self.wordlist_file, 'r', encoding='utf-8') as f:
                    wordlist = [line.strip().lower() for line in f if line.strip() and not line.startswith('#')]
            else:
                logger.info("Using default wordlist", module=self.engine_name, size=len(self.default_wordlist))
                wordlist = self.default_wordlist.copy()
            
            # Nettoyer et valider la wordlist
            cleaned_wordlist = []
            for word in wordlist:
                if (word and 
                    len(word) > 0 and 
                    len(word) < 50 and
                    word.replace('-', '').replace('_', '').isalnum()):
                    cleaned_wordlist.append(word)
            
            logger.info("Wordlist loaded", module=self.engine_name, 
                       total_words=len(wordlist), valid_words=len(cleaned_wordlist))
            
            return cleaned_wordlist
            
        except Exception as e:
            logger.error("Wordlist loading failed", module=self.engine_name, error=str(e))
            return self.default_wordlist
    
    def _resolve_subdomain(self, subdomain):
        """Résout un sous-domaine via DNS"""
        try:
            import socket
            full_domain = f"{subdomain}.{self.domain}"
            
            # Essayer de résoudre le domaine
            try:
                result = socket.gethostbyname(full_domain)
                if result:
                    return full_domain, result
            except socket.gaierror:
                pass
            
            return None, None
            
        except Exception as e:
            logger.debug("DNS resolution error", module=self.engine_name, 
                        subdomain=subdomain, error=str(e))
            return None, None
    
    def _worker(self, word_queue, results, progress_callback=None):
        """Worker thread pour le brute force DNS"""
        try:
            while True:
                try:
                    word = word_queue.get_nowait()
                except:
                    break
                
                try:
                    subdomain, ip = self._resolve_subdomain(word)
                    if subdomain and ip:
                        with threading.Lock():
                            if self.add_subdomain(subdomain):
                                results.append((subdomain, ip))
                                logger.info("DNS resolved", module=self.engine_name,
                                          subdomain=subdomain, ip=ip)
                                
                                if progress_callback:
                                    progress_callback(subdomain)
                    
                    if progress_callback:
                        progress_callback(None)  # Signal de progression
                        
                except Exception as e:
                    logger.debug("Worker error", module=self.engine_name, 
                               word=word, error=str(e))
                finally:
                    word_queue.task_done()
                    
        except Exception as e:
            logger.error("Worker thread failed", module=self.engine_name, error=str(e))
    
    def enumerate(self):
        """Énumération par brute force DNS"""
        try:
            logger.info("Starting DNS BruteForce enumeration", module=self.engine_name, domain=self.domain)
            
            # Charger la wordlist
            wordlist = self._load_wordlist()
            if not wordlist:
                logger.warning("Empty wordlist", module=self.engine_name)
                return list(self.subdomains)
            
            # Préparer la queue et les résultats
            import queue
            word_queue = queue.Queue()
            results = []
            
            # Ajouter tous les mots à la queue
            for word in wordlist:
                word_queue.put(word)
            
            total_words = len(wordlist)
            completed = 0
            found_count = 0
            
            def progress_callback(subdomain):
                nonlocal completed, found_count
                if subdomain:
                    found_count += 1
                    if not self.silent and self.verbose:
                        print(f"[DNS] Found: {subdomain}")
                else:
                    completed += 1
                    if completed % 50 == 0:
                        logger.info("DNS progress", module=self.engine_name,
                                  completed=completed, total=total_words, found=found_count)
            
            # Créer et démarrer les threads
            threads = []
            num_threads = min(self.max_threads, total_words, 100)
            
            logger.info("Starting DNS threads", module=self.engine_name, 
                       threads=num_threads, wordlist_size=total_words)
            
            for i in range(num_threads):
                thread = threading.Thread(
                    target=self._worker, 
                    args=(word_queue, results, progress_callback)
                )
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            # Attendre que tous les mots soient traités
            word_queue.join()
            
            # Attendre que tous les threads se terminent
            for thread in threads:
                thread.join(timeout=1)
            
            result_list = list(self.subdomains)
            logger.info("DNS BruteForce enumeration completed", module=self.engine_name, 
                       tested=total_words, found=len(result_list))
            
            return result_list
            
        except Exception as e:
            logger.error("DNS BruteForce enumeration failed", module=self.engine_name, error=str(e))
            return list(self.subdomains)


class WaybackMachineEnum(object):
    """
    Énumérateur Wayback Machine pour découvrir des sous-domaines historiques
    """
    
    def __init__(self, domain, **kwargs):
        try:
            self.domain = domain
            self.base_url = "https://web.archive.org/cdx/search/cdx"
            self.engine_name = "WaybackMachine"
            self.timeout = kwargs.get('timeout', 30)
            self.subdomains = set()
            
        except Exception as e:
            logger.error("Wayback Machine enumerator initialization failed", error=str(e))
            raise
    
    def send_req(self, url, params=None):
        """Requête spécialisée pour l'API CDX de Wayback Machine"""
        try:
            if not REQUESTS_AVAILABLE:
                logger.error("requests module not available", module=self.engine_name)
                return None
            
            # Construction des paramètres pour l'API CDX
            if not params:
                params = {
                    'url': f'*.{self.domain}',
                    'output': 'json',
                    'fl': 'original',
                    'collapse': 'urlkey',
                    'limit': 10000
                }
            
            logger.info("Querying Wayback Machine CDX API", module=self.engine_name, params=params)
            
            response = requests.get(
                url, 
                params=params,
                timeout=config_manager.get_setting('timeout', 30),
                headers={
                    'User-Agent': config_manager.get_setting('user_agent', 
                        'JARVIS Intelligence Scanner v1.0')
                }
            )
            
            if response.status_code == 200:
                return response.text
            else:
                logger.warning("Wayback Machine request failed", 
                             module=self.engine_name, status_code=response.status_code)
                return None
                
        except Exception as e:
            logger.error("Wayback Machine request failed", module=self.engine_name, error=str(e))
            return None
    
    def enumerate(self):
        """Point d'entrée principal pour l'énumération"""
        return self.get_subdomains()
    
    def get_metrics(self):
        """Retourne les métriques de base"""
        return {
            'subdomains_found': len(self.subdomains),
            'requests_sent': 1,
            'errors': 0
        }
    
    def get_subdomains(self):
        """Énumère les sous-domaines via Wayback Machine"""
        try:
            subdomains = set()
            
            if not config_manager.is_service_enabled('wayback_machine'):
                logger.info("Wayback Machine disabled in config", module=self.engine_name)
                return []
            
            logger.info("Starting Wayback Machine enumeration", module=self.engine_name, domain=self.domain)
            
            # Requête à l'API CDX
            response_text = self.send_req(self.base_url)
            
            if response_text:
                try:
                    # Parser la réponse JSON
                    lines = response_text.strip().split('\n')
                    if lines and lines[0].startswith('['):
                        # Format JSON
                        data = json.loads(response_text)
                        if data and len(data) > 1:  # Skip header
                            for entry in data[1:]:
                                if entry and len(entry) > 0:
                                    url = entry[0]
                                    subdomain = self._extract_subdomain_from_url(url)
                                    if subdomain:
                                        subdomains.add(subdomain)
                    else:
                        # Format texte simple
                        for line in lines:
                            if line.strip():
                                subdomain = self._extract_subdomain_from_url(line.strip())
                                if subdomain:
                                    subdomains.add(subdomain)
                
                except json.JSONDecodeError:
                    # Traiter comme du texte simple
                    lines = response_text.strip().split('\n')
                    for line in lines:
                        if line.strip():
                            subdomain = self._extract_subdomain_from_url(line.strip())
                            if subdomain:
                                subdomains.add(subdomain)
                
                logger.info("Wayback Machine enumeration completed", 
                           module=self.engine_name, found=len(subdomains))
                
                return list(subdomains)
            else:
                logger.warning("No data from Wayback Machine", module=self.engine_name)
                return []
                
        except Exception as e:
            logger.error("Wayback Machine enumeration failed", module=self.engine_name, error=str(e))
            return []
    
    def _extract_subdomain_from_url(self, url):
        """Extrait le sous-domaine d'une URL"""
        try:
            # Nettoyer l'URL
            url = url.strip()
            if url.startswith(('http://', 'https://')):
                url = url.split('://', 1)[1]
            
            # Extraire le domaine de l'URL
            domain_part = url.split('/')[0].split(':')[0]
            
            # Vérifier si c'est un sous-domaine du domaine cible
            if domain_part.endswith(f'.{self.domain}') or domain_part == self.domain:
                return domain_part
            
            return None
            
        except Exception:
            return None


class ThreatCrowdEnum(object):
    """
    Énumérateur ThreatCrowd pour l'intelligence des menaces et découverte de sous-domaines
    """
    
    def __init__(self, domain, **kwargs):
        try:
            self.domain = domain
            self.base_url = "https://threatcrowd.org/searchApi/v2/domain/report/"
            self.engine_name = "ThreatCrowd"
            self.timeout = kwargs.get('timeout', 30)
            self.subdomains = set()
            
        except Exception as e:
            logger.error("ThreatCrowd enumerator initialization failed", error=str(e))
            raise
    
    def send_req(self, url):
        """Requête spécialisée pour l'API ThreatCrowd"""
        try:
            if not REQUESTS_AVAILABLE:
                logger.error("requests module not available", module=self.engine_name)
                return None
            
            params = {'domain': self.domain}
            
            logger.info("Querying ThreatCrowd API", module=self.engine_name, domain=self.domain)
            
            response = requests.get(
                url,
                params=params,
                timeout=config_manager.get_setting('timeout', 30),
                headers={
                    'User-Agent': config_manager.get_setting('user_agent', 
                        'JARVIS Intelligence Scanner v1.0')
                }
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.warning("ThreatCrowd request failed", 
                             module=self.engine_name, status_code=response.status_code)
                return None
                
        except Exception as e:
            logger.error("ThreatCrowd request failed", module=self.engine_name, error=str(e))
            return None
    
    def enumerate(self):
        """Point d'entrée principal pour l'énumération"""
        return self.get_subdomains()
    
    def get_metrics(self):
        """Retourne les métriques de base"""
        return {
            'subdomains_found': len(self.subdomains),
            'requests_sent': 1,
            'errors': 0
        }
    
    def get_subdomains(self):
        """Énumère les sous-domaines via ThreatCrowd"""
        try:
            subdomains = set()
            
            if not config_manager.is_service_enabled('threatcrowd'):
                logger.info("ThreatCrowd disabled in config", module=self.engine_name)
                return []
            
            logger.info("Starting ThreatCrowd enumeration", module=self.engine_name, domain=self.domain)
            
            # Requête à l'API ThreatCrowd
            data = self.send_req(self.base_url)
            
            if data and data.get('response_code') == '1':
                # Extraire les sous-domaines de la réponse
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        if subdomain and self._is_valid_subdomain(subdomain):
                            subdomains.add(subdomain)
                
                # Extraire aussi des résolutions DNS
                if 'resolutions' in data:
                    for resolution in data['resolutions']:
                        if 'last_resolved' in resolution:
                            domain_name = resolution.get('last_resolved', '')
                            if domain_name and self._is_valid_subdomain(domain_name):
                                subdomains.add(domain_name)
                
                logger.info("ThreatCrowd enumeration completed", 
                           module=self.engine_name, found=len(subdomains))
                
                return list(subdomains)
            else:
                logger.warning("No valid data from ThreatCrowd", module=self.engine_name, 
                             response=data.get('response_code') if data else 'None')
                return []
                
        except Exception as e:
            logger.error("ThreatCrowd enumeration failed", module=self.engine_name, error=str(e))
            return []
    
    def _is_valid_subdomain(self, subdomain):
        """Valide si c'est un sous-domaine légitime du domaine cible"""
        try:
            return (subdomain and 
                    isinstance(subdomain, str) and
                    (subdomain.endswith(f'.{self.domain}') or subdomain == self.domain) and
                    len(subdomain) > len(self.domain))
        except Exception:
            return False

class DomainIntelligenceCollector:
    """
    Collecteur d'intelligence complet pour analyse de propriétaires par IA
    """
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.intelligence_data = {
            'target_domain': '',
            'collection_timestamp': datetime.now().isoformat(),
            'subdomains': {},
            'whois_data': {},
            'certificates': [],
            'dns_records': {},
            'network_info': {},
            'owner_analysis': {
                'detected_owners': [],
                'confidence_scores': {},
                'attribution_sources': {},
                'potential_conflicts': []
            },
            'security_context': {
                'ssl_issuers': [],
                'dns_providers': [],
                'hosting_providers': [],
                'email_domains': [],
                'suspicious_patterns': []
            }
        }
    
    def collect_subdomain_intelligence(self, subdomain):
        """Collecte toutes les informations d'un sous-domaine"""
        try:
            self.logger.info("Collecting intelligence", module="DomainIntel", subdomain=subdomain)
            
            subdomain_data = {
                'domain': subdomain,
                'discovered_at': datetime.now().isoformat(),
                'whois': {},
                'dns': {},
                'certificates': [],
                'network': {},
                'ownership_indicators': {}
            }
            
            # Collecte WHOIS
            whois_data = self._collect_whois(subdomain)
            if whois_data:
                subdomain_data['whois'] = whois_data
                self._extract_ownership_from_whois(subdomain, whois_data)
            
            # Collecte DNS
            dns_data = self._collect_dns_records(subdomain)
            if dns_data:
                subdomain_data['dns'] = dns_data
                self._analyze_dns_patterns(subdomain, dns_data)
            
            # Résolution IP et info réseau
            network_data = self._collect_network_info(subdomain)
            if network_data:
                subdomain_data['network'] = network_data
                self._analyze_hosting_patterns(subdomain, network_data)
            
            self.intelligence_data['subdomains'][subdomain] = subdomain_data
            
        except Exception as e:
            self.logger.error("Intelligence collection failed", module="DomainIntel", 
                            subdomain=subdomain, error=str(e))
    
    def _collect_whois(self, domain):
        """Collecte les données WHOIS complètes"""
        try:
            import whois
            
            w = whois.whois(domain)
            if not w:
                return None
            
            whois_data = {
                'registrar': getattr(w, 'registrar', None),
                'registrant': getattr(w, 'registrant', None),
                'admin': getattr(w, 'admin', None),
                'tech': getattr(w, 'tech', None),
                'emails': [],
                'organization': getattr(w, 'org', None),
                'country': getattr(w, 'country', None),
                'creation_date': str(getattr(w, 'creation_date', None)),
                'expiration_date': str(getattr(w, 'expiration_date', None)),
                'name_servers': getattr(w, 'name_servers', []),
                'status': getattr(w, 'status', [])
            }
            
            # Extraire tous les emails
            email_fields = ['emails', 'registrant_email', 'admin_email', 'tech_email']
            for field in email_fields:
                if hasattr(w, field):
                    emails = getattr(w, field)
                    if emails:
                        if isinstance(emails, list):
                            whois_data['emails'].extend(emails)
                        else:
                            whois_data['emails'].append(emails)
            
            # Nettoyer les emails
            whois_data['emails'] = list(set([str(e).lower() for e in whois_data['emails'] if e and '@' in str(e)]))
            
            return whois_data
            
        except ImportError:
            self.logger.warning("python-whois not available", module="DomainIntel")
            return None
        except Exception as e:
            self.logger.debug("WHOIS collection failed", module="DomainIntel", domain=domain, error=str(e))
            return None
    
    def _collect_dns_records(self, domain):
        """Collecte les enregistrements DNS"""
        try:
            import socket
            import subprocess
            
            dns_data = {
                'a_records': [],
                'aaaa_records': [],
                'mx_records': [],
                'ns_records': [],
                'txt_records': [],
                'cname_records': []
            }
            
            # A records (IPv4)
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                dns_data['a_records'] = ips
            except:
                pass
            
            # Utiliser dig si disponible pour plus d'infos
            try:
                # MX records
                result = subprocess.run(['dig', '+short', 'MX', domain], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    dns_data['mx_records'] = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                
                # NS records
                result = subprocess.run(['dig', '+short', 'NS', domain], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    dns_data['ns_records'] = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                
                # TXT records
                result = subprocess.run(['dig', '+short', 'TXT', domain], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    dns_data['txt_records'] = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                    
            except Exception as e:
                self.logger.debug("dig command failed", module="DomainIntel", error=str(e))
            
            return dns_data
            
        except Exception as e:
            self.logger.debug("DNS collection failed", module="DomainIntel", domain=domain, error=str(e))
            return None
    
    def _collect_network_info(self, domain):
        """Collecte les informations réseau et géolocalisation"""
        try:
            import socket
            import requests
            
            network_data = {
                'ips': [],
                'geolocation': {},
                'asn': {},
                'hosting_provider': None,
                'cloud_provider': None
            }
            
            # Résoudre l'IP
            try:
                ip = socket.gethostbyname(domain)
                network_data['ips'].append(ip)
                
                # Géolocalisation via ipapi (gratuit)
                try:
                    response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
                    if response.status_code == 200:
                        geo_data = response.json()
                        network_data['geolocation'] = {
                            'country': geo_data.get('country'),
                            'region': geo_data.get('regionName'),
                            'city': geo_data.get('city'),
                            'isp': geo_data.get('isp'),
                            'org': geo_data.get('org'),
                            'as': geo_data.get('as')
                        }
                        
                        # Détecter les fournisseurs cloud
                        org = geo_data.get('org', '').lower()
                        if 'amazon' in org or 'aws' in org:
                            network_data['cloud_provider'] = 'AWS'
                        elif 'google' in org or 'gcp' in org:
                            network_data['cloud_provider'] = 'Google Cloud'
                        elif 'microsoft' in org or 'azure' in org:
                            network_data['cloud_provider'] = 'Azure'
                        elif 'cloudflare' in org:
                            network_data['cloud_provider'] = 'Cloudflare'
                        
                        network_data['hosting_provider'] = geo_data.get('org')
                        
                except Exception as e:
                    self.logger.debug("Geolocation failed", module="DomainIntel", error=str(e))
                    
            except Exception as e:
                self.logger.debug("IP resolution failed", module="DomainIntel", domain=domain, error=str(e))
            
            return network_data
            
        except Exception as e:
            self.logger.debug("Network info collection failed", module="DomainIntel", error=str(e))
            return None
    
    def _extract_ownership_from_whois(self, domain, whois_data):
        """Extrait les indicateurs de propriété depuis WHOIS"""
        try:
            ownership_indicators = {
                'registrar': whois_data.get('registrar'),
                'emails': whois_data.get('emails', []),
                'organization': whois_data.get('organization'),
                'registrant': whois_data.get('registrant'),
                'name_servers': whois_data.get('name_servers', [])
            }
            
            # Ajouter aux données d'analyse de propriété
            for email in whois_data.get('emails', []):
                if email not in self.intelligence_data['owner_analysis']['detected_owners']:
                    self.intelligence_data['owner_analysis']['detected_owners'].append({
                        'type': 'email',
                        'value': email,
                        'source': f'whois:{domain}',
                        'confidence': 0.8
                    })
            
            if whois_data.get('organization'):
                org = whois_data.get('organization')
                self.intelligence_data['owner_analysis']['detected_owners'].append({
                    'type': 'organization',
                    'value': org,
                    'source': f'whois:{domain}',
                    'confidence': 0.9
                })
            
        except Exception as e:
            self.logger.debug("Ownership extraction failed", module="DomainIntel", error=str(e))
    
    def _analyze_dns_patterns(self, domain, dns_data):
        """Analyse les patterns DNS pour l'attribution"""
        try:
            # Analyser les serveurs de noms
            for ns in dns_data.get('ns_records', []):
                if 'cloudflare' in ns.lower():
                    self.intelligence_data['security_context']['dns_providers'].append('Cloudflare')
                elif 'godaddy' in ns.lower():
                    self.intelligence_data['security_context']['dns_providers'].append('GoDaddy')
                elif 'google' in ns.lower():
                    self.intelligence_data['security_context']['dns_providers'].append('Google')
            
            # Analyser les enregistrements TXT pour des patterns de propriété
            for txt in dns_data.get('txt_records', []):
                if 'google-site-verification' in txt:
                    self.intelligence_data['owner_analysis']['detected_owners'].append({
                        'type': 'google_verification',
                        'value': txt,
                        'source': f'dns:{domain}',
                        'confidence': 0.7
                    })
                elif 'facebook-domain-verification' in txt:
                    self.intelligence_data['owner_analysis']['detected_owners'].append({
                        'type': 'facebook_verification',
                        'value': txt,
                        'source': f'dns:{domain}',
                        'confidence': 0.7
                    })
                    
        except Exception as e:
            self.logger.debug("DNS pattern analysis failed", module="DomainIntel", error=str(e))
    
    def _analyze_hosting_patterns(self, domain, network_data):
        """Analyse les patterns d'hébergement"""
        try:
            hosting_provider = network_data.get('hosting_provider')
            cloud_provider = network_data.get('cloud_provider')
            
            if hosting_provider:
                self.intelligence_data['security_context']['hosting_providers'].append(hosting_provider)
            
            if cloud_provider:
                self.intelligence_data['owner_analysis']['detected_owners'].append({
                    'type': 'cloud_provider',
                    'value': cloud_provider,
                    'source': f'network:{domain}',
                    'confidence': 0.6
                })
                
        except Exception as e:
            self.logger.debug("Hosting pattern analysis failed", module="DomainIntel", error=str(e))
    
    def add_certificate_data(self, cert_data):
        """Ajoute les données de certificats à l'analyse"""
        try:
            for cert in cert_data:
                cert_info = {
                    'common_name': cert.get('common_name'),
                    'issuer': cert.get('issuer_name'),
                    'subject': cert.get('subject'),
                    'not_before': cert.get('not_before'),
                    'not_after': cert.get('not_after')
                }
                
                self.intelligence_data['certificates'].append(cert_info)
                
                # Extraire les émetteurs SSL
                issuer = cert.get('issuer_name', '')
                if issuer:
                    self.intelligence_data['security_context']['ssl_issuers'].append(issuer)
                    
                    # Patterns d'émetteurs connus
                    if 'Let\'s Encrypt' in issuer:
                        self.intelligence_data['owner_analysis']['detected_owners'].append({
                            'type': 'ssl_issuer',
                            'value': 'Let\'s Encrypt (Automated)',
                            'source': f'certificate:{cert.get("common_name")}',
                            'confidence': 0.5
                        })
                    elif 'DigiCert' in issuer:
                        self.intelligence_data['owner_analysis']['detected_owners'].append({
                            'type': 'ssl_issuer',
                            'value': 'DigiCert (Commercial)',
                            'source': f'certificate:{cert.get("common_name")}',
                            'confidence': 0.6
                        })
                        
        except Exception as e:
            self.logger.debug("Certificate analysis failed", module="DomainIntel", error=str(e))
    
    def analyze_ownership_patterns(self):
        """Analyse finale pour détecter les patterns de propriété"""
        try:
            # Grouper par type d'indicateur
            owners_by_type = {}
            for owner in self.intelligence_data['owner_analysis']['detected_owners']:
                owner_type = owner['type']
                if owner_type not in owners_by_type:
                    owners_by_type[owner_type] = []
                owners_by_type[owner_type].append(owner)
            
            # Calculer les scores de confiance
            email_domains = set()
            for owner in owners_by_type.get('email', []):
                domain = owner['value'].split('@')[1] if '@' in owner['value'] else None
                if domain:
                    email_domains.add(domain)
            
            # Détecter les conflits potentiels
            if len(email_domains) > 3:
                self.intelligence_data['owner_analysis']['potential_conflicts'].append({
                    'type': 'multiple_email_domains',
                    'description': f'Multiple email domains detected: {list(email_domains)}',
                    'severity': 'medium'
                })
            
            # Analyser la cohérence des organisations
            orgs = [o['value'] for o in owners_by_type.get('organization', [])]
            if len(set(orgs)) > 2:
                self.intelligence_data['owner_analysis']['potential_conflicts'].append({
                    'type': 'multiple_organizations',
                    'description': f'Multiple organizations detected: {orgs}',
                    'severity': 'high'
                })
            
            self.logger.info("Ownership analysis completed", module="DomainIntel",
                           owners_found=len(self.intelligence_data['owner_analysis']['detected_owners']),
                           conflicts=len(self.intelligence_data['owner_analysis']['potential_conflicts']))
            
        except Exception as e:
            self.logger.error("Ownership pattern analysis failed", module="DomainIntel", error=str(e))
    
    def export_for_ai_analysis(self, filename):
        """Exporte les données formatées pour l'analyse IA"""
        try:
            import json
            
            # Finaliser l'analyse
            self.analyze_ownership_patterns()
            
            # Structurer les données pour l'IA
            ai_data = {
                'metadata': {
                    'target_domain': self.intelligence_data['target_domain'],
                    'collection_timestamp': self.intelligence_data['collection_timestamp'],
                    'total_subdomains': len(self.intelligence_data['subdomains']),
                    'total_owners_detected': len(self.intelligence_data['owner_analysis']['detected_owners']),
                    'potential_conflicts': len(self.intelligence_data['owner_analysis']['potential_conflicts'])
                },
                'raw_intelligence': self.intelligence_data,
                'ai_analysis_prompts': {
                    'ownership_verification': "Analyze the collected data to verify domain ownership attribution. Look for consistency patterns in emails, organizations, registrars, and technical contacts.",
                    'security_assessment': "Evaluate security posture based on SSL certificates, DNS configuration, and hosting patterns.",
                    'anomaly_detection': "Identify potential security threats, suspicious patterns, or ownership discrepancies."
                }
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(ai_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info("AI analysis data exported", module="DomainIntel", 
                           filename=filename, total_indicators=len(self.intelligence_data['owner_analysis']['detected_owners']))
            
            return ai_data
            
        except Exception as e:
            self.logger.error("AI export failed", module="DomainIntel", error=str(e))
            return None

class EmailExtractor:
    """
    Extracteur d'emails depuis WHOIS et certificats
    """
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.emails = set()
        self.organizations = set()
        
    def extract_from_whois(self, domain):
        """Extrait emails et organisations depuis WHOIS"""
        try:
            import whois
            
            self.logger.info("Querying WHOIS", module="EmailExtractor", domain=domain)
            
            w = whois.whois(domain)
            if w:
                # Extraire les emails
                emails = []
                if hasattr(w, 'emails') and w.emails:
                    if isinstance(w.emails, list):
                        emails.extend(w.emails)
                    else:
                        emails.append(w.emails)
                
                # Extraire depuis les champs texte
                for field in ['registrant_email', 'admin_email', 'tech_email']:
                    if hasattr(w, field) and getattr(w, field):
                        emails.append(getattr(w, field))
                
                # Nettoyer et valider les emails
                for email in emails:
                    if email and '@' in str(email):
                        clean_email = str(email).strip().lower()
                        if self._is_valid_email(clean_email):
                            self.emails.add(clean_email)
                
                # Extraire les organisations
                orgs = []
                for field in ['org', 'registrant', 'admin', 'tech']:
                    if hasattr(w, field) and getattr(w, field):
                        org = str(getattr(w, field)).strip()
                        if org and len(org) > 3:
                            orgs.append(org)
                
                for org in orgs:
                    self.organizations.add(org)
                
                self.logger.info("WHOIS extraction completed", module="EmailExtractor",
                               emails_found=len(self.emails), orgs_found=len(self.organizations))
                
        except ImportError:
            self.logger.warning("python-whois not available", module="EmailExtractor")
        except Exception as e:
            self.logger.error("WHOIS extraction failed", module="EmailExtractor", error=str(e))
    
    def extract_from_certificates(self, cert_data):
        """Extrait emails et organisations depuis les certificats"""
        try:
            if not cert_data:
                return
            
            for cert in cert_data:
                try:
                    # Extraire depuis issuer_name
                    issuer = cert.get('issuer_name', '')
                    if issuer:
                        emails = self._extract_emails_from_text(issuer)
                        self.emails.update(emails)
                        
                        orgs = self._extract_organizations_from_text(issuer)
                        self.organizations.update(orgs)
                    
                    # Extraire depuis subject
                    subject = cert.get('subject', '')
                    if subject:
                        emails = self._extract_emails_from_text(subject)
                        self.emails.update(emails)
                        
                        orgs = self._extract_organizations_from_text(subject)
                        self.organizations.update(orgs)
                        
                except Exception as e:
                    self.logger.debug("Certificate parsing error", module="EmailExtractor", error=str(e))
                    continue
            
            self.logger.info("Certificate extraction completed", module="EmailExtractor",
                           emails_found=len(self.emails), orgs_found=len(self.organizations))
            
        except Exception as e:
            self.logger.error("Certificate extraction failed", module="EmailExtractor", error=str(e))
    
    def _extract_emails_from_text(self, text):
        """Extrait les emails d'un texte avec regex"""
        import re
        emails = set()
        try:
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            matches = re.findall(email_pattern, text)
            for match in matches:
                if self._is_valid_email(match.lower()):
                    emails.add(match.lower())
        except Exception as e:
            self.logger.debug("Email regex extraction failed", module="EmailExtractor", error=str(e))
        return emails
    
    def _extract_organizations_from_text(self, text):
        """Extrait les organisations d'un texte"""
        orgs = set()
        try:
            # Pattern pour extraire O= (Organization)
            import re
            org_patterns = [
                r'O=([^,]+)',
                r'Organization:\s*([^\n]+)',
                r'Org:\s*([^\n]+)'
            ]
            
            for pattern in org_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    org = match.strip()
                    if org and len(org) > 3 and not any(x in org.lower() for x in ['null', 'none', 'n/a']):
                        orgs.add(org)
                        
        except Exception as e:
            self.logger.debug("Organization extraction failed", module="EmailExtractor", error=str(e))
        return orgs
    
    def _is_valid_email(self, email):
        """Valide un email"""
        try:
            import re
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return bool(re.match(pattern, email)) and len(email) < 100
        except:
            return False
    
    def get_results(self):
        """Retourne les résultats extraits"""
        return {
            'emails': list(self.emails),
            'organizations': list(self.organizations)
        }

class StatisticsCollector:
    """
    Collecteur de statistiques détaillées
    """
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.start_time = time.time()
        self.stats = {
            'domain': '',
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'total_time': 0,
            'engines_used': [],
            'engines_stats': {},
            'total_subdomains': 0,
            'unique_subdomains': 0,
            'subdomains_by_engine': {},
            'ips_resolved': 0,
            'emails_found': 0,
            'organizations_found': 0,
            'errors': [],
            'performance_metrics': {
                'requests_sent': 0,
                'requests_successful': 0,
                'requests_failed': 0,
                'avg_response_time': 0
            }
        }
    
    def set_domain(self, domain):
        """Définit le domaine cible"""
        self.stats['domain'] = domain
    
    def add_engine(self, engine_name):
        """Ajoute un moteur utilisé"""
        if engine_name not in self.stats['engines_used']:
            self.stats['engines_used'].append(engine_name)
        
        if engine_name not in self.stats['engines_stats']:
            self.stats['engines_stats'][engine_name] = {
                'start_time': time.time(),
                'end_time': None,
                'duration': 0,
                'subdomains_found': 0,
                'requests_sent': 0,
                'requests_successful': 0,
                'requests_failed': 0,
                'errors': []
            }
    
    def update_engine_stats(self, engine_name, metrics):
        """Met à jour les statistiques d'un moteur"""
        if engine_name in self.stats['engines_stats']:
            engine_stats = self.stats['engines_stats'][engine_name]
            engine_stats['end_time'] = time.time()
            engine_stats['duration'] = engine_stats['end_time'] - engine_stats['start_time']
            
            if hasattr(metrics, 'get'):
                engine_stats['requests_sent'] = metrics.get('requests_sent', 0)
                engine_stats['requests_successful'] = metrics.get('requests_successful', 0)
                engine_stats['requests_failed'] = metrics.get('requests_failed', 0)
    
    def set_subdomains(self, subdomains, engine_results=None):
        """Définit les sous-domaines trouvés"""
        self.stats['total_subdomains'] = len(subdomains)
        self.stats['unique_subdomains'] = len(set(subdomains))
        
        if engine_results:
            self.stats['subdomains_by_engine'] = engine_results
    
    def set_extraction_results(self, email_results):
        """Définit les résultats d'extraction"""
        if email_results:
            self.stats['emails_found'] = len(email_results.get('emails', []))
            self.stats['organizations_found'] = len(email_results.get('organizations', []))
    
    def add_error(self, error, engine=None):
        """Ajoute une erreur"""
        error_entry = {
            'timestamp': datetime.now().isoformat(),
            'error': str(error),
            'engine': engine
        }
        self.stats['errors'].append(error_entry)
    
    def finalize(self):
        """Finalise les statistiques"""
        self.stats['end_time'] = datetime.now().isoformat()
        self.stats['total_time'] = time.time() - self.start_time
        
        # Calculer les métriques de performance globales
        total_requests = sum(engine['requests_sent'] for engine in self.stats['engines_stats'].values())
        total_successful = sum(engine['requests_successful'] for engine in self.stats['engines_stats'].values())
        total_failed = sum(engine['requests_failed'] for engine in self.stats['engines_stats'].values())
        
        self.stats['performance_metrics'] = {
            'requests_sent': total_requests,
            'requests_successful': total_successful,
            'requests_failed': total_failed,
            'success_rate': (total_successful / total_requests * 100) if total_requests > 0 else 0,
            'avg_time_per_request': (self.stats['total_time'] / total_requests) if total_requests > 0 else 0
        }
    
    def export_to_file(self, filename):
        """Exporte les statistiques vers un fichier"""
        try:
            import json
            
            self.finalize()
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.stats, f, indent=2, ensure_ascii=False)
            
            self.logger.info("Statistics exported", module="StatisticsCollector", 
                           filename=filename, total_subdomains=self.stats['total_subdomains'])
            
        except Exception as e:
            self.logger.error("Statistics export failed", module="StatisticsCollector", 
                            filename=filename, error=str(e))

class EnhancedPortScanner:
    """
    Scanner de ports amélioré avec threading et gestion d'erreurs.
    """
    
    def __init__(self, subdomains, ports, max_threads=50, timeout=3):
        """Initialise le scanner de ports."""
        try:
            self.subdomains = subdomains if subdomains else []
            self.ports = ports if ports else []
            self.max_threads = min(max_threads, 100)  # Limiter à 100 threads max
            self.timeout = max(timeout, 1)  # Minimum 1 seconde
            self.results = {}
            self.lock = threading.Lock()
            self.progress_bar = None
            
            # Validation des ports
            valid_ports = []
            for port in self.ports:
                if isinstance(port, int) and 1 <= port <= 65535:
                    valid_ports.append(port)
                elif isinstance(port, str) and port.isdigit():
                    port_int = int(port)
                    if 1 <= port_int <= 65535:
                        valid_ports.append(port_int)
            
            self.ports = valid_ports
            
            if not self.ports:
                logger.warning("No valid ports to scan", module="PortScanner")
            
            if not self.subdomains:
                logger.warning("No subdomains to scan", module="PortScanner")
            
            logger.info("Port scanner initialized", module="PortScanner", 
                       subdomains=len(self.subdomains), ports=len(self.ports))
            
        except Exception as e:
            logger.error("Port scanner initialization failed", module="PortScanner", error=str(e))
            raise
    
    def scan_port(self, host, port):
        """
        Scanne un port spécifique sur un hôte.
        
        Args:
            host: Nom d'hôte à scanner
            port: Port à scanner
            
        Returns:
            bool: True si le port est ouvert
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((host, port))
            sock.close()
            
            return result == 0
            
        except socket.gaierror:
            # Erreur de résolution DNS
            logger.debug("DNS resolution failed", module="PortScanner", host=host)
            return False
        except Exception as e:
            logger.debug("Port scan failed", module="PortScanner", host=host, port=port, error=str(e))
            return False
    
    def scan_host(self, host):
        """
        Scanne tous les ports d'un hôte.
        
        Args:
            host: Nom d'hôte à scanner
        """
        try:
            open_ports = []
            
            for port in self.ports:
                if self.scan_port(host, port):
                    open_ports.append(port)
            
            # Stocker les résultats
            with self.lock:
                if open_ports:
                    self.results[host] = open_ports
                    
                    # Affichage des résultats
                    ports_str = ', '.join(map(str, open_ports))
                    result_text = "{}{}[{}] {}Found open ports on {}: {}{}".format(
                        colors.GREEN,
                        colors.BOLD,
                        datetime.now().strftime("%H:%M:%S"),
                        colors.WHITE,
                        host,
                        colors.YELLOW,
                        ports_str,
                        colors.WHITE
                    )
                    print(result_text)
                    
                    logger.info("Open ports found", module="PortScanner", 
                               host=host, ports=open_ports)
                
                # Mettre à jour la barre de progression
                if self.progress_bar:
                    self.progress_bar.update(increment=1)
            
        except Exception as e:
            logger.error("Host scan failed", module="PortScanner", host=host, error=str(e))
    
    def run(self):
        """Exécute le scan de ports avec threading."""
        try:
            if not self.subdomains or not self.ports:
                logger.warning("Nothing to scan", module="PortScanner")
                return self.results
            
            total_hosts = len(self.subdomains)
            logger.info("Starting port scan", module="PortScanner", 
                       hosts=total_hosts, ports=len(self.ports), max_threads=self.max_threads)
            
            # Initialiser la barre de progression
            self.progress_bar = ProgressBar(
                total=total_hosts,
                prefix="{}Scanning ports{}".format(colors.CYAN, colors.WHITE),
                suffix="hosts completed"
            )
            
            # Créer le pool de threads
            threads = []
            semaphore = threading.Semaphore(self.max_threads)
            
            def worker(host):
                with semaphore:
                    self.scan_host(host)
            
            # Lancer les threads
            for host in self.subdomains:
                thread = threading.Thread(target=worker, args=(host,))
                threads.append(thread)
                thread.start()
            
            # Attendre que tous les threads se terminent
            for thread in threads:
                thread.join()
            
            # Finaliser la barre de progression
            self.progress_bar.finish()
            
            # Résumé des résultats
            total_open_ports = sum(len(ports) for ports in self.results.values())
            logger.info("Port scan completed", module="PortScanner", 
                       hosts_with_open_ports=len(self.results), 
                       total_open_ports=total_open_ports)
            
            if not logger.silent:
                summary_text = "{}Port scan summary: {} hosts with open ports, {} total open ports{}".format(
                    colors.GREEN, len(self.results), total_open_ports, colors.WHITE
                )
                print(summary_text)
            
            return self.results
            
        except Exception as e:
            logger.error("Port scan execution failed", module="PortScanner", error=str(e))
            return self.results

def enhanced_main(domain, threads=30, output_file=None, output_format='txt', 
                 ports=None, silent=False, verbose=True, enable_bruteforce=True, 
                 engines=None, timeout=25, delay=0, user_agent=None, 
                 statistics=False, debug=False, extract_emails=False, 
                 extract_owners=False, stats_file=None, include_ips=False,
                 intelligence=False, ai_export=None):
    """
    Fonction principale améliorée de JARVIS Intelligence.
    
    Args:
        domain: Domaine cible
        threads: Nombre de threads pour le bruteforce
        output_file: Fichier de sortie
        output_format: Format de sortie
        ports: Liste de ports à scanner
        silent: Mode silencieux
        verbose: Mode verbose
        enable_bruteforce: Activer le bruteforce
        engines: Moteurs de recherche à utiliser
        timeout: Timeout des requêtes
        delay: Délai entre les requêtes
        user_agent: User-Agent personnalisé
        statistics: Afficher les statistiques
        debug: Mode debug
    
    Returns:
        list: Liste des sous-domaines trouvés
    """
    try:
        # Initialiser les variables globales
        initialize_globals(debug=debug, no_color=silent)
        
        logger.info("Starting JARVIS Intelligence", module="Main", domain=domain)
        
        # Validation du domaine
        is_valid, clean_domain, error_msg = security_validator.validate_domain(domain)
        if not is_valid:
            error_text = "{}Domain validation failed: {}{}".format(colors.RED, error_msg, colors.WHITE)
            if not silent:
                print(error_text)
            logger.error("Domain validation failed", module="Main", domain=domain, error=error_msg)
            return []
        
        # Validation des ports si spécifiés
        port_list = []
        if ports:
            is_valid_ports, port_list, port_error = security_validator.validate_port_list(ports)
            if not is_valid_ports:
                error_text = "{}Port validation failed: {}{}".format(colors.RED, port_error, colors.WHITE)
                if not silent:
                    print(error_text)
                logger.error("Port validation failed", module="Main", ports=ports, error=port_error)
                return []
        
        # Affichage des informations
        if not silent:
            print("{}{}Target Domain: {}{}{}".format(colors.BLUE, colors.BOLD, colors.WHITE, clean_domain, colors.WHITE))
            if verbose:
                print("{}Verbose mode enabled - showing real-time results{}".format(colors.YELLOW, colors.WHITE))
            if enable_bruteforce:
                print("{}Bruteforce module enabled{}".format(colors.GREEN, colors.WHITE))
            if port_list:
                print("{}Port scanning enabled for {} ports{}".format(colors.CYAN, len(port_list), colors.WHITE))
        
        # Structures de données pour les résultats
        search_results = set()
        bruteforce_results = set()
        all_subdomains = set()
        
        # Métriques globales
        global_metrics = {
            'start_time': time.time(),
            'engines_used': [],
            'total_requests': 0,
            'total_errors': 0,
            'bruteforce_enabled': enable_bruteforce,
            'port_scan_enabled': bool(port_list)
        }
        
        # Configuration des moteurs de recherche
        available_engines = {
            'google': PlaywrightGoogleEnum,
            'google-simple': EnhancedGoogleEnum,  # Version simple sans Playwright
            'crt': CertificateTransparencyEnum,  # Certificate Transparency (gratuit)
            'securitytrails': SecurityTrailsEnum,  # SecurityTrails API (clé requise)
            'virustotal': VirusTotalEnum,  # VirusTotal API (clé requise)
            'dns': DNSBruteForceEnum,  # DNS Brute Force (gratuit)
            'wayback': WaybackMachineEnum,  # Archives web (gratuit)
            'threatcrowd': ThreatCrowdEnum,  # Threat intelligence (gratuit)
            # TODO: Implémenter prochainement:
            # 'shodan': ShodanEnum,  # Infrastructure discovery
            # 'censys': CensysEnum,  # Internet-wide scanning
            # 'passivedns': PassiveDNSEnum,  # Historical DNS
            # 'reverse-dns': ReverseDNSEnum,  # Reverse IP lookups
            # 'asn': ASNEnum,  # BGP/ASN enumeration
            # 'zone-transfer': ZoneTransferEnum,  # Zone transfer attempts
        }
        
        selected_engines = []
        if engines:
            engine_names = [name.strip().lower() for name in engines.split(',')]
            for engine_name in engine_names:
                if engine_name in available_engines:
                    selected_engines.append((engine_name, available_engines[engine_name]))
                else:
                    logger.warning("Unknown engine ignored", module="Main", engine=engine_name)
        else:
            # Utiliser tous les moteurs disponibles par défaut
            selected_engines = list(available_engines.items())
        
        if not selected_engines:
            logger.warning("No valid engines selected, using default", module="Main")
            selected_engines = [('crt', CertificateTransparencyEnum)]
        
        # Énumération avec les moteurs de recherche
        if not silent:
            print("{}Starting enumeration with {} engines{}".format(
                colors.GREEN, len(selected_engines), colors.WHITE))
        
        engine_results = {}
        for engine_name, engine_class in selected_engines:
            try:
                if not silent:
                    print("{}Processing with {} engine{}".format(colors.BLUE, engine_name.title(), colors.WHITE))
                
                # Initialiser l'énumérateur
                enumerator = engine_class(
                    clean_domain,
                    silent=silent,
                    verbose=verbose,
                    timeout=timeout,
                    delay=delay,
                    user_agent=user_agent
                )
                
                # Exécuter l'énumération
                engine_subdomains = enumerator.enumerate()
                engine_results[engine_name] = {
                    'subdomains': engine_subdomains,
                    'metrics': enumerator.get_metrics()
                }
                
                # Ajouter aux résultats de recherche
                search_results.update(engine_subdomains)
                
                # Mettre à jour les métriques globales
                global_metrics['engines_used'].append(engine_name)
                global_metrics['total_requests'] += enumerator.metrics['requests_sent']
                global_metrics['total_errors'] += enumerator.metrics['requests_failed']
                
                logger.info("Engine completed", module="Main", engine=engine_name, 
                          found=len(engine_subdomains))
                
            except Exception as e:
                logger.error("Engine failed", module="Main", engine=engine_name, error=str(e))
                continue
        
        # Bruteforce avec SubBrute si activé
        if enable_bruteforce and subbrute:
            try:
                if not silent:
                    print("{}Starting bruteforce module{}".format(colors.GREEN, colors.WHITE))
                
                # Configuration du bruteforce
                record_type = False  # Utiliser le type par défaut
                path_to_file = os.path.dirname(os.path.realpath(__file__))
                subs_file = os.path.join(path_to_file, 'subbrute', 'names.txt')
                resolvers_file = os.path.join(path_to_file, 'subbrute', 'resolvers.txt')
                
                # Vérifier l'existence des fichiers
                if not os.path.exists(subs_file):
                    logger.warning("Subdomains file not found", module="Main", file=subs_file)
                if not os.path.exists(resolvers_file):
                    logger.warning("Resolvers file not found", module="Main", file=resolvers_file)
                
                if os.path.exists(subs_file) and os.path.exists(resolvers_file):
                    # Exécuter le bruteforce
                    bf_results = subbrute.print_target(
                        clean_domain, record_type, subs_file, resolvers_file,
                        threads, False, False, list(search_results), verbose
                    )
                    
                    if bf_results:
                        bruteforce_results.update(bf_results)
                        logger.info("Bruteforce completed", module="Main", found=len(bf_results))
                else:
                    logger.warning("Bruteforce skipped due to missing files", module="Main")
                    
            except Exception as e:
                logger.error("Bruteforce failed", module="Main", error=str(e))
        
        # Combiner tous les résultats
        all_subdomains.update(search_results)
        all_subdomains.update(bruteforce_results)
        
        # Trier les résultats
        final_subdomains = sorted(list(all_subdomains), key=subdomain_sorting_key_enhanced)
        
        # Affichage des résultats
        if not silent:
            print("{}{}Total unique subdomains found: {}{}{}".format(
                colors.GREEN, colors.BOLD, len(final_subdomains), colors.WHITE, colors.WHITE))
            
            if not verbose:  # Si pas verbose, afficher tous les résultats maintenant
                for subdomain in final_subdomains:
                    print("{}{}{}".format(colors.GREEN, subdomain, colors.WHITE))
        
        # Sauvegarde des résultats
        if output_file:
            try:
                # Préparer les métadonnées
                metadata = {
                    'target_domain': clean_domain,
                    'enumeration_time': datetime.now().isoformat(),
                    'total_subdomains': len(final_subdomains),
                    'search_results': len(search_results),
                    'bruteforce_results': len(bruteforce_results),
                    'engines_used': global_metrics['engines_used'],
                    'tool_version': 'JARVIS Intelligence v1.0'
                }
                
                success = write_file_enhanced(output_file, final_subdomains, output_format, metadata)
                if success and not silent:
                    print("{}Results saved to: {}{}{}".format(colors.BLUE, colors.WHITE, output_file, colors.WHITE))
                
            except Exception as e:
                logger.error("Failed to save results", module="Main", error=str(e))
                if not silent:
                    print("{}Error saving results: {}{}".format(colors.RED, str(e), colors.WHITE))
        
        # Scanner de ports
        if port_list and final_subdomains:
            try:
                if not silent:
                    print("{}Starting port scan on {} subdomains{}".format(
                        colors.CYAN, len(final_subdomains), colors.WHITE))
                
                port_scanner = EnhancedPortScanner(
                    final_subdomains, port_list, max_threads=min(threads, 50)
                )
                port_results = port_scanner.run()
                
                # Sauvegarder les résultats de port si demandé
                if output_file and port_results:
                    port_file = output_file.rsplit('.', 1)[0] + '_ports.' + output_format
                    port_data = []
                    for host, ports in port_results.items():
                        port_data.append("{}:{}".format(host, ','.join(map(str, ports))))
                    
                    write_file_enhanced(port_file, port_data, output_format, {
                        'scan_type': 'port_scan',
                        'total_hosts': len(final_subdomains),
                        'hosts_with_open_ports': len(port_results)
                    })
                
            except Exception as e:
                logger.error("Port scan failed", module="Main", error=str(e))
        
        # Statistiques finales
        global_metrics['end_time'] = time.time()
        global_metrics['total_time'] = global_metrics['end_time'] - global_metrics['start_time']
        global_metrics['subdomains_found'] = len(final_subdomains)
        
        if statistics and not silent:
            print_statistics(global_metrics, engine_results)
        
        logger.info("Enumeration completed successfully", module="Main", 
                   total_found=len(final_subdomains), 
                   time_elapsed=global_metrics['total_time'])
        
        return final_subdomains
        
    except KeyboardInterrupt:
        if not silent:
            print("{}\\nEnumeration interrupted by user{}".format(colors.YELLOW, colors.WHITE))
        logger.warning("Enumeration interrupted by user", module="Main")
        return []
        
    except Exception as e:
        error_text = "{}Critical error in main execution: {}{}".format(colors.RED, str(e), colors.WHITE)
        if not silent:
            print(error_text)
        logger.critical("Main execution failed", module="Main", error=str(e))
        return []

def print_statistics(global_metrics, engine_results):
    """Affiche les statistiques détaillées."""
    try:
        print("\\n{}{}=== DETAILED STATISTICS ==={}".format(colors.CYAN, colors.BOLD, colors.WHITE))
        
        # Statistiques globales
        print("{}Global Metrics:{}".format(colors.YELLOW, colors.WHITE))
        print("  • Total execution time: {:.2f} seconds".format(global_metrics['total_time']))
        print("  • Subdomains found: {}".format(global_metrics['subdomains_found']))
        print("  • Total HTTP requests: {}".format(global_metrics['total_requests']))
        print("  • Total errors: {}".format(global_metrics['total_errors']))
        
        if global_metrics['total_requests'] > 0:
            success_rate = ((global_metrics['total_requests'] - global_metrics['total_errors']) / 
                          global_metrics['total_requests']) * 100
            print("  • Success rate: {:.1f}%".format(success_rate))
        
        # Statistiques par moteur
        if engine_results:
            print("\\n{}Engine Performance:{}".format(colors.YELLOW, colors.WHITE))
            for engine_name, results in engine_results.items():
                metrics = results['metrics']
                subdomains = results['subdomains']
                
                print("  {}{}:{}".format(colors.GREEN, engine_name.title(), colors.WHITE))
                print("    - Subdomains found: {}".format(len(subdomains)))
                print("    - Requests sent: {}".format(metrics.get('requests_sent', 0)))
                print("    - Success rate: {:.1f}%".format(metrics.get('success_rate', 0) * 100))
                print("    - Requests/second: {:.2f}".format(metrics.get('requests_per_second', 0)))
                
                if metrics.get('timeouts', 0) > 0:
                    print("    - Timeouts: {}".format(metrics['timeouts']))
                if metrics.get('rate_limited', 0) > 0:
                    print("    - Rate limited: {}".format(metrics['rate_limited']))
        
        print("{}{}================================\\n{}".format(colors.CYAN, colors.BOLD, colors.WHITE))
        
    except Exception as e:
        logger.error("Statistics display failed", module="Statistics", error=str(e))

def interactive_enhanced():
    """Mode interactif amélioré avec gestion d'erreurs complète."""
    try:
        # Parser les arguments
        args = enhanced_parse_args()
        
        # Initialiser les globals avec les paramètres
        initialize_globals(debug=args.debug, no_color=args.no_color)
        
        # Afficher le banner
        if not args.silent:
            jarvis_banner()
        
        # Gestionnaire de signal pour interruption propre
        def signal_handler(signum, frame):
            if not args.silent:
                print("\\n{}Received interrupt signal, cleaning up...{}".format(colors.YELLOW, colors.WHITE))
            logger.info("Received interrupt signal", module="Main", signal=signum)
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)
        
        # Validation des arguments supplémentaire
        if args.threads < 1 or args.threads > 100:
            logger.warning("Thread count adjusted", module="Main", 
                         original=args.threads, adjusted=max(1, min(args.threads, 100)))
            args.threads = max(1, min(args.threads, 100))
        
        if args.timeout < 5:
            logger.warning("Timeout adjusted to minimum", module="Main", 
                         original=args.timeout, adjusted=5)
            args.timeout = 5
        
        # Traiter les presets d'engines
        if args.preset:
            engine_presets = {
                'fast': 'crt,dns',  # Rapide et efficace (gratuit)
                'complete': 'crt,dns,google,wayback,threatcrowd',  # Complet avec nouveaux moteurs
                'free': 'crt,dns,wayback,threatcrowd',  # Tous les moteurs gratuits
                'apis': 'crt,dns,wayback,threatcrowd,virustotal,securitytrails',  # Avec APIs
                'exhaustive': 'crt,dns,google,wayback,threatcrowd,virustotal,securitytrails'  # Tout
            }
            
            if args.preset in engine_presets:
                args.engines = engine_presets[args.preset]
                if not args.silent:
                    print("{}Using preset '{}': {}{}".format(
                        colors.CYAN, args.preset, args.engines, colors.WHITE))
        
        # Si aucun engine spécifié, utiliser le preset 'free' par défaut
        if not args.engines and not args.preset:
            args.engines = 'crt,dns,wayback,threatcrowd'
            if not args.silent:
                print("{}Using default engines (free): {}{}".format(
                    colors.CYAN, args.engines, colors.WHITE))
        
        # Exécuter l'énumération principale
        results = enhanced_main(
            domain=args.domain,
            threads=args.threads,
            output_file=args.output,
            output_format=args.format,
            ports=args.ports,
            silent=args.silent,
            verbose=args.verbose,
            enable_bruteforce=args.bruteforce,
            engines=args.engines,
            timeout=args.timeout,
            delay=args.delay,
            user_agent=args.user_agent,
            statistics=args.statistics,
            debug=args.debug,
            extract_emails=getattr(args, 'extract_emails', False),
            extract_owners=getattr(args, 'extract_owners', False),
            stats_file=getattr(args, 'stats_file', None),
            include_ips=getattr(args, 'include_ips', False),
            intelligence=getattr(args, 'intelligence', False),
            ai_export=getattr(args, 'ai_export', None)
        )
        
        # Résumé final
        if not args.silent:
            if results:
                print("{}\\nEnumeration completed successfully with {} subdomains{}".format(
                    colors.GREEN, len(results), colors.WHITE))
            else:
                print("{}\\nNo subdomains found{}".format(colors.YELLOW, colors.WHITE))
        
        # Logs de métriques finales
        if logger:
            final_metrics = logger.get_metrics()
            logger.success("Session completed", module="Main", 
                         subdomains_found=len(results),
                         total_logs=final_metrics.get('total_messages', 0),
                         errors=final_metrics.get('errors_count', 0))
        
        return results
        
    except SystemExit:
        # Exit normal, ne pas traiter comme une erreur
        return []
    except KeyboardInterrupt:
        if logger:
            logger.warning("Interactive session interrupted", module="Main")
        return []
    except Exception as e:
        error_text = "{}CRITICAL ERROR in interactive mode: {}{}".format(colors.RED, str(e), colors.WHITE)
        print(error_text)
        if logger:
            logger.critical("Interactive mode failed", module="Main", error=str(e))
        return []

if __name__ == "__main__":
    try:
        # Vérifier la version Python
        if sys.version_info < (2, 7):
            print("Error: Python 2.7 or higher required")
            sys.exit(1)
        
        # Lancer le mode interactif amélioré
        interactive_enhanced()
        
    except Exception as e:
        print("FATAL ERROR: {}".format(str(e)))
        sys.exit(1)