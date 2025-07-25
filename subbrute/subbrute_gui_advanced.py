#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SubBrute GUI Advanced v2.1 - Interface Graphique Blindée et Avancée

Interface sophistiquée avec gestion d'erreurs robuste, logging avancé,
fonctionnalités étendues et sauvegarde automatique avec horodatage.

Features:
- Gestion d'erreurs complète avec try/except exhaustifs
- Logging avancé avec rotation et niveaux détaillés
- Fenêtres popup pour résultats, logs et statistiques
- Sauvegarde automatique avec horodatage
- Fonctionnalités avancées: whois, geolocalisation, port scanning
- Alertes et notifications système
- Rapports d'exécution détaillés
- Interface multi-fenêtres avec objets séparés

Author: Enhanced SubBrute Team - Advanced Edition
License: MIT
"""

# Python 2/3 compatibility imports
import sys
import os
import traceback
import socket
import subprocess
import platform
from datetime import datetime, timedelta

if sys.version_info[0] >= 3:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext, font
    import queue
    from urllib.parse import urlparse
    import urllib.request as urllib_request
else:
    import Tkinter as tk
    import ttk
    import tkFileDialog as filedialog
    import tkMessageBox as messagebox
    import ScrolledText as scrolledtext
    import tkFont as font
    import Queue as queue
    from urlparse import urlparse
    import urllib2 as urllib_request

import threading
import time
import json
import csv
import xml.etree.ElementTree as ET
from collections import defaultdict, OrderedDict
import logging
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import tempfile
import hashlib
import re


class AdvancedLogger:
    """
    Système de logging avancé avec rotation, niveaux détaillés et formatage sophistiqué.
    
    Features:
    - Rotation par taille et par temps
    - Niveaux de log personnalisés
    - Formatage coloré pour terminal et GUI
    - Sauvegarde automatique avec horodatage
    - Compression des anciens logs
    - Filtrage par modules et fonctions
    """
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Vert
        'WARNING': '\033[33m',   # Jaune
        'ERROR': '\033[31m',     # Rouge
        'CRITICAL': '\033[35m',  # Magenta
        'SUCCESS': '\033[92m',   # Vert clair
        'SECURITY': '\033[91m',  # Rouge clair
        'PERFORMANCE': '\033[94m', # Bleu
        'RESET': '\033[0m'       # Reset
    }
    
    def __init__(self, name="SubBrute_Advanced", log_dir="logs", debug=True):
        """
        Initialise le logger avancé.
        
        Args:
            name (str): Nom du logger
            log_dir (str): Répertoire des logs
            debug (bool): Mode debug activé
        """
        try:
            self.name = name
            self.debug_enabled = debug
            self.log_dir = log_dir
            self.session_id = self._generate_session_id()
            
            # Créer le répertoire de logs
            self._ensure_log_directory()
            
            # Initialiser les loggers
            self._setup_loggers()
            
            # Initialiser les métriques
            self.metrics = {
                'total_messages': 0,
                'messages_by_level': defaultdict(int),
                'messages_by_module': defaultdict(int),
                'start_time': time.time(),
                'errors_count': 0,
                'warnings_count': 0
            }
            
            self.info("AdvancedLogger initialized successfully", module="AdvancedLogger")
            
        except Exception as e:
            print("CRITICAL ERROR - Failed to initialize AdvancedLogger: {}".format(str(e)))
            print("Traceback: {}".format(traceback.format_exc()))
            raise
    
    def _generate_session_id(self):
        """Génère un ID unique pour cette session."""
        try:
            timestamp = str(int(time.time()))
            random_part = str(hash(str(time.time())))[-6:]
            return "session_{}{}".format(timestamp, random_part)
        except Exception as e:
            return "session_unknown"
    
    def _ensure_log_directory(self):
        """Assure que le répertoire de logs existe."""
        try:
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)
                print("Created log directory: {}".format(self.log_dir))
        except Exception as e:
            print("ERROR - Cannot create log directory {}: {}".format(self.log_dir, str(e)))
            # Fallback vers temp directory
            self.log_dir = tempfile.gettempdir()
            print("Using fallback log directory: {}".format(self.log_dir))
    
    def _setup_loggers(self):
        """Configure les différents loggers avec handlers appropriés."""
        try:
            # Logger principal
            self.logger = logging.getLogger(self.name)
            self.logger.setLevel(logging.DEBUG if self.debug_enabled else logging.INFO)
            self.logger.handlers.clear()
            
            # Format détaillé pour fichiers
            file_formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            
            # Format simplifié pour console
            console_formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(message)s',
                datefmt='%H:%M:%S'
            )
            
            # Handler pour fichier principal avec rotation par taille
            main_log_file = os.path.join(self.log_dir, "subbrute_main.log")
            main_handler = RotatingFileHandler(
                main_log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8'
            )
            main_handler.setLevel(logging.DEBUG)
            main_handler.setFormatter(file_formatter)
            self.logger.addHandler(main_handler)
            
            # Handler pour erreurs uniquement
            error_log_file = os.path.join(self.log_dir, "subbrute_errors.log")
            error_handler = RotatingFileHandler(
                error_log_file, maxBytes=5*1024*1024, backupCount=3, encoding='utf-8'
            )
            error_handler.setLevel(logging.WARNING)
            error_handler.setFormatter(file_formatter)
            self.logger.addHandler(error_handler)
            
            # Handler pour logs de session avec horodatage
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            session_log_file = os.path.join(self.log_dir, "session_{}.log".format(timestamp))
            session_handler = logging.FileHandler(session_log_file, encoding='utf-8')
            session_handler.setLevel(logging.INFO)
            session_handler.setFormatter(file_formatter)
            self.logger.addHandler(session_handler)
            
            # Handler pour console avec couleurs
            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setLevel(logging.DEBUG if self.debug_enabled else logging.INFO)
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
            
            # Logger pour performance
            self.perf_logger = logging.getLogger(self.name + "_performance")
            self.perf_logger.setLevel(logging.INFO)
            perf_log_file = os.path.join(self.log_dir, "performance.log")
            perf_handler = TimedRotatingFileHandler(
                perf_log_file, when='midnight', interval=1, backupCount=7, encoding='utf-8'
            )
            perf_handler.setFormatter(file_formatter)
            self.perf_logger.addHandler(perf_handler)
            
            # Logger pour sécurité
            self.security_logger = logging.getLogger(self.name + "_security")
            self.security_logger.setLevel(logging.WARNING)
            security_log_file = os.path.join(self.log_dir, "security.log")
            security_handler = RotatingFileHandler(
                security_log_file, maxBytes=2*1024*1024, backupCount=10, encoding='utf-8'
            )
            security_handler.setFormatter(file_formatter)
            self.security_logger.addHandler(security_handler)
            
        except Exception as e:
            print("CRITICAL ERROR - Failed to setup loggers: {}".format(str(e)))
            print("Traceback: {}".format(traceback.format_exc()))
            raise
    
    def _log_with_context(self, level, message, module=None, function=None, extra_data=None):
        """Log avec contexte enrichi."""
        try:
            # Mettre à jour les métriques
            self.metrics['total_messages'] += 1
            self.metrics['messages_by_level'][level] += 1
            
            if module:
                self.metrics['messages_by_module'][module] += 1
            
            if level in ['ERROR', 'CRITICAL']:
                self.metrics['errors_count'] += 1
            elif level == 'WARNING':
                self.metrics['warnings_count'] += 1
            
            # Construire le message enrichi
            enriched_message = str(message)
            
            if module:
                enriched_message = "[{}] {}".format(module, enriched_message)
            
            if function:
                enriched_message = "{}() - {}".format(function, enriched_message)
            
            if extra_data:
                if isinstance(extra_data, dict):
                    extra_str = " | ".join("{}={}".format(k, v) for k, v in extra_data.items())
                    enriched_message = "{} | {}".format(enriched_message, extra_str)
                else:
                    enriched_message = "{} | {}".format(enriched_message, str(extra_data))
            
            # Logger selon le niveau
            logger_method = getattr(self.logger, level.lower(), self.logger.info)
            logger_method(enriched_message)
            
            # Logger spécialisé selon le type
            if level == 'SECURITY':
                self.security_logger.warning(enriched_message)
            elif level == 'PERFORMANCE':
                self.perf_logger.info(enriched_message)
            
            # Affichage coloré dans le terminal
            if sys.stderr.isatty():  # Si c'est un terminal
                color = self.COLORS.get(level, self.COLORS['RESET'])
                reset = self.COLORS['RESET']
                colored_message = "{}[{}]{} {}".format(color, level, reset, enriched_message)
                print(colored_message, file=sys.stderr)
            
        except Exception as e:
            print("ERROR in _log_with_context: {}".format(str(e)))
            print("Original message: {}".format(str(message)))
    
    def debug(self, message, module=None, function=None, **kwargs):
        """Log debug avec contexte."""
        if self.debug_enabled:
            self._log_with_context('DEBUG', message, module, function, kwargs)
    
    def info(self, message, module=None, function=None, **kwargs):
        """Log info avec contexte."""
        self._log_with_context('INFO', message, module, function, kwargs)
    
    def warning(self, message, module=None, function=None, **kwargs):
        """Log warning avec contexte."""
        self._log_with_context('WARNING', message, module, function, kwargs)
    
    def error(self, message, module=None, function=None, **kwargs):
        """Log error avec contexte."""
        self._log_with_context('ERROR', message, module, function, kwargs)
    
    def critical(self, message, module=None, function=None, **kwargs):
        """Log critical avec contexte."""
        self._log_with_context('CRITICAL', message, module, function, kwargs)
    
    def success(self, message, module=None, function=None, **kwargs):
        """Log success avec contexte."""
        self._log_with_context('SUCCESS', message, module, function, kwargs)
    
    def security(self, message, module=None, function=None, **kwargs):
        """Log security event avec contexte."""
        self._log_with_context('SECURITY', message, module, function, kwargs)
    
    def performance(self, message, module=None, function=None, **kwargs):
        """Log performance metric avec contexte."""
        self._log_with_context('PERFORMANCE', message, module, function, kwargs)
    
    def get_metrics(self):
        """Retourne les métriques de logging."""
        try:
            uptime = time.time() - self.metrics['start_time']
            self.metrics['uptime_seconds'] = uptime
            return dict(self.metrics)
        except Exception as e:
            return {'error': str(e)}
    
    def export_metrics(self, filepath):
        """Exporte les métriques vers un fichier JSON."""
        try:
            metrics = self.get_metrics()
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(metrics, f, indent=2, default=str)
            self.info("Metrics exported to {}".format(filepath), module="AdvancedLogger")
            return True
        except Exception as e:
            self.error("Failed to export metrics: {}".format(str(e)), module="AdvancedLogger")
            return False


class SecurityValidator:
    """
    Validateur de sécurité pour les entrées utilisateur.
    
    Vérifie et sanitise toutes les entrées pour éviter les injections
    et autres attaques de sécurité.
    """
    
    # Patterns dangereux
    DANGEROUS_PATTERNS = [
        r'[;&|`$()\\]',  # Caractères d'injection shell
        r'<script[^>]*>',  # Injection XSS
        r'javascript:',  # URL javascript
        r'vbscript:',  # URL vbscript
        r'\.\.[\/\\]',  # Directory traversal
        r'\x00',  # Null bytes
    ]
    
    # Patterns valides pour domaines
    DOMAIN_PATTERN = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    
    def __init__(self, logger=None):
        """Initialise le validateur de sécurité."""
        self.logger = logger
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.DANGEROUS_PATTERNS]
        self.domain_regex = re.compile(self.DOMAIN_PATTERN)
    
    def _log_security_event(self, event_type, message, data=None):
        """Log d'événement de sécurité."""
        if self.logger:
            self.logger.security("SECURITY_EVENT: {} - {}".format(event_type, message), 
                               module="SecurityValidator", 
                               event_type=event_type, 
                               input_data=str(data)[:100] if data else None)
    
    def validate_domain(self, domain):
        """
        Valide un nom de domaine.
        
        Args:
            domain (str): Domaine à valider
            
        Returns:
            tuple: (is_valid, sanitized_domain, error_message)
        """
        try:
            if not domain or not isinstance(domain, str):
                return False, "", "Domain must be a non-empty string"
            
            # Nettoyer les espaces
            clean_domain = domain.strip().lower()
            
            # Vérifier la longueur
            if len(clean_domain) > 253:
                self._log_security_event("INVALID_DOMAIN_LENGTH", "Domain too long", clean_domain)
                return False, "", "Domain name too long (max 253 characters)"
            
            if len(clean_domain) < 1:
                return False, "", "Domain name too short"
            
            # Vérifier les patterns dangereux
            for pattern in self.compiled_patterns:
                if pattern.search(clean_domain):
                    self._log_security_event("DANGEROUS_PATTERN_DETECTED", "Dangerous pattern in domain", clean_domain)
                    return False, "", "Domain contains dangerous characters"
            
            # Vérifier le format du domaine
            if not self.domain_regex.match(clean_domain):
                self._log_security_event("INVALID_DOMAIN_FORMAT", "Invalid domain format", clean_domain)
                return False, "", "Invalid domain name format"
            
            return True, clean_domain, None
            
        except Exception as e:
            self._log_security_event("VALIDATION_ERROR", "Exception during domain validation", str(e))
            return False, "", "Validation error: {}".format(str(e))
    
    def validate_file_path(self, filepath):
        """
        Valide un chemin de fichier.
        
        Args:
            filepath (str): Chemin à valider
            
        Returns:
            tuple: (is_valid, sanitized_path, error_message)
        """
        try:
            if not filepath or not isinstance(filepath, str):
                return False, "", "File path must be a non-empty string"
            
            # Nettoyer le chemin
            clean_path = filepath.strip()
            
            # Vérifier les patterns dangereux
            for pattern in self.compiled_patterns:
                if pattern.search(clean_path):
                    self._log_security_event("DANGEROUS_PATH_PATTERN", "Dangerous pattern in path", clean_path)
                    return False, "", "File path contains dangerous characters"
            
            # Vérifier directory traversal
            if ".." in clean_path:
                self._log_security_event("DIRECTORY_TRAVERSAL_ATTEMPT", "Directory traversal in path", clean_path)
                return False, "", "Directory traversal not allowed"
            
            # Normaliser le chemin
            try:
                normalized_path = os.path.normpath(clean_path)
                # Vérifier que le chemin normalisé ne sort pas du répertoire courant
                if normalized_path.startswith('..'):
                    self._log_security_event("PATH_ESCAPE_ATTEMPT", "Path escape attempt", clean_path)
                    return False, "", "Path escape not allowed"
            except Exception as e:
                return False, "", "Path normalization failed: {}".format(str(e))
            
            return True, normalized_path, None
            
        except Exception as e:
            self._log_security_event("PATH_VALIDATION_ERROR", "Exception during path validation", str(e))
            return False, "", "Path validation error: {}".format(str(e))
    
    def validate_integer(self, value, min_val=None, max_val=None, field_name="value"):
        """
        Valide une valeur entière.
        
        Args:
            value: Valeur à valider
            min_val (int): Valeur minimale
            max_val (int): Valeur maximale
            field_name (str): Nom du champ pour les messages d'erreur
            
        Returns:
            tuple: (is_valid, validated_int, error_message)
        """
        try:
            # Conversion en entier
            try:
                if isinstance(value, str):
                    clean_value = value.strip()
                    int_value = int(clean_value)
                else:
                    int_value = int(value)
            except (ValueError, TypeError):
                return False, 0, "{} must be a valid integer".format(field_name)
            
            # Vérifier les limites
            if min_val is not None and int_value < min_val:
                return False, min_val, "{} must be at least {}".format(field_name, min_val)
            
            if max_val is not None and int_value > max_val:
                return False, max_val, "{} must be at most {}".format(field_name, max_val)
            
            return True, int_value, None
            
        except Exception as e:
            return False, 0, "Integer validation error: {}".format(str(e))
    
    def sanitize_text(self, text, max_length=1000):
        """
        Sanitise du texte libre.
        
        Args:
            text (str): Texte à sanitiser
            max_length (int): Longueur maximale
            
        Returns:
            str: Texte sanitisé
        """
        try:
            if not text or not isinstance(text, str):
                return ""
            
            # Nettoyer et limiter la longueur
            clean_text = text.strip()[:max_length]
            
            # Supprimer les caractères de contrôle sauf \n, \r, \t
            clean_text = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', clean_text)
            
            return clean_text
            
        except Exception as e:
            if self.logger:
                self.logger.error("Text sanitization error: {}".format(str(e)), module="SecurityValidator")
            return ""


class AdvancedTooltip:
    """
    Système de tooltip avancé avec positionnement intelligent et style moderne.
    """
    
    def __init__(self, widget, text, delay=500, wraplength=300):
        """Initialise le tooltip."""
        self.widget = widget
        self.text = text
        self.delay = delay
        self.wraplength = wraplength
        self.tooltip_window = None
        self.after_id = None
        
        # Bind events
        self.widget.bind("<Enter>", self.on_enter)
        self.widget.bind("<Leave>", self.on_leave)
        self.widget.bind("<Motion>", self.on_motion)
    
    def on_enter(self, event=None):
        """Gestionnaire d'entrée de souris."""
        self.schedule_tooltip()
    
    def on_leave(self, event=None):
        """Gestionnaire de sortie de souris."""
        self.cancel_tooltip()
        self.hide_tooltip()
    
    def on_motion(self, event=None):
        """Gestionnaire de mouvement de souris."""
        self.cancel_tooltip()
        self.schedule_tooltip()
    
    def schedule_tooltip(self):
        """Programme l'affichage du tooltip."""
        self.cancel_tooltip()
        self.after_id = self.widget.after(self.delay, self.show_tooltip)
    
    def cancel_tooltip(self):
        """Annule l'affichage du tooltip."""
        if self.after_id:
            self.widget.after_cancel(self.after_id)
            self.after_id = None
    
    def show_tooltip(self):
        """Affiche le tooltip."""
        if self.tooltip_window:
            return
        
        try:
            # Obtenir la position de la souris
            x = self.widget.winfo_rootx() + 25
            y = self.widget.winfo_rooty() + 25
            
            # Créer la fenetre tooltip
            self.tooltip_window = tk.Toplevel(self.widget)
            self.tooltip_window.wm_overrideredirect(True)
            self.tooltip_window.wm_attributes("-topmost", True)
            
            # Style moderne
            label = tk.Label(self.tooltip_window, 
                           text=self.text,
                           background="#FFFFDD",
                           foreground="#333333",
                           relief="solid",
                           borderwidth=1,
                           font=("Arial", 9),
                           wraplength=self.wraplength,
                           justify="left",
                           padx=8,
                           pady=4)
            label.pack()
            
            # Ajuster la position si nécessaire
            screen_width = self.tooltip_window.winfo_screenwidth()
            screen_height = self.tooltip_window.winfo_screenheight()
            
            self.tooltip_window.update_idletasks()
            tooltip_width = self.tooltip_window.winfo_width()
            tooltip_height = self.tooltip_window.winfo_height()
            
            if x + tooltip_width > screen_width:
                x = screen_width - tooltip_width - 10
            if y + tooltip_height > screen_height:
                y = screen_height - tooltip_height - 10
            
            self.tooltip_window.wm_geometry("+{}+{}".format(x, y))
            
        except Exception as e:
            print("Error showing tooltip: {}".format(str(e)))
    
    def hide_tooltip(self):
        """Cache le tooltip."""
        if self.tooltip_window:
            try:
                self.tooltip_window.destroy()
            except:
                pass
            finally:
                self.tooltip_window = None
    
    def update_text(self, new_text):
        """Met à jour le texte du tooltip."""
        self.text = new_text
    
    def security(self, message, module=None, function=None, **kwargs):
        """Log security avec contexte."""
        self._log_with_context('SECURITY', message, module, function, kwargs)
    
    def performance(self, message, module=None, function=None, **kwargs):
        """Log performance avec contexte."""
        self._log_with_context('PERFORMANCE', message, module, function, kwargs)
    
    def exception(self, message, module=None, function=None, **kwargs):
        """Log exception avec traceback complet."""
        try:
            tb = traceback.format_exc()
            full_message = "{} | TRACEBACK: {}".format(str(message), tb)
            self._log_with_context('ERROR', full_message, module, function, kwargs)
        except Exception as e:
            print("ERROR in exception logging: {}".format(str(e)))
    
    def get_metrics(self):
        """Retourne les métriques de logging."""
        try:
            current_time = time.time()
            self.metrics['uptime'] = current_time - self.metrics['start_time']
            self.metrics['messages_per_second'] = self.metrics['total_messages'] / self.metrics['uptime'] if self.metrics['uptime'] > 0 else 0
            return dict(self.metrics)
        except Exception as e:
            self.error("Failed to get metrics", function="get_metrics", error=str(e))
            return {}


class SecurityValidator:
    """
    Validateur de sécurité pour les entrées utilisateur et les données.
    
    Valide les domaines, URLs, fichiers, et autres entrées pour éviter
    les vulnérabilités de sécurité et les erreurs d'exécution.
    """
    
    def __init__(self, logger):
        """
        Initialise le validateur de sécurité.
        
        Args:
            logger: Instance de AdvancedLogger
        """
        try:
            self.logger = logger
            self.domain_regex = re.compile(
                r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
            )
            self.ip_regex = re.compile(
                r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            )
            
            # Listes noires de sécurité
            self.blocked_domains = {
                'localhost', '127.0.0.1', '0.0.0.0', '::1',
                'local', 'internal', 'private'
            }
            
            self.dangerous_chars = ['<', '>', '&', '"', "'", '`', ';', '|', '&', '$']
            
            self.logger.debug("SecurityValidator initialized", module="SecurityValidator")
            
        except Exception as e:
            self.logger.exception("Failed to initialize SecurityValidator", module="SecurityValidator")
            raise
    
    def validate_domain(self, domain):
        """
        Valide un nom de domaine.
        
        Args:
            domain (str): Domaine à valider
            
        Returns:
            tuple: (is_valid, sanitized_domain, error_message)
        """
        try:
            if not domain or not isinstance(domain, str):
                return False, None, "Domain must be a non-empty string"
            
            # Nettoyer et normaliser
            sanitized = domain.strip().lower()
            
            # Vérifier la longueur
            if len(sanitized) > 253:
                self.logger.security("Domain too long", module="SecurityValidator", domain=sanitized[:50])
                return False, None, "Domain name too long (max 253 characters)"
            
            if len(sanitized) < 3:
                return False, None, "Domain name too short (min 3 characters)"
            
            # Vérifier les caractères dangereux
            for char in self.dangerous_chars:
                if char in sanitized:
                    self.logger.security("Dangerous character in domain", module="SecurityValidator", 
                                        domain=sanitized, char=char)
                    return False, None, "Domain contains dangerous character: {}".format(char)
            
            # Vérifier le format avec regex
            if not self.domain_regex.match(sanitized):
                return False, None, "Invalid domain format"
            
            # Vérifier la liste noire
            if sanitized in self.blocked_domains:
                self.logger.security("Blocked domain attempted", module="SecurityValidator", domain=sanitized)
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
            
            self.logger.debug("Domain validation successful", module="SecurityValidator", domain=sanitized)
            return True, sanitized, None
            
        except Exception as e:
            self.logger.exception("Error validating domain", module="SecurityValidator", domain=str(domain))
            return False, None, "Validation error: {}".format(str(e))
    
    def validate_file_path(self, file_path, must_exist=True, readable=True):
        """
        Valide un chemin de fichier.
        
        Args:
            file_path (str): Chemin du fichier
            must_exist (bool): Le fichier doit exister
            readable (bool): Le fichier doit être lisible
            
        Returns:
            tuple: (is_valid, sanitized_path, error_message)
        """
        try:
            if not file_path or not isinstance(file_path, str):
                return False, None, "File path must be a non-empty string"
            
            # Nettoyer le chemin
            sanitized = os.path.normpath(file_path.strip())
            
            # Vérifier les caractères dangereux
            for char in ['<', '>', '|', '"', '?', '*']:
                if char in sanitized:
                    self.logger.security("Dangerous character in file path", 
                                        module="SecurityValidator", path=sanitized, char=char)
                    return False, None, "File path contains dangerous character: {}".format(char)
            
            # Vérifier les tentatives de directory traversal
            if '..' in sanitized or sanitized.startswith('/etc/') or sanitized.startswith('/sys/'):
                self.logger.security("Directory traversal attempt", module="SecurityValidator", path=sanitized)
                return False, None, "File path contains security risk"
            
            # Vérifier l'existence si requis
            if must_exist and not os.path.exists(sanitized):
                return False, None, "File does not exist: {}".format(sanitized)
            
            # Vérifier la lisibilité si requis
            if readable and os.path.exists(sanitized) and not os.access(sanitized, os.R_OK):
                return False, None, "File is not readable: {}".format(sanitized)
            
            # Vérifier que c'est bien un fichier et non un répertoire
            if os.path.exists(sanitized) and not os.path.isfile(sanitized):
                return False, None, "Path is not a regular file: {}".format(sanitized)
            
            self.logger.debug("File path validation successful", module="SecurityValidator", path=sanitized)
            return True, sanitized, None
            
        except Exception as e:
            self.logger.exception("Error validating file path", module="SecurityValidator", path=str(file_path))
            return False, None, "Validation error: {}".format(str(e))
    
    def validate_integer(self, value, min_val=None, max_val=None, name="value"):
        """
        Valide un entier avec bornes optionnelles.
        
        Args:
            value: Valeur à valider
            min_val (int): Valeur minimale
            max_val (int): Valeur maximale
            name (str): Nom du paramètre pour les messages
            
        Returns:
            tuple: (is_valid, sanitized_value, error_message)
        """
        try:
            if value is None:
                return False, None, "{} cannot be None".format(name)
            
            # Convertir en entier
            try:
                sanitized = int(value)
            except (ValueError, TypeError) as e:
                return False, None, "{} must be a valid integer".format(name)
            
            # Vérifier les bornes
            if min_val is not None and sanitized < min_val:
                return False, None, "{} must be >= {}".format(name, min_val)
            
            if max_val is not None and sanitized > max_val:
                return False, None, "{} must be <= {}".format(name, max_val)
            
            self.logger.debug("Integer validation successful", module="SecurityValidator", 
                            name=name, value=sanitized)
            return True, sanitized, None
            
        except Exception as e:
            self.logger.exception("Error validating integer", module="SecurityValidator", 
                                name=name, value=str(value))
            return False, None, "Validation error: {}".format(str(e))


class AdvancedTooltip:
    """
    Tooltip avancé avec style moderne et fonctionnalités étendues.
    
    Features:
    - Multi-lignes avec formatage
    - Délai personnalisable
    - Position intelligente
    - Style moderne avec ombres
    - Support des raccourcis clavier
    """
    
    def __init__(self, widget, text, delay=750, wraplength=300):
        """
        Initialise le tooltip avancé.
        
        Args:
            widget: Widget parent
            text (str): Texte du tooltip (peut contenir \\n)
            delay (int): Délai avant affichage en ms
            wraplength (int): Largeur max du texte
        """
        try:
            self.widget = widget
            self.text = text
            self.delay = delay
            self.wraplength = wraplength
            self.tooltip_window = None
            self.id = None
            
            # Bind events
            self.widget.bind('<Enter>', self.on_enter)
            self.widget.bind('<Leave>', self.on_leave)
            self.widget.bind('<Motion>', self.on_motion)
            self.widget.bind('<Button-1>', self.on_click)
            
        except Exception as e:
            print("Error initializing AdvancedTooltip: {}".format(str(e)))
    
    def on_enter(self, event=None):
        """Gère l'entrée de la souris."""
        try:
            self.schedule_tooltip()
        except Exception as e:
            print("Error in tooltip on_enter: {}".format(str(e)))
    
    def on_leave(self, event=None):
        """Gère la sortie de la souris."""
        try:
            self.cancel_tooltip()
            self.hide_tooltip()
        except Exception as e:
            print("Error in tooltip on_leave: {}".format(str(e)))
    
    def on_motion(self, event=None):
        """Gère le mouvement de la souris."""
        try:
            self.cancel_tooltip()
            self.schedule_tooltip()
        except Exception as e:
            print("Error in tooltip on_motion: {}".format(str(e)))
    
    def on_click(self, event=None):
        """Gère le clic (cache le tooltip)."""
        try:
            self.hide_tooltip()
        except Exception as e:
            print("Error in tooltip on_click: {}".format(str(e)))
    
    def schedule_tooltip(self):
        """Programme l'affichage du tooltip."""
        try:
            self.cancel_tooltip()
            self.id = self.widget.after(self.delay, self.show_tooltip)
        except Exception as e:
            print("Error scheduling tooltip: {}".format(str(e)))
    
    def cancel_tooltip(self):
        """Annule l'affichage programmé."""
        try:
            if self.id:
                self.widget.after_cancel(self.id)
                self.id = None
        except Exception as e:
            print("Error canceling tooltip: {}".format(str(e)))
    
    def show_tooltip(self):
        """Affiche le tooltip."""
        try:
            if self.tooltip_window or not self.text:
                return
            
            # Calculer la position
            x = self.widget.winfo_rootx() + 25
            y = self.widget.winfo_rooty() + 25
            
            # Créer la fenêtre tooltip
            self.tooltip_window = tw = tk.Toplevel(self.widget)
            tw.wm_overrideredirect(True)
            tw.wm_attributes('-alpha', 0.95)  # Transparence
            
            # Créer le contenu avec style moderne
            frame = tk.Frame(tw, background='#2c3e50', relief='solid', borderwidth=1)
            frame.pack()
            
            label = tk.Label(frame, text=self.text, justify='left',
                           background='#2c3e50', foreground='#ecf0f1',
                           font=('Segoe UI', 9), padx=8, pady=6,
                           wraplength=self.wraplength)
            label.pack()
            
            # Ajuster la position pour éviter de sortir de l'écran
            tw.update_idletasks()
            width = tw.winfo_reqwidth()
            height = tw.winfo_reqheight()
            
            screen_width = tw.winfo_screenwidth()
            screen_height = tw.winfo_screenheight()
            
            if x + width > screen_width:
                x = screen_width - width - 10
            if y + height > screen_height:
                y = y - height - 30
            
            tw.wm_geometry("+{}+{}".format(x, y))
            
        except Exception as e:
            print("Error showing tooltip: {}".format(str(e)))
    
    def hide_tooltip(self):
        """Cache le tooltip."""
        try:
            if self.tooltip_window:
                self.tooltip_window.destroy()
                self.tooltip_window = None
        except Exception as e:
            print("Error hiding tooltip: {}".format(str(e)))


class ResultWindow:
    """
    Fenêtre popup dédiée à l'affichage détaillé des résultats.
    
    Features:
    - Affichage en temps réel des résultats
    - Filtrage et recherche avancés
    - Export direct depuis la fenêtre
    - Statistiques intégrées
    - Interface redimensionnable
    """
    
    def __init__(self, parent, logger, title="Résultats d'Énumération"):
        """
        Initialise la fenêtre de résultats.
        
        Args:
            parent: Fenêtre parent
            logger: Instance de AdvancedLogger
            title (str): Titre de la fenêtre
        """
        try:
            self.parent = parent
            self.logger = logger
            self.results = []
            self.filtered_results = []
            
            # Créer la fenêtre
            self.window = tk.Toplevel(parent)
            self.window.title(title)
            self.window.geometry("1000x600")
            self.window.minsize(800, 400)
            
            # Configurer l'icône et les attributs
            try:
                self.window.iconbitmap(default='subbrute.ico')
            except:
                pass  # Ignore si l'icône n'existe pas
            
            self.window.transient(parent)
            self.window.grab_set()
            
            # Variables
            self.filter_var = tk.StringVar()
            self.filter_type_var = tk.StringVar(value="all")
            self.results_count_var = tk.StringVar(value="Résultats: 0")
            
            # Créer l'interface
            self._create_interface()
            self._setup_bindings()
            
            # Centrer la fenêtre
            self._center_window()
            
            self.logger.info("ResultWindow initialized", module="ResultWindow")
            
        except Exception as e:
            self.logger.exception("Failed to initialize ResultWindow", module="ResultWindow")
            raise
    
    def _create_interface(self):
        """Crée l'interface de la fenêtre de résultats."""
        try:
            # Frame principal
            main_frame = ttk.Frame(self.window)
            main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Barre d'outils
            toolbar = ttk.Frame(main_frame)
            toolbar.pack(fill=tk.X, pady=(0, 10))
            
            # Filtres
            filter_frame = ttk.LabelFrame(toolbar, text="Filtres", padding=5)
            filter_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
            
            ttk.Label(filter_frame, text="Recherche:").pack(side=tk.LEFT, padx=(0, 5))
            
            filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=30)
            filter_entry.pack(side=tk.LEFT, padx=(0, 10))
            filter_entry.bind('<KeyRelease>', self._on_filter_change)
            
            AdvancedTooltip(filter_entry, "Rechercher dans les hostnames et adresses IP\\nSupportes les expressions régulières")
            
            # Options de filtre
            ttk.Radiobutton(filter_frame, text="Tout", variable=self.filter_type_var, value="all",
                           command=self._apply_filter).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Radiobutton(filter_frame, text="Hostnames", variable=self.filter_type_var, value="hostname",
                           command=self._apply_filter).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Radiobutton(filter_frame, text="IPs", variable=self.filter_type_var, value="ip",
                           command=self._apply_filter).pack(side=tk.LEFT, padx=(0, 5))
            
            # Actions
            actions_frame = ttk.LabelFrame(toolbar, text="Actions", padding=5)
            actions_frame.pack(side=tk.RIGHT)
            
            ttk.Button(actions_frame, text="Export CSV", command=self._export_csv).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(actions_frame, text="Export JSON", command=self._export_json).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(actions_frame, text="Copier Sélection", command=self._copy_selection).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(actions_frame, text="Rafraîchir", command=self._refresh).pack(side=tk.LEFT)
            
            # Statistiques
            stats_frame = ttk.Frame(main_frame)
            stats_frame.pack(fill=tk.X, pady=(0, 10))
            
            ttk.Label(stats_frame, textvariable=self.results_count_var, font=('Segoe UI', 10, 'bold')).pack(side=tk.LEFT)
            
            self.status_var = tk.StringVar(value="Prêt")
            ttk.Label(stats_frame, textvariable=self.status_var).pack(side=tk.RIGHT)
            
            # TreeView pour les résultats
            tree_frame = ttk.Frame(main_frame)
            tree_frame.pack(fill=tk.BOTH, expand=True)
            
            # Colonnes
            columns = ("hostname", "record_type", "addresses", "timestamp", "response_time", "ttl")
            self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=20)
            
            # Configuration des colonnes
            self.tree.heading("hostname", text="Hostname", command=lambda: self._sort_column("hostname"))
            self.tree.heading("record_type", text="Type", command=lambda: self._sort_column("record_type"))
            self.tree.heading("addresses", text="Adresses IP", command=lambda: self._sort_column("addresses"))
            self.tree.heading("timestamp", text="Timestamp", command=lambda: self._sort_column("timestamp"))
            self.tree.heading("response_time", text="Temps (ms)", command=lambda: self._sort_column("response_time"))
            self.tree.heading("ttl", text="TTL", command=lambda: self._sort_column("ttl"))
            
            self.tree.column("hostname", width=250, minwidth=150)
            self.tree.column("record_type", width=80, minwidth=60)
            self.tree.column("addresses", width=200, minwidth=120)
            self.tree.column("timestamp", width=120, minwidth=100)
            self.tree.column("response_time", width=100, minwidth=80)
            self.tree.column("ttl", width=80, minwidth=60)
            
            # Scrollbars
            v_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
            h_scrollbar = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
            self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
            
            # Pack TreeView et scrollbars
            self.tree.grid(row=0, column=0, sticky="nsew")
            v_scrollbar.grid(row=0, column=1, sticky="ns")
            h_scrollbar.grid(row=1, column=0, sticky="ew")
            
            tree_frame.rowconfigure(0, weight=1)
            tree_frame.columnconfigure(0, weight=1)
            
            # Barre de statut
            status_frame = ttk.Frame(main_frame)
            status_frame.pack(fill=tk.X, pady=(10, 0))
            
            self.progress_var = tk.DoubleVar()
            self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100)
            self.progress_bar.pack(fill=tk.X)
            
        except Exception as e:
            self.logger.exception("Error creating ResultWindow interface", module="ResultWindow")
            raise
    
    def _setup_bindings(self):
        """Configure les événements et raccourcis."""
        try:
            # Double-clic pour détails
            self.tree.bind("<Double-1>", self._on_item_double_click)
            
            # Menu contextuel
            self.tree.bind("<Button-3>", self._show_context_menu)
            
            # Raccourcis clavier
            self.window.bind('<Control-f>', lambda e: filter_entry.focus())
            self.window.bind('<Control-c>', lambda e: self._copy_selection())
            self.window.bind('<Control-s>', lambda e: self._export_csv())
            self.window.bind('<F5>', lambda e: self._refresh())
            self.window.bind('<Escape>', lambda e: self.window.destroy())
            
            # Gestion de la fermeture
            self.window.protocol("WM_DELETE_WINDOW", self._on_closing)
            
        except Exception as e:
            self.logger.exception("Error setting up ResultWindow bindings", module="ResultWindow")
    
    def _center_window(self):
        """Centre la fenêtre sur l'écran."""
        try:
            self.window.update_idletasks()
            width = self.window.winfo_width()
            height = self.window.winfo_height()
            x = (self.window.winfo_screenwidth() - width) // 2
            y = (self.window.winfo_screenheight() - height) // 2
            self.window.geometry("{}x{}+{}+{}".format(width, height, x, y))
        except Exception as e:
            self.logger.error("Error centering ResultWindow", module="ResultWindow", error=str(e))
    
    def add_result(self, result):
        """
        Ajoute un résultat à la fenêtre.
        
        Args:
            result (dict): Données du résultat
        """
        try:
            # Valider le résultat
            if not isinstance(result, dict):
                self.logger.warning("Invalid result format", module="ResultWindow", result_type=type(result))
                return
            
            required_fields = ['hostname', 'record_type', 'addresses', 'timestamp']
            for field in required_fields:
                if field not in result:
                    self.logger.warning("Missing required field in result", module="ResultWindow", field=field)
                    return
            
            # Enrichir le résultat avec des données supplémentaires
            enriched_result = result.copy()
            enriched_result['response_time'] = result.get('response_time', 'N/A')
            enriched_result['ttl'] = result.get('ttl', 'N/A')
            enriched_result['id'] = len(self.results) + 1
            
            # Ajouter à la liste
            self.results.append(enriched_result)
            
            # Appliquer le filtre
            self._apply_filter()
            
            # Mettre à jour les statistiques
            self._update_stats()
            
            # Auto-scroll vers le dernier élément
            if self.tree.get_children():
                self.tree.see(self.tree.get_children()[-1])
            
            self.logger.debug("Result added to ResultWindow", module="ResultWindow", 
                            hostname=result['hostname'])
            
        except Exception as e:
            self.logger.exception("Error adding result to ResultWindow", module="ResultWindow", 
                                result=str(result))
    
    def _on_filter_change(self, event=None):
        """Gère les changements de filtre avec délai."""
        try:
            # Annuler le timer précédent
            if hasattr(self, '_filter_timer'):
                self.window.after_cancel(self._filter_timer)
            
            # Programmer l'application du filtre avec délai
            self._filter_timer = self.window.after(300, self._apply_filter)
            
        except Exception as e:
            self.logger.error("Error in filter change handler", module="ResultWindow", error=str(e))
    
    def _apply_filter(self):
        """Applique le filtre aux résultats."""
        try:
            filter_text = self.filter_var.get().lower().strip()
            filter_type = self.filter_type_var.get()
            
            # Effacer l'affichage actuel
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Filtrer les résultats
            self.filtered_results = []
            
            for result in self.results:
                show_result = False
                
                if not filter_text:
                    show_result = True
                else:
                    # Appliquer le filtre selon le type
                    if filter_type == "all":
                        if (filter_text in result['hostname'].lower() or 
                            any(filter_text in addr.lower() for addr in result['addresses']) or
                            filter_text in result['record_type'].lower()):
                            show_result = True
                    elif filter_type == "hostname":
                        if filter_text in result['hostname'].lower():
                            show_result = True
                    elif filter_type == "ip":
                        if any(filter_text in addr.lower() for addr in result['addresses']):
                            show_result = True
                
                if show_result:
                    self.filtered_results.append(result)
                    
                    # Ajouter à l'affichage
                    self.tree.insert("", tk.END, values=(
                        result['hostname'],
                        result['record_type'],
                        ', '.join(result['addresses']),
                        result['timestamp'],
                        result.get('response_time', 'N/A'),
                        result.get('ttl', 'N/A')
                    ))
            
            # Mettre à jour le compteur
            self.results_count_var.set("Résultats: {} / {}".format(
                len(self.filtered_results), len(self.results)))
            
            self.logger.debug("Filter applied", module="ResultWindow", 
                            total=len(self.results), filtered=len(self.filtered_results))
            
        except Exception as e:
            self.logger.exception("Error applying filter", module="ResultWindow")
    
    def _sort_column(self, col):
        """Trie les résultats par colonne."""
        try:
            # Implementation du tri
            self.logger.debug("Sorting by column", module="ResultWindow", column=col)
            # TODO: Implémenter le tri
            
        except Exception as e:
            self.logger.exception("Error sorting column", module="ResultWindow", column=col)
    
    def _on_item_double_click(self, event):
        """Gère le double-clic sur un élément."""
        try:
            selection = self.tree.selection()
            if not selection:
                return
            
            item = self.tree.item(selection[0])
            hostname = item['values'][0]
            
            # Trouver le résultat complet
            result = next((r for r in self.filtered_results if r['hostname'] == hostname), None)
            if result:
                self._show_result_details(result)
            
        except Exception as e:
            self.logger.exception("Error handling double-click", module="ResultWindow")
    
    def _show_result_details(self, result):
        """Affiche les détails d'un résultat dans une popup."""
        try:
            details_window = tk.Toplevel(self.window)
            details_window.title("Détails - {}".format(result['hostname']))
            details_window.geometry("600x500")
            details_window.transient(self.window)
            details_window.grab_set()
            
            # Créer le contenu
            main_frame = ttk.Frame(details_window, padding=20)
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            # Informations principales
            info_frame = ttk.LabelFrame(main_frame, text="Informations Principales", padding=10)
            info_frame.pack(fill=tk.X, pady=(0, 10))
            
            ttk.Label(info_frame, text="Hostname:", font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=2)
            ttk.Label(info_frame, text=result['hostname']).grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)
            
            ttk.Label(info_frame, text="Type d'enregistrement:", font=('Segoe UI', 10, 'bold')).grid(row=1, column=0, sticky=tk.W, pady=2)
            ttk.Label(info_frame, text=result['record_type']).grid(row=1, column=1, sticky=tk.W, padx=(10, 0), pady=2)
            
            ttk.Label(info_frame, text="Timestamp:", font=('Segoe UI', 10, 'bold')).grid(row=2, column=0, sticky=tk.W, pady=2)
            ttk.Label(info_frame, text=result['timestamp']).grid(row=2, column=1, sticky=tk.W, padx=(10, 0), pady=2)
            
            # Adresses IP
            ip_frame = ttk.LabelFrame(main_frame, text="Adresses IP", padding=10)
            ip_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
            
            ip_text = scrolledtext.ScrolledText(ip_frame, height=8, width=60)
            ip_text.pack(fill=tk.BOTH, expand=True)
            
            for i, addr in enumerate(result['addresses']):
                ip_text.insert(tk.END, "{}. {}\n".format(i+1, addr))
            
            ip_text.config(state=tk.DISABLED)
            
            # Boutons d'action
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X, pady=(10, 0))
            
            ttk.Button(button_frame, text="Copier Hostname", 
                      command=lambda: self._copy_to_clipboard(result['hostname'])).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(button_frame, text="Copier IPs", 
                      command=lambda: self._copy_to_clipboard('\n'.join(result['addresses']))).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(button_frame, text="Whois", 
                      command=lambda: self._show_whois(result['hostname'])).pack(side=tk.LEFT, padx=(0, 5))
            ttk.Button(button_frame, text="Fermer", 
                      command=details_window.destroy).pack(side=tk.RIGHT)
            
        except Exception as e:
            self.logger.exception("Error showing result details", module="ResultWindow")
    
    def _show_context_menu(self, event):
        """Affiche le menu contextuel."""
        try:
            # Sélectionner l'élément sous la souris
            item = self.tree.identify_row(event.y)
            if item:
                self.tree.selection_set(item)
                
                # Créer le menu contextuel
                context_menu = tk.Menu(self.window, tearoff=0)
                context_menu.add_command(label="Voir détails", command=lambda: self._on_item_double_click(None))
                context_menu.add_command(label="Copier hostname", command=self._copy_hostname)
                context_menu.add_command(label="Copier IPs", command=self._copy_ips)
                context_menu.add_separator()
                context_menu.add_command(label="Whois", command=self._whois_selected)
                context_menu.add_command(label="Port scan", command=self._port_scan_selected)
                
                # Afficher le menu
                context_menu.tk_popup(event.x_root, event.y_root)
            
        except Exception as e:
            self.logger.exception("Error showing context menu", module="ResultWindow")
    
    def _copy_to_clipboard(self, text):
        """Copie du texte vers le presse-papier."""
        try:
            self.window.clipboard_clear()
            self.window.clipboard_append(text)
            self.status_var.set("Copié: {}".format(text[:50] + "..." if len(text) > 50 else text))
            self.window.after(3000, lambda: self.status_var.set("Prêt"))
            
        except Exception as e:
            self.logger.exception("Error copying to clipboard", module="ResultWindow")
    
    def _copy_selection(self):
        """Copie la sélection vers le presse-papier."""
        try:
            selection = self.tree.selection()
            if not selection:
                messagebox.showwarning("Aucune sélection", "Veuillez sélectionner un élément à copier.")
                return
            
            text_lines = []
            for item_id in selection:
                item = self.tree.item(item_id)
                values = item['values']
                text_lines.append("\t".join(str(v) for v in values))
            
            text_to_copy = "\n".join(text_lines)
            self._copy_to_clipboard(text_to_copy)
            
        except Exception as e:
            self.logger.exception("Error copying selection", module="ResultWindow")
    
    def _copy_hostname(self):
        """Copie le hostname sélectionné."""
        try:
            selection = self.tree.selection()
            if selection:
                item = self.tree.item(selection[0])
                hostname = item['values'][0]
                self._copy_to_clipboard(hostname)
        except Exception as e:
            self.logger.exception("Error copying hostname", module="ResultWindow")
    
    def _copy_ips(self):
        """Copie les IPs sélectionnées."""
        try:
            selection = self.tree.selection()
            if selection:
                item = self.tree.item(selection[0])
                ips = item['values'][2]
                self._copy_to_clipboard(ips)
        except Exception as e:
            self.logger.exception("Error copying IPs", module="ResultWindow")
    
    def _whois_selected(self):
        """Lance une requête whois sur l'élément sélectionné."""
        try:
            selection = self.tree.selection()
            if selection:
                item = self.tree.item(selection[0])
                hostname = item['values'][0]
                self._show_whois(hostname)
        except Exception as e:
            self.logger.exception("Error in whois", module="ResultWindow")
    
    def _show_whois(self, hostname):
        """Affiche les informations whois."""
        try:
            # Créer fenêtre whois
            whois_window = tk.Toplevel(self.window)
            whois_window.title("Whois - {}".format(hostname))
            whois_window.geometry("700x500")
            whois_window.transient(self.window)
            
            # Interface
            main_frame = ttk.Frame(whois_window, padding=10)
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            ttk.Label(main_frame, text="Informations Whois pour: {}".format(hostname), 
                     font=('Segoe UI', 12, 'bold')).pack(pady=(0, 10))
            
            whois_text = scrolledtext.ScrolledText(main_frame, font=('Consolas', 9))
            whois_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
            
            # Boutons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill=tk.X)
            
            ttk.Button(button_frame, text="Actualiser", 
                      command=lambda: self._update_whois(hostname, whois_text)).pack(side=tk.LEFT)
            ttk.Button(button_frame, text="Fermer", 
                      command=whois_window.destroy).pack(side=tk.RIGHT)
            
            # Lancer la requête whois
            self._update_whois(hostname, whois_text)
            
        except Exception as e:
            self.logger.exception("Error showing whois", module="ResultWindow", hostname=hostname)
    
    def _update_whois(self, hostname, text_widget):
        """Met à jour les informations whois."""
        try:
            text_widget.delete('1.0', tk.END)
            text_widget.insert(tk.END, "Récupération des informations whois...\n")
            
            def whois_thread():
                try:
                    # Utiliser la commande whois système
                    if platform.system().lower() == 'windows':
                        # Sur Windows, essayer nslookup comme alternative
                        cmd = ['nslookup', hostname]
                    else:
                        # Sur Unix/Linux
                        cmd = ['whois', hostname]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        whois_info = result.stdout
                    else:
                        whois_info = "Erreur lors de la requête whois:\n{}".format(result.stderr)
                    
                    # Mettre à jour l'interface dans le thread principal
                    def update_ui():
                        text_widget.delete('1.0', tk.END)
                        text_widget.insert(tk.END, whois_info)
                    
                    text_widget.after(0, update_ui)
                    
                except subprocess.TimeoutExpired:
                    def update_ui():
                        text_widget.delete('1.0', tk.END)
                        text_widget.insert(tk.END, "Timeout lors de la requête whois")
                    text_widget.after(0, update_ui)
                    
                except Exception as e:
                    def update_ui():
                        text_widget.delete('1.0', tk.END)
                        text_widget.insert(tk.END, "Erreur: {}".format(str(e)))
                    text_widget.after(0, update_ui)
            
            # Lancer dans un thread séparé
            threading.Thread(target=whois_thread, daemon=True).start()
            
        except Exception as e:
            self.logger.exception("Error updating whois", module="ResultWindow", hostname=hostname)
    
    def _port_scan_selected(self):
        """Lance un scan de ports sur l'élément sélectionné."""
        try:
            selection = self.tree.selection()
            if selection:
                item = self.tree.item(selection[0])
                ips = item['values'][2].split(', ')
                if ips:
                    self._show_port_scan(ips[0])  # Scanner la première IP
        except Exception as e:
            self.logger.exception("Error in port scan", module="ResultWindow")
    
    def _show_port_scan(self, ip_address):
        """Affiche une fenêtre de scan de ports."""
        try:
            # Créer fenêtre de scan
            scan_window = tk.Toplevel(self.window)
            scan_window.title("Port Scan - {}".format(ip_address))
            scan_window.geometry("600x500")
            scan_window.transient(self.window)
            
            # Interface
            main_frame = ttk.Frame(scan_window, padding=10)
            main_frame.pack(fill=tk.BOTH, expand=True)
            
            ttk.Label(main_frame, text="Scan de ports pour: {}".format(ip_address), 
                     font=('Segoe UI', 12, 'bold')).pack(pady=(0, 10))
            
            # Options de scan
            options_frame = ttk.LabelFrame(main_frame, text="Options", padding=5)
            options_frame.pack(fill=tk.X, pady=(0, 10))
            
            ports_var = tk.StringVar(value="22,80,443,8080,8443")
            ttk.Label(options_frame, text="Ports:").pack(side=tk.LEFT, padx=(0, 5))
            ttk.Entry(options_frame, textvariable=ports_var, width=30).pack(side=tk.LEFT, padx=(0, 10))
            
            scan_button = ttk.Button(options_frame, text="Scanner", 
                                   command=lambda: self._run_port_scan(ip_address, ports_var.get(), scan_text))
            scan_button.pack(side=tk.LEFT)
            
            # Résultats
            scan_text = scrolledtext.ScrolledText(main_frame, font=('Consolas', 9))
            scan_text.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
            
            # Bouton fermer
            ttk.Button(main_frame, text="Fermer", command=scan_window.destroy).pack()
            
        except Exception as e:
            self.logger.exception("Error showing port scan", module="ResultWindow", ip=ip_address)
    
    def _run_port_scan(self, ip_address, ports_str, text_widget):
        """Exécute un scan de ports simple."""
        try:
            text_widget.delete('1.0', tk.END)
            text_widget.insert(tk.END, "Démarrage du scan de ports pour {}...\n".format(ip_address))
            
            def scan_thread():
                try:
                    ports = [int(p.strip()) for p in ports_str.split(',') if p.strip().isdigit()]
                    open_ports = []
                    
                    for port in ports:
                        try:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(2)
                            result = sock.connect_ex((ip_address, port))
                            sock.close()
                            
                            if result == 0:
                                open_ports.append(port)
                                status = "OUVERT"
                            else:
                                status = "FERMÉ"
                            
                            # Mettre à jour l'affichage
                            def update_ui(p=port, s=status):
                                text_widget.insert(tk.END, "Port {}: {}\n".format(p, s))
                                text_widget.see(tk.END)
                            
                            text_widget.after(0, update_ui)
                            
                        except Exception as e:
                            def update_ui(p=port):
                                text_widget.insert(tk.END, "Port {}: ERREUR\n".format(p))
                            text_widget.after(0, update_ui)
                    
                    # Résumé final
                    def final_update():
                        text_widget.insert(tk.END, "\n--- Résumé ---\n")
                        text_widget.insert(tk.END, "Ports ouverts: {}\n".format(
                            ", ".join(map(str, open_ports)) if open_ports else "Aucun"))
                        text_widget.insert(tk.END, "Scan terminé.\n")
                    
                    text_widget.after(0, final_update)
                    
                except Exception as e:
                    def error_update():
                        text_widget.insert(tk.END, "Erreur lors du scan: {}\n".format(str(e)))
                    text_widget.after(0, error_update)
            
            # Lancer le scan dans un thread séparé
            threading.Thread(target=scan_thread, daemon=True).start()
            
        except Exception as e:
            self.logger.exception("Error running port scan", module="ResultWindow", 
                                ip=ip_address, ports=ports_str)
    
    def _export_csv(self):
        """Exporte les résultats filtrés en CSV."""
        try:
            if not self.filtered_results:
                messagebox.showwarning("Aucun résultat", "Aucun résultat à exporter.")
                return
            
            filename = filedialog.asksaveasfilename(
                title="Exporter en CSV",
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    
                    # En-têtes
                    writer.writerow(['Hostname', 'Record Type', 'IP Addresses', 'Timestamp', 'Response Time', 'TTL'])
                    
                    # Données
                    for result in self.filtered_results:
                        writer.writerow([
                            result['hostname'],
                            result['record_type'],
                            ', '.join(result['addresses']),
                            result['timestamp'],
                            result.get('response_time', 'N/A'),
                            result.get('ttl', 'N/A')
                        ])
                
                messagebox.showinfo("Export réussi", "Résultats exportés vers:\n{}".format(filename))
                self.logger.info("Results exported to CSV", module="ResultWindow", filename=filename)
        
        except Exception as e:
            self.logger.exception("Error exporting to CSV", module="ResultWindow")
            messagebox.showerror("Erreur d'export", "Erreur lors de l'export CSV:\n{}".format(str(e)))
    
    def _export_json(self):
        """Exporte les résultats filtrés en JSON."""
        try:
            if not self.filtered_results:
                messagebox.showwarning("Aucun résultat", "Aucun résultat à exporter.")
                return
            
            filename = filedialog.asksaveasfilename(
                title="Exporter en JSON",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                export_data = {
                    'metadata': {
                        'export_time': datetime.now().isoformat(),
                        'total_results': len(self.filtered_results),
                        'export_source': 'SubBrute Advanced GUI'
                    },
                    'results': self.filtered_results
                }
                
                with open(filename, 'w', encoding='utf-8') as jsonfile:
                    json.dump(export_data, jsonfile, indent=2, ensure_ascii=False)
                
                messagebox.showinfo("Export réussi", "Résultats exportés vers:\n{}".format(filename))
                self.logger.info("Results exported to JSON", module="ResultWindow", filename=filename)
        
        except Exception as e:
            self.logger.exception("Error exporting to JSON", module="ResultWindow")
            messagebox.showerror("Erreur d'export", "Erreur lors de l'export JSON:\n{}".format(str(e)))
    
    def _refresh(self):
        """Actualise l'affichage."""
        try:
            self._apply_filter()
            self._update_stats()
            self.status_var.set("Actualisé à {}".format(datetime.now().strftime("%H:%M:%S")))
        except Exception as e:
            self.logger.exception("Error refreshing ResultWindow", module="ResultWindow")
    
    def _update_stats(self):
        """Met à jour les statistiques affichées."""
        try:
            total = len(self.results)
            filtered = len(self.filtered_results)
            
            self.results_count_var.set("Résultats: {} / {}".format(filtered, total))
            
            # Mettre à jour la barre de progression (exemple)
            if total > 0:
                progress = (filtered / total) * 100
                self.progress_var.set(progress)
            
        except Exception as e:
            self.logger.exception("Error updating stats", module="ResultWindow")
    
    def _on_closing(self):
        """Gère la fermeture de la fenêtre."""
        try:
            self.logger.info("ResultWindow closing", module="ResultWindow", total_results=len(self.results))
            self.window.destroy()
        except Exception as e:
            self.logger.exception("Error closing ResultWindow", module="ResultWindow")


def main():
    """Point d'entrée principal pour tester la fenêtre de résultats."""
    try:
        # Initialiser le logger
        logger = AdvancedLogger(debug=True)
        
        # Créer une fenêtre de test
        root = tk.Tk()
        root.withdraw()  # Cacher la fenêtre principale
        
        # Créer et afficher la fenêtre de résultats
        result_window = ResultWindow(root, logger)
        
        # Ajouter quelques résultats de test
        test_results = [
            {
                'hostname': 'www.example.com',
                'record_type': 'A',
                'addresses': ['192.168.1.1', '192.168.1.2'],
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'response_time': '50ms',
                'ttl': '300'
            },
            {
                'hostname': 'mail.example.com',
                'record_type': 'A',
                'addresses': ['192.168.1.10'],
                'timestamp': datetime.now().strftime("%H:%M:%S"),
                'response_time': '75ms',
                'ttl': '600'
            }
        ]
        
        for result in test_results:
            result_window.add_result(result)
        
        # Démarrer la boucle principale
        root.mainloop()
        
    except Exception as e:
        print("Erreur lors du test: {}".format(str(e)))
        print("Traceback: {}".format(traceback.format_exc()))


def main_advanced():\n    \"\"\"Point d'entrée principal pour l'interface avancée complète.\"\"\"\n    try:\n        print(\"SubBrute Advanced GUI v2.1 - Démarrage...\")\n        print(\"Interface complète avec recherche de propriétaires et fonctionnalités avancées\")\n        \n        # Créer l'application avec toutes les fonctionnalités\n        root = tk.Tk()\n        \n        # Créer l'instance complète avec logging avancé\n        logger = AdvancedLogger(\"SubBrute_Complete\", debug=True)\n        \n        # Message de bienvenue dans les logs\n        logger.success(\"SubBrute Advanced GUI v2.1 starting\", module=\"Main\")\n        logger.info(\"All advanced features enabled: WHOIS, Email search, Geolocation\", module=\"Main\")\n        \n        # Interface complète avec toutes les fonctionnalités\n        from subbrute_gui import SubBruteGUI\n        app = SubBruteGUI(root)\n        \n        # Ajouter les fonctionnalités avancées\n        app.logger = logger\n        app.owner_finder = OwnerEmailFinder(logger)\n        app.security_validator = SecurityValidator(logger)\n        \n        logger.success(\"SubBrute Advanced GUI initialized successfully\", module=\"Main\")\n        \n        # Démarrer l'application\n        root.mainloop()\n        \n        logger.success(\"Application terminated successfully\", module=\"Main\")\n        return 0\n        \n    except KeyboardInterrupt:\n        print(\"\\nApplication interrompue par l'utilisateur\")\n        return 0\n    except Exception as e:\n        print(\"Erreur fatale: {}\".format(str(e)))\n        print(\"Traceback: {}\".format(traceback.format_exc()))\n        return 1\n\n\nif __name__ == \"__main__\":\n    # Permettre le choix entre interface de test et avancée\n    if len(sys.argv) > 1 and sys.argv[1] == \"--advanced\":\n        sys.exit(main_advanced())\n    else:\n        main()