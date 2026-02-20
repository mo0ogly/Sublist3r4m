"""Enhanced logging system for JARVIS Intelligence."""
from __future__ import annotations

import logging
import os
import sys
import tempfile
import time
import traceback
from collections import defaultdict
from datetime import datetime
from logging.handlers import RotatingFileHandler

from jarvis.config import is_windows


# Enhanced color system with fallback
class ColorSystem:
    """
    Systeme de couleurs avance avec support multi-plateforme et fallback.
    """

    def __init__(self, enable_colors: bool = True) -> None:
        """Initialise le systeme de couleurs."""
        self.enabled = enable_colors and self._supports_color()

        if self.enabled:
            self._setup_colors()
        else:
            self._disable_colors()

    def _supports_color(self):
        """Verifie si les couleurs sont supportees."""
        try:
            # Windows color support
            if is_windows:
                try:
                    import colorama
                    import win_unicode_console
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
        """Desactive les couleurs."""
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
        """Desactive les couleurs."""
        self.enabled = False
        self._disable_colors()


# Instance globale du systeme de couleurs
colors = ColorSystem()


class EnhancedLogger:
    """
    Systeme de logging avance pour JARVIS Intelligence.

    Features:
    - Niveaux de log detailles
    - Rotation automatique des fichiers
    - Formatage personnalise avec couleurs
    - Sauvegarde horodatee
    - Metriques integrees
    """

    def __init__(self, name: str = "JARVIS_Intelligence", log_dir: str = "logs", debug: bool = False) -> None:
        """Initialise le logger avance."""
        try:
            self.name = name
            self.debug_enabled = debug
            self.log_dir = log_dir
            self.session_id = self._generate_session_id()

            # Creer le repertoire de logs
            self._ensure_log_directory()

            # Initialiser les loggers
            self._setup_loggers()

            # Metriques
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
        """Genere un ID unique pour cette session."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            random_part = str(hash(str(time.time())))[-6:]
            return "session_{}_{}_{}".format(timestamp, os.getpid(), random_part)
        except Exception:
            return "session_unknown"

    def _ensure_log_directory(self):
        """Assure que le repertoire de logs existe."""
        try:
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)
        except Exception as e:
            print("WARNING: Cannot create log directory {}: {}".format(self.log_dir, str(e)))
            self.log_dir = tempfile.gettempdir()

    def _setup_loggers(self):
        """Configure les loggers avec handlers appropries."""
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

            # Handler pour session horodatee
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
            # Mettre a jour les metriques
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

            # Affichage colore dans le terminal si supporte
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
        """Retourne les metriques de logging."""
        try:
            uptime = time.time() - self.metrics['start_time']
            self.metrics['uptime_seconds'] = uptime
            return dict(self.metrics)
        except Exception as e:
            return {'error': str(e)}


class ProgressBar:
    """
    Barre de progression moderne et configurable.
    """

    def __init__(self, total: int = 100, width: int = 50, prefix: str = "Progress", suffix: str = "Complete",
                 fill: str = '\u2588', empty: str = '-', show_percent: bool = True, show_count: bool = True) -> None:
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
        """Met a jour la barre de progression."""
        try:
            if current is not None:
                self.current = current
            else:
                self.current += increment

            # Assurer que current ne depasse pas total
            self.current = min(self.current, self.total)

            # Calculer le pourcentage
            if self.total > 0:
                percent = (self.current / self.total) * 100
            else:
                percent = 0

            # Calculer le nombre de caracteres remplis
            filled_length = int(self.width * self.current // self.total) if self.total > 0 else 0

            # Creer la barre
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

            # Effacer la ligne precedente et afficher la nouvelle
            sys.stdout.write('\\r' + ' ' * 80 + '\\r')  # Clear line
            sys.stdout.write(message)
            sys.stdout.flush()

            # Nouvelle ligne si termine
            if self.current >= self.total:
                sys.stdout.write('\\n')
                sys.stdout.flush()

        except Exception:
            pass  # Ne pas interrompre le processus pour un probleme d'affichage

    def finish(self):
        """Termine la barre de progression."""
        self.update(self.total)
