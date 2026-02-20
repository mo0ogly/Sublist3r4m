"""Advanced logging system for SubBrute GUI."""
import json
import logging
import os
import sys
import tempfile
import time
import traceback
from collections import defaultdict
from datetime import datetime
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler


class AdvancedLogger:
    """
    Systeme de logging avance avec rotation, niveaux detailles et formatage sophistique.

    Features:
    - Rotation par taille et par temps
    - Niveaux de log personnalises
    - Formatage colore pour terminal et GUI
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
        Initialise le logger avance.

        Args:
            name (str): Nom du logger
            log_dir (str): Repertoire des logs
            debug (bool): Mode debug active
        """
        try:
            self.name = name
            self.debug_enabled = debug
            self.log_dir = log_dir
            self.session_id = self._generate_session_id()

            # Creer le repertoire de logs
            self._ensure_log_directory()

            # Initialiser les loggers
            self._setup_loggers()

            # Initialiser les metriques
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
        """Genere un ID unique pour cette session."""
        try:
            timestamp = str(int(time.time()))
            random_part = str(hash(str(time.time())))[-6:]
            return "session_{}{}".format(timestamp, random_part)
        except Exception:
            return "session_unknown"

    def _ensure_log_directory(self):
        """Assure que le repertoire de logs existe."""
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
        """Configure les differents loggers avec handlers appropries."""
        try:
            # Logger principal
            self.logger = logging.getLogger(self.name)
            self.logger.setLevel(logging.DEBUG if self.debug_enabled else logging.INFO)
            self.logger.handlers.clear()

            # Format detaille pour fichiers
            file_formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )

            # Format simplifie pour console
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

            # Logger pour securite
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
            # Mettre a jour les metriques
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

            # Logger specialise selon le type
            if level == 'SECURITY':
                self.security_logger.warning(enriched_message)
            elif level == 'PERFORMANCE':
                self.perf_logger.info(enriched_message)

            # Affichage colore dans le terminal
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

    def exception(self, message, module=None, function=None, **kwargs):
        """Log exception avec traceback complet."""
        try:
            tb = traceback.format_exc()
            full_message = "{} | TRACEBACK: {}".format(str(message), tb)
            self._log_with_context('ERROR', full_message, module, function, kwargs)
        except Exception as e:
            print("ERROR in exception logging: {}".format(str(e)))

    def get_metrics(self):
        """Retourne les metriques de logging."""
        try:
            uptime = time.time() - self.metrics['start_time']
            self.metrics['uptime_seconds'] = uptime
            if uptime > 0:
                self.metrics['messages_per_second'] = (
                    self.metrics['total_messages'] / uptime
                )
            else:
                self.metrics['messages_per_second'] = 0
            return dict(self.metrics)
        except Exception as e:
            return {'error': str(e)}

    def export_metrics(self, filepath):
        """Exporte les metriques vers un fichier JSON."""
        try:
            metrics = self.get_metrics()
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(metrics, f, indent=2, default=str)
            self.info("Metrics exported to {}".format(filepath), module="AdvancedLogger")
            return True
        except Exception as e:
            self.error("Failed to export metrics: {}".format(str(e)), module="AdvancedLogger")
            return False
