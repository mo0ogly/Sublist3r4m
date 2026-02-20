#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Owner Research Engine v2.1 - Moteur de Recherche de Propriétaires Avancé

Fonctionnalités sophistiquées:
- Recherche floue multi-critères paramétrable
- Système de scoring avancé avec pondération
- Multi-threading pour performances optimales
- Export enrichi avec statistiques et métadonnées
- Validation et normalisation des données
- Cache intelligent avec persistance
- Métriques détaillées de performance
- Support multiple sources de données

Author: Enhanced Security Team
License: MIT
"""

from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import logging
import os
import queue
import re
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.parse as urlparse
from collections import defaultdict
from datetime import datetime
from difflib import SequenceMatcher

REQUESTS_AVAILABLE = importlib.util.find_spec("requests") is not None
DNS_AVAILABLE = importlib.util.find_spec("dns") is not None

class AdvancedOwnerLogger:
    """
    Système de logging avancé spécialisé pour la recherche de propriétaires.
    """

    def __init__(self, name: str = "OwnerResearch", log_dir: str = "logs", debug: bool = False) -> None:
        """Initialise le logger avancé."""
        try:
            self.name = name
            self.debug_enabled = debug
            self.log_dir = log_dir
            self.session_id = self._generate_session_id()

            # Couleurs pour terminal
            self.colors = {
                'DEBUG': '\033[36m',    # Cyan
                'INFO': '\033[32m',     # Vert
                'WARNING': '\033[33m',  # Jaune
                'ERROR': '\033[31m',    # Rouge
                'CRITICAL': '\033[35m', # Magenta
                'SUCCESS': '\033[92m',  # Vert clair
                'RESET': '\033[0m'      # Reset
            }

            # Créer le répertoire de logs
            self._ensure_log_directory()

            # Configurer le logger
            self._setup_logger()

            # Métriques
            self.metrics = {
                'start_time': time.time(),
                'total_messages': 0,
                'messages_by_level': defaultdict(int),
                'errors_count': 0
            }

            self.info("AdvancedOwnerLogger initialized", module="AdvancedOwnerLogger")

        except Exception as e:
            print("CRITICAL: Failed to initialize logger: {}".format(str(e)))
            raise

    def _generate_session_id(self):
        """Génère un ID unique pour la session."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            random_part = str(hash(str(time.time())))[-6:]
            return "owner_session_{}_{}".format(timestamp, random_part)
        except Exception:
            return "owner_session_unknown"

    def _ensure_log_directory(self):
        """Assure que le répertoire de logs existe."""
        try:
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)
        except Exception as e:
            print("WARNING: Cannot create log directory {}: {}".format(self.log_dir, str(e)))
            self.log_dir = tempfile.gettempdir()

    def _setup_logger(self):
        """Configure le logger avec formatage coloré."""
        try:
            self.logger = logging.getLogger(self.name)
            self.logger.setLevel(logging.DEBUG if self.debug_enabled else logging.INFO)
            self.logger.handlers.clear()

            # Handler pour fichier
            log_file = os.path.join(self.log_dir, "owner_research.log")
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)

            # Handler pour console avec couleurs
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG if self.debug_enabled else logging.INFO)
            self.logger.addHandler(console_handler)

        except Exception as e:
            print("CRITICAL: Failed to setup logger: {}".format(str(e)))
            raise

    def _log_with_context(self, level, message, module=None, function=None, **kwargs):
        """Log avec contexte et couleurs."""
        try:
            # Mettre à jour les métriques
            self.metrics['total_messages'] += 1
            self.metrics['messages_by_level'][level] += 1

            if level in ['ERROR', 'CRITICAL']:
                self.metrics['errors_count'] += 1

            # Enrichir le message
            enriched_message = str(message)

            if module:
                enriched_message = "[{}] {}".format(module, enriched_message)

            if function:
                enriched_message = "{}() - {}".format(function, enriched_message)

            if kwargs:
                extra_str = " | ".join("{}={}".format(k, v) for k, v in kwargs.items())
                enriched_message = "{} | {}".format(enriched_message, extra_str)

            # Logger standard
            logger_method = getattr(self.logger, level.lower(), self.logger.info)
            logger_method(enriched_message)

            # Affichage coloré pour terminal
            if hasattr(sys.stderr, 'isatty') and sys.stderr.isatty():
                color = self.colors.get(level, self.colors['RESET'])
                reset = self.colors['RESET']
                timestamp = datetime.now().strftime('%H:%M:%S')
                colored_message = "{}[{}] [{}] {}{}{}".format(
                    color, timestamp, level, enriched_message, reset, ''
                )
                print(colored_message, file=sys.stderr)

        except Exception as e:
            print("ERROR in logging: {}".format(str(e)))

    def debug(self, message, module=None, function=None, **kwargs):
        """Log debug."""
        if self.debug_enabled:
            self._log_with_context('DEBUG', message, module, function, **kwargs)

    def info(self, message, module=None, function=None, **kwargs):
        """Log info."""
        self._log_with_context('INFO', message, module, function, **kwargs)

    def warning(self, message, module=None, function=None, **kwargs):
        """Log warning."""
        self._log_with_context('WARNING', message, module, function, **kwargs)

    def error(self, message, module=None, function=None, **kwargs):
        """Log error."""
        self._log_with_context('ERROR', message, module, function, **kwargs)

    def critical(self, message, module=None, function=None, **kwargs):
        """Log critical."""
        self._log_with_context('CRITICAL', message, module, function, **kwargs)

    def success(self, message, module=None, function=None, **kwargs):
        """Log success."""
        self._log_with_context('SUCCESS', message, module, function, **kwargs)

class FuzzyMatcher:
    """
    Moteur de recherche floue avancé avec scoring paramétrable.
    """

    def __init__(self, logger: AdvancedOwnerLogger | None = None) -> None:
        """Initialise le matcher flou."""
        self.logger = logger

        # Configuration par défaut des algorithmes de matching
        self.algorithms = {
            'exact': {'weight': 1.0, 'enabled': True},
            'substring': {'weight': 0.8, 'enabled': True},
            'sequence': {'weight': 0.7, 'enabled': True},
            'soundex': {'weight': 0.6, 'enabled': True},
            'metaphone': {'weight': 0.65, 'enabled': True},
            'levenshtein': {'weight': 0.75, 'enabled': True},
            'jaro_winkler': {'weight': 0.72, 'enabled': True},
            'ngram': {'weight': 0.68, 'enabled': True}
        }

        # Seuils de scoring
        self.scoring_thresholds = {
            'excellent': 0.95,
            'very_good': 0.85,
            'good': 0.75,
            'fair': 0.60,
            'poor': 0.40
        }

        # Métriques
        self.metrics = {
            'comparisons_made': 0,
            'matches_found': 0,
            'algorithm_usage': defaultdict(int)
        }

        if self.logger:
            self.logger.debug("FuzzyMatcher initialized", module="FuzzyMatcher")

    def configure_algorithms(self, config):
        """
        Configure les algorithmes et leurs poids.

        Args:
            config (dict): Configuration des algorithmes
        """
        try:
            for algo_name, settings in config.items():
                if algo_name in self.algorithms:
                    self.algorithms[algo_name].update(settings)

            if self.logger:
                self.logger.info("Algorithms configured", module="FuzzyMatcher",
                               enabled_algos=len([a for a in self.algorithms.values() if a['enabled']]))

        except Exception as e:
            if self.logger:
                self.logger.error("Algorithm configuration failed", module="FuzzyMatcher", error=str(e))

    def exact_match(self, str1, str2):
        """Matching exact (insensible à la casse)."""
        try:
            return 1.0 if str1.lower().strip() == str2.lower().strip() else 0.0
        except Exception:
            return 0.0

    def substring_match(self, str1, str2):
        """Matching par sous-chaîne."""
        try:
            s1, s2 = str1.lower().strip(), str2.lower().strip()
            if not s1 or not s2:
                return 0.0

            if s1 in s2 or s2 in s1:
                # Score basé sur la proportion de la sous-chaîne
                shorter, longer = (s1, s2) if len(s1) <= len(s2) else (s2, s1)
                return len(shorter) / len(longer)

            return 0.0
        except Exception:
            return 0.0

    def sequence_match(self, str1, str2):
        """Matching par similarité de séquence."""
        try:
            return SequenceMatcher(None, str1.lower().strip(), str2.lower().strip()).ratio()
        except Exception:
            return 0.0

    def levenshtein_distance(self, str1, str2):
        """Calcule la distance de Levenshtein."""
        try:
            s1, s2 = str1.lower().strip(), str2.lower().strip()

            if len(s1) < len(s2):
                return self.levenshtein_distance(s2, s1)

            if len(s2) == 0:
                return len(s1)

            previous_row = list(range(len(s2) + 1))
            for i, c1 in enumerate(s1):
                current_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = previous_row[j + 1] + 1
                    deletions = current_row[j] + 1
                    substitutions = previous_row[j] + (c1 != c2)
                    current_row.append(min(insertions, deletions, substitutions))
                previous_row = current_row

            # Convertir en score de similarité (0-1)
            max_len = max(len(s1), len(s2))
            return 1.0 - (previous_row[-1] / max_len) if max_len > 0 else 0.0

        except Exception:
            return 0.0

    def soundex(self, text):
        """Implémentation simple de Soundex."""
        try:
            text = text.upper().strip()
            if not text:
                return "0000"

            # Garder la première lettre
            soundex_code = text[0]

            # Mapping des consonnes
            mapping = {
                'BFPV': '1', 'CGJKQSXZ': '2', 'DT': '3',
                'L': '4', 'MN': '5', 'R': '6'
            }

            # Convertir les consonnes
            for char in text[1:]:
                for group, code in mapping.items():
                    if char in group and (not soundex_code or soundex_code[-1] != code):
                        soundex_code += code
                        break

            # Tronquer ou padding à 4 caractères
            soundex_code = (soundex_code + '000')[:4]
            return soundex_code

        except Exception:
            return "0000"

    def soundex_match(self, str1, str2):
        """Matching par Soundex."""
        try:
            soundex1 = self.soundex(str1)
            soundex2 = self.soundex(str2)
            return 1.0 if soundex1 == soundex2 else 0.0
        except Exception:
            return 0.0

    def jaro_similarity(self, str1, str2):
        """Calcule la similarité de Jaro."""
        try:
            s1, s2 = str1.lower().strip(), str2.lower().strip()

            if s1 == s2:
                return 1.0

            len1, len2 = len(s1), len(s2)
            if len1 == 0 or len2 == 0:
                return 0.0

            # Distance de matching
            match_distance = max(len1, len2) // 2 - 1
            match_distance = max(0, match_distance)

            # Arrays pour marquer les matches
            s1_matches = [False] * len1
            s2_matches = [False] * len2

            matches = 0
            transpositions = 0

            # Identifier les matches
            for i in range(len1):
                start = max(0, i - match_distance)
                end = min(i + match_distance + 1, len2)

                for j in range(start, end):
                    if s2_matches[j] or s1[i] != s2[j]:
                        continue
                    s1_matches[i] = s2_matches[j] = True
                    matches += 1
                    break

            if matches == 0:
                return 0.0

            # Compter les transpositions
            k = 0
            for i in range(len1):
                if not s1_matches[i]:
                    continue
                while not s2_matches[k]:
                    k += 1
                if s1[i] != s2[k]:
                    transpositions += 1
                k += 1

            return (matches / len1 + matches / len2 + (matches - transpositions / 2) / matches) / 3.0

        except Exception:
            return 0.0

    def jaro_winkler_similarity(self, str1, str2):
        """Calcule la similarité de Jaro-Winkler."""
        try:
            jaro_sim = self.jaro_similarity(str1, str2)

            if jaro_sim < 0.7:
                return jaro_sim

            # Calculer le préfixe commun (max 4 caractères)
            prefix = 0
            for i in range(min(len(str1), len(str2), 4)):
                if str1[i] == str2[i]:
                    prefix += 1
                else:
                    break

            return jaro_sim + (0.1 * prefix * (1 - jaro_sim))

        except Exception:
            return 0.0

    def ngram_similarity(self, str1, str2, n=2):
        """Calcule la similarité par n-grammes."""
        try:
            s1, s2 = str1.lower().strip(), str2.lower().strip()

            if len(s1) < n or len(s2) < n:
                return self.sequence_match(s1, s2)

            # Générer les n-grammes
            ngrams1 = set(s1[i:i+n] for i in range(len(s1) - n + 1))
            ngrams2 = set(s2[i:i+n] for i in range(len(s2) - n + 1))

            if not ngrams1 or not ngrams2:
                return 0.0

            # Calcul de la similarité Jaccard
            intersection = len(ngrams1.intersection(ngrams2))
            union = len(ngrams1.union(ngrams2))

            return intersection / union if union > 0 else 0.0

        except Exception:
            return 0.0

    def compute_similarity(self, str1, str2, algorithms=None):
        """
        Calcule la similarité globale entre deux chaînes.

        Args:
            str1 (str): Première chaîne
            str2 (str): Deuxième chaîne
            algorithms (list): Liste des algorithmes à utiliser

        Returns:
            dict: Scores détaillés par algorithme et score global
        """
        try:
            self.metrics['comparisons_made'] += 1

            if not str1 or not str2:
                return {'global_score': 0.0, 'algorithms': {}, 'quality': 'invalid'}

            # Utiliser tous les algorithmes activés si non spécifié
            if algorithms is None:
                algorithms = [name for name, config in self.algorithms.items() if config['enabled']]

            scores = {}
            weighted_sum = 0.0
            total_weight = 0.0

            # Appliquer chaque algorithme
            for algo_name in algorithms:
                if algo_name not in self.algorithms or not self.algorithms[algo_name]['enabled']:
                    continue

                try:
                    # Sélectionner la méthode
                    if algo_name == 'exact':
                        score = self.exact_match(str1, str2)
                    elif algo_name == 'substring':
                        score = self.substring_match(str1, str2)
                    elif algo_name == 'sequence':
                        score = self.sequence_match(str1, str2)
                    elif algo_name == 'soundex':
                        score = self.soundex_match(str1, str2)
                    elif algo_name == 'levenshtein':
                        score = self.levenshtein_distance(str1, str2)
                    elif algo_name == 'jaro_winkler':
                        score = self.jaro_winkler_similarity(str1, str2)
                    elif algo_name == 'ngram':
                        score = self.ngram_similarity(str1, str2)
                    else:
                        continue

                    # Normaliser le score (0-1)
                    score = max(0.0, min(1.0, score))
                    scores[algo_name] = score

                    # Pondération
                    weight = self.algorithms[algo_name]['weight']
                    weighted_sum += score * weight
                    total_weight += weight

                    self.metrics['algorithm_usage'][algo_name] += 1

                except Exception as e:
                    if self.logger:
                        self.logger.debug("Algorithm failed", module="FuzzyMatcher",
                                        algorithm=algo_name, error=str(e))
                    continue

            # Calculer le score global
            global_score = weighted_sum / total_weight if total_weight > 0 else 0.0

            # Déterminer la qualité
            quality = self._determine_quality(global_score)

            # Incrémenter les matches si score significatif
            if global_score > 0.5:
                self.metrics['matches_found'] += 1

            result = {
                'global_score': global_score,
                'algorithms': scores,
                'quality': quality,
                'threshold_category': self._get_threshold_category(global_score)
            }

            if self.logger:
                self.logger.debug("Similarity computed", module="FuzzyMatcher",
                                str1=str1[:20], str2=str2[:20], global_score=global_score, quality=quality)

            return result

        except Exception as e:
            if self.logger:
                self.logger.error("Similarity computation failed", module="FuzzyMatcher", error=str(e))

            return {'global_score': 0.0, 'algorithms': {}, 'quality': 'error'}

    def _determine_quality(self, score):
        """Détermine la qualité textuelle du score."""
        try:
            if score >= 0.95:
                return 'excellent'
            elif score >= 0.85:
                return 'very_good'
            elif score >= 0.75:
                return 'good'
            elif score >= 0.60:
                return 'fair'
            elif score >= 0.40:
                return 'poor'
            else:
                return 'very_poor'
        except Exception:
            return 'unknown'

    def _get_threshold_category(self, score):
        """Retourne la catégorie de seuil du score."""
        try:
            for category, threshold in sorted(self.scoring_thresholds.items(),
                                            key=lambda x: x[1], reverse=True):
                if score >= threshold:
                    return category
            return 'below_threshold'
        except Exception:
            return 'unknown'

    def get_metrics(self):
        """Retourne les métriques du matcher."""
        try:
            return dict(self.metrics)
        except Exception:
            return {}

class OwnerDatabase:
    """
    Base de données SQLite pour le cache des propriétaires.
    """

    def __init__(self, db_path: str = "owner_cache.db", logger: AdvancedOwnerLogger | None = None) -> None:
        """Initialise la base de données."""
        try:
            self.db_path = db_path
            self.logger = logger
            self.connection = None

            self._create_connection()
            self._create_tables()

            if self.logger:
                self.logger.info("Owner database initialized", module="OwnerDatabase", db_path=db_path)

        except Exception as e:
            if self.logger:
                self.logger.error("Database initialization failed", module="OwnerDatabase", error=str(e))
            raise

    def _create_connection(self):
        """Crée la connexion à la base de données."""
        try:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row  # Pour accès par nom de colonne

            # Configuration pour performance
            self.connection.execute("PRAGMA journal_mode=WAL")
            self.connection.execute("PRAGMA synchronous=NORMAL")
            self.connection.execute("PRAGMA cache_size=1000")
            self.connection.execute("PRAGMA temp_store=MEMORY")

        except Exception as e:
            if self.logger:
                self.logger.error("Database connection failed", module="OwnerDatabase", error=str(e))
            raise

    def _create_tables(self):
        """Crée les tables nécessaires."""
        try:
            # Table pour cache des propriétaires
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS owner_cache (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL,
                    owner_name TEXT,
                    registrar TEXT,
                    creation_date TEXT,
                    expiry_date TEXT,
                    emails TEXT,  -- JSON array
                    phone TEXT,
                    address TEXT,
                    raw_whois TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source TEXT,
                    confidence_score REAL DEFAULT 0.0,
                    UNIQUE(domain)
                )
            """)

            # Table pour recherches floues
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS fuzzy_searches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    search_query TEXT NOT NULL,
                    target_owner TEXT NOT NULL,
                    match_score REAL NOT NULL,
                    match_quality TEXT,
                    algorithms_used TEXT,  -- JSON
                    search_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    result_data TEXT  -- JSON
                )
            """)

            # Table pour métriques
            self.connection.execute("""
                CREATE TABLE IF NOT EXISTS search_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    search_type TEXT,
                    total_searches INTEGER,
                    successful_matches INTEGER,
                    average_score REAL,
                    execution_time REAL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Créer les index pour performance
            self.connection.execute("CREATE INDEX IF NOT EXISTS idx_domain ON owner_cache(domain)")
            self.connection.execute("CREATE INDEX IF NOT EXISTS idx_owner_name ON owner_cache(owner_name)")
            self.connection.execute("CREATE INDEX IF NOT EXISTS idx_search_query ON fuzzy_searches(search_query)")
            self.connection.execute("CREATE INDEX IF NOT EXISTS idx_target_owner ON fuzzy_searches(target_owner)")

            self.connection.commit()

        except Exception as e:
            if self.logger:
                self.logger.error("Table creation failed", module="OwnerDatabase", error=str(e))
            raise

    def cache_owner_info(self, domain, owner_data):
        """
        Met en cache les informations d'un propriétaire.

        Args:
            domain (str): Domaine
            owner_data (dict): Données du propriétaire
        """
        try:
            cursor = self.connection.cursor()

            # Préparer les données
            emails_json = json.dumps(owner_data.get('emails', []))

            cursor.execute("""
                INSERT OR REPLACE INTO owner_cache
                (domain, owner_name, registrar, creation_date, expiry_date,
                 emails, phone, address, raw_whois, source, confidence_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                domain,
                owner_data.get('owner_name'),
                owner_data.get('registrar'),
                owner_data.get('creation_date'),
                owner_data.get('expiry_date'),
                emails_json,
                owner_data.get('phone'),
                owner_data.get('address'),
                owner_data.get('raw_whois'),
                owner_data.get('source', 'whois'),
                owner_data.get('confidence_score', 0.5)
            ))

            self.connection.commit()

            if self.logger:
                self.logger.debug("Owner info cached", module="OwnerDatabase", domain=domain)

            return True

        except Exception as e:
            if self.logger:
                self.logger.error("Cache storage failed", module="OwnerDatabase",
                                domain=domain, error=str(e))
            return False

    def get_cached_owner(self, domain, max_age_hours=24):
        """
        Récupère les informations d'un propriétaire depuis le cache.

        Args:
            domain (str): Domaine
            max_age_hours (int): Age maximum en heures

        Returns:
            dict: Informations du propriétaire ou None
        """
        try:
            cursor = self.connection.cursor()

            cursor.execute("""
                SELECT * FROM owner_cache
                WHERE domain = ?
                AND datetime(last_updated) > datetime('now', '-{} hours')
            """.format(max_age_hours), (domain,))

            row = cursor.fetchone()

            if row:
                # Convertir en dictionnaire
                owner_data = dict(row)

                # Parser le JSON des emails
                try:
                    owner_data['emails'] = json.loads(owner_data['emails'] or '[]')
                except (json.JSONDecodeError, TypeError):
                    owner_data['emails'] = []

                if self.logger:
                    self.logger.debug("Owner info retrieved from cache", module="OwnerDatabase", domain=domain)

                return owner_data

            return None

        except Exception as e:
            if self.logger:
                self.logger.error("Cache retrieval failed", module="OwnerDatabase",
                                domain=domain, error=str(e))
            return None

    def store_fuzzy_search(self, search_query, target_owner, match_result):
        """
        Stocke le résultat d'une recherche floue.

        Args:
            search_query (str): Requête de recherche
            target_owner (str): Propriétaire cible
            match_result (dict): Résultat du matching
        """
        try:
            cursor = self.connection.cursor()

            cursor.execute("""
                INSERT INTO fuzzy_searches
                (search_query, target_owner, match_score, match_quality, algorithms_used, result_data)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                search_query,
                target_owner,
                match_result.get('global_score', 0.0),
                match_result.get('quality', 'unknown'),
                json.dumps(match_result.get('algorithms', {})),
                json.dumps(match_result)
            ))

            self.connection.commit()

            if self.logger:
                self.logger.debug("Fuzzy search stored", module="OwnerDatabase",
                                query=search_query[:20], score=match_result.get('global_score', 0.0))

            return True

        except Exception as e:
            if self.logger:
                self.logger.error("Fuzzy search storage failed", module="OwnerDatabase", error=str(e))
            return False

    def get_search_history(self, limit=100):
        """
        Récupère l'historique des recherches.

        Args:
            limit (int): Nombre maximum de résultats

        Returns:
            list: Liste des recherches
        """
        try:
            cursor = self.connection.cursor()

            cursor.execute("""
                SELECT * FROM fuzzy_searches
                ORDER BY search_timestamp DESC
                LIMIT ?
            """, (limit,))

            rows = cursor.fetchall()

            results = []
            for row in rows:
                search_data = dict(row)

                # Parser les JSON
                try:
                    search_data['algorithms_used'] = json.loads(search_data['algorithms_used'] or '{}')
                    search_data['result_data'] = json.loads(search_data['result_data'] or '{}')
                except (json.JSONDecodeError, TypeError):
                    search_data['algorithms_used'] = {}
                    search_data['result_data'] = {}

                results.append(search_data)

            return results

        except Exception as e:
            if self.logger:
                self.logger.error("Search history retrieval failed", module="OwnerDatabase", error=str(e))
            return []

    def store_metrics(self, session_id, metrics_data):
        """
        Stocke les métriques de session.

        Args:
            session_id (str): ID de session
            metrics_data (dict): Données de métriques
        """
        try:
            cursor = self.connection.cursor()

            cursor.execute("""
                INSERT INTO search_metrics
                (session_id, search_type, total_searches, successful_matches,
                 average_score, execution_time)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                metrics_data.get('search_type', 'fuzzy'),
                metrics_data.get('total_searches', 0),
                metrics_data.get('successful_matches', 0),
                metrics_data.get('average_score', 0.0),
                metrics_data.get('execution_time', 0.0)
            ))

            self.connection.commit()

            if self.logger:
                self.logger.debug("Metrics stored", module="OwnerDatabase", session_id=session_id)

            return True

        except Exception as e:
            if self.logger:
                self.logger.error("Metrics storage failed", module="OwnerDatabase", error=str(e))
            return False

    def cleanup_old_data(self, days_old=30):
        """
        Nettoie les anciennes données.

        Args:
            days_old (int): Age en jours pour suppression
        """
        try:
            cursor = self.connection.cursor()

            # Nettoyer le cache ancien
            cursor.execute("""
                DELETE FROM owner_cache
                WHERE datetime(last_updated) < datetime('now', '-{} days')
            """.format(days_old))

            cache_deleted = cursor.rowcount

            # Nettoyer les recherches anciennes
            cursor.execute("""
                DELETE FROM fuzzy_searches
                WHERE datetime(search_timestamp) < datetime('now', '-{} days')
            """.format(days_old))

            searches_deleted = cursor.rowcount

            # Nettoyer les métriques anciennes
            cursor.execute("""
                DELETE FROM search_metrics
                WHERE datetime(timestamp) < datetime('now', '-{} days')
            """.format(days_old))

            metrics_deleted = cursor.rowcount

            self.connection.commit()

            if self.logger:
                self.logger.info("Database cleanup completed", module="OwnerDatabase",
                               cache_deleted=cache_deleted, searches_deleted=searches_deleted,
                               metrics_deleted=metrics_deleted)

            return True

        except Exception as e:
            if self.logger:
                self.logger.error("Database cleanup failed", module="OwnerDatabase", error=str(e))
            return False

    def close(self):
        """Ferme la connexion à la base de données."""
        try:
            if self.connection:
                self.connection.close()
                self.connection = None

            if self.logger:
                self.logger.debug("Database connection closed", module="OwnerDatabase")

        except Exception as e:
            if self.logger:
                self.logger.error("Database close failed", module="OwnerDatabase", error=str(e))

    def __del__(self):
        """Destructeur pour fermer la connexion."""
        self.close()

class AdvancedOwnerResearchEngine:
    """
    Moteur de recherche de propriétaires avancé avec scoring et recherche floue.
    """

    def __init__(
        self,
        debug: bool = False,
        cache_db: str = "owner_cache.db",
        config: dict[str, object] | None = None,
    ) -> None:
        """
        Initialise le moteur de recherche.

        Args:
            debug (bool): Mode debug
            cache_db (str): Chemin de la base de données de cache
            config (dict): Configuration personnalisée
        """
        try:
            # Initialiser le logger
            self.logger = AdvancedOwnerLogger(debug=debug)

            # Configuration par défaut
            self.config = {
                'max_threads': 20,
                'request_timeout': 10,
                'rate_limit_delay': 1.0,
                'cache_max_age_hours': 24,
                'min_confidence_score': 0.6,
                'whois_servers': {
                    'com': 'whois.verisign-grs.com',
                    'net': 'whois.verisign-grs.com',
                    'org': 'whois.pir.org',
                    'fr': 'whois.afnic.fr',
                    'uk': 'whois.nominet.uk'
                },
                'fuzzy_algorithms': {
                    'exact': {'weight': 1.0, 'enabled': True},
                    'substring': {'weight': 0.8, 'enabled': True},
                    'sequence': {'weight': 0.7, 'enabled': True},
                    'levenshtein': {'weight': 0.75, 'enabled': True},
                    'jaro_winkler': {'weight': 0.72, 'enabled': True}
                }
            }

            # Appliquer la configuration personnalisée
            if config:
                self.config.update(config)

            # Initialiser les composants
            self.fuzzy_matcher = FuzzyMatcher(self.logger)
            self.fuzzy_matcher.configure_algorithms(self.config['fuzzy_algorithms'])

            self.database = OwnerDatabase(cache_db, self.logger)

            # État et métriques
            self.session_id = self._generate_session_id()
            self.metrics = {
                'session_start': time.time(),
                'domains_processed': 0,
                'cache_hits': 0,
                'cache_misses': 0,
                'whois_queries': 0,
                'fuzzy_searches': 0,
                'successful_matches': 0,
                'threading_stats': defaultdict(int)
            }

            # Threading
            self.thread_lock = threading.Lock()
            self.active_threads = 0

            self.logger.success("Advanced Owner Research Engine initialized",
                              module="AdvancedOwnerResearchEngine", session_id=self.session_id)

        except Exception as e:
            if hasattr(self, 'logger'):
                self.logger.critical("Engine initialization failed",
                                   module="AdvancedOwnerResearchEngine", error=str(e))
            raise

    def _generate_session_id(self):
        """Génère un ID de session unique."""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            hash_part = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
            return "owner_research_{}_{}".format(timestamp, hash_part)
        except Exception:
            return "owner_research_unknown"

    def research_owner_from_file(self, input_file, expected_owners_file=None,
                               output_file=None, output_format='json'):
        """
        Recherche les propriétaires depuis un fichier de domaines.

        Args:
            input_file (str): Fichier contenant les domaines
            expected_owners_file (str): Fichier avec domaines et propriétaires attendus
            output_file (str): Fichier de sortie
            output_format (str): Format de sortie (json, csv)

        Returns:
            dict: Résultats de la recherche
        """
        try:
            self.logger.info("Starting owner research from file",
                           module="AdvancedOwnerResearchEngine",
                           input_file=input_file, expected_owners=expected_owners_file)

            # Lire les domaines
            domains = self._read_domains_file(input_file)
            if not domains:
                self.logger.error("No domains found in input file",
                                module="AdvancedOwnerResearchEngine", input_file=input_file)
                return {'error': 'No domains found'}

            # Lire les propriétaires attendus si fourni
            expected_owners = {}
            if expected_owners_file:
                expected_owners = self._read_expected_owners_file(expected_owners_file)

            # Effectuer la recherche
            results = self._process_domains_threaded(domains, expected_owners)

            # Exporter les résultats
            if output_file:
                self._export_results(results, output_file, output_format)

            # Métriques finales
            self._finalize_metrics()

            self.logger.success("Owner research completed",
                              module="AdvancedOwnerResearchEngine",
                              domains_processed=len(domains),
                              successful_matches=self.metrics['successful_matches'])

            return results

        except Exception as e:
            self.logger.error("Owner research failed",
                            module="AdvancedOwnerResearchEngine", error=str(e))
            return {'error': str(e)}

    def _read_domains_file(self, filename):
        """Lit la liste des domaines depuis un fichier."""
        try:
            domains = []

            self.logger.debug("Reading domains file",
                            module="AdvancedOwnerResearchEngine", filename=filename)

            with open(filename, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Ignorer les lignes vides et commentaires
                    if not line or line.startswith('#') or line.startswith('//'):
                        continue

                    # Nettoyer le domaine
                    domain = self._clean_domain(line)
                    if domain and self._is_valid_domain(domain):
                        domains.append(domain)
                    else:
                        self.logger.warning("Invalid domain skipped",
                                          module="AdvancedOwnerResearchEngine",
                                          line_num=line_num, domain=line)

            self.logger.info("Domains file read successfully",
                           module="AdvancedOwnerResearchEngine",
                           filename=filename, domains_count=len(domains))

            return domains

        except Exception as e:
            self.logger.error("Failed to read domains file",
                            module="AdvancedOwnerResearchEngine",
                            filename=filename, error=str(e))
            return []

    def _read_expected_owners_file(self, filename):
        """Lit le fichier des propriétaires attendus."""
        try:
            expected_owners = {}

            self.logger.debug("Reading expected owners file",
                            module="AdvancedOwnerResearchEngine", filename=filename)

            # Détecter le format (CSV ou texte simple)
            if filename.lower().endswith('.csv'):
                with open(filename, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)

                    # Ignorer l'en-tête si présent
                    first_row = next(reader, None)
                    if first_row and ('domain' in first_row[0].lower() or 'owner' in ' '.join(first_row).lower()):
                        pass  # C'est un en-tête, continuer
                    else:
                        # Traiter la première ligne comme données
                        if first_row and len(first_row) >= 2:
                            domain = self._clean_domain(first_row[0])
                            owner = first_row[1].strip()
                            if domain and owner:
                                expected_owners[domain] = owner

                    # Traiter le reste
                    for row_num, row in enumerate(reader, 2):
                        if len(row) >= 2:
                            domain = self._clean_domain(row[0])
                            owner = row[1].strip()
                            if domain and owner:
                                expected_owners[domain] = owner
                            else:
                                self.logger.warning("Invalid row in expected owners file",
                                                  module="AdvancedOwnerResearchEngine",
                                                  row_num=row_num, row=row)
            else:
                # Format texte simple: domaine|propriétaire ou domaine:propriétaire
                with open(filename, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()

                        if not line or line.startswith('#'):
                            continue

                        # Essayer différents séparateurs
                        parts = None
                        for sep in ['|', ':', '\t', ';']:
                            if sep in line:
                                parts = line.split(sep, 1)
                                break

                        if parts and len(parts) == 2:
                            domain = self._clean_domain(parts[0])
                            owner = parts[1].strip()
                            if domain and owner:
                                expected_owners[domain] = owner
                            else:
                                self.logger.warning("Invalid line in expected owners file",
                                                  module="AdvancedOwnerResearchEngine",
                                                  line_num=line_num, line=line)

            self.logger.info("Expected owners file read successfully",
                           module="AdvancedOwnerResearchEngine",
                           filename=filename, owners_count=len(expected_owners))

            return expected_owners

        except Exception as e:
            self.logger.error("Failed to read expected owners file",
                            module="AdvancedOwnerResearchEngine",
                            filename=filename, error=str(e))
            return {}

    def _clean_domain(self, domain_str):
        """Nettoie et normalise un domaine."""
        try:
            if not domain_str:
                return None

            # Supprimer les protocoles
            domain = domain_str.strip().lower()
            if domain.startswith(('http://', 'https://')):
                domain = urlparse.urlparse(domain).netloc

            # Supprimer les ports
            if ':' in domain:
                domain = domain.split(':')[0]

            # Supprimer les chemins
            if '/' in domain:
                domain = domain.split('/')[0]

            return domain.strip() if domain else None

        except Exception:
            return None

    def _is_valid_domain(self, domain):
        """Vérifie si un domaine est valide."""
        try:
            if not domain or len(domain) < 3 or len(domain) > 253:
                return False

            # Pattern basique pour domaine
            domain_pattern = re.compile(
                r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
                r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
            )

            return bool(domain_pattern.match(domain))

        except Exception:
            return False

    def _process_domains_threaded(self, domains, expected_owners):
        """Traite les domaines avec multi-threading."""
        try:
            self.logger.info("Starting threaded domain processing",
                           module="AdvancedOwnerResearchEngine",
                           domains_count=len(domains), max_threads=self.config['max_threads'])

            results = {
                'processed_domains': [],
                'fuzzy_matches': [],
                'statistics': {},
                'session_info': {
                    'session_id': self.session_id,
                    'start_time': datetime.now().isoformat(),
                    'domains_count': len(domains),
                    'expected_owners_count': len(expected_owners)
                }
            }

            # Queue pour les résultats
            results_queue = queue.Queue()
            threads = []

            # Créer et démarrer les threads
            for i in range(min(self.config['max_threads'], len(domains))):
                thread = threading.Thread(
                    target=self._domain_worker,
                    args=(domains, expected_owners, results_queue),
                    daemon=True
                )
                threads.append(thread)
                thread.start()

                with self.thread_lock:
                    self.active_threads += 1
                    self.metrics['threading_stats']['threads_created'] += 1

            # Attendre que tous les threads se terminent
            for thread in threads:
                thread.join()

            # Collecter les résultats
            while not results_queue.empty():
                try:
                    result = results_queue.get_nowait()
                    if result['type'] == 'domain_processed':
                        results['processed_domains'].append(result['data'])
                    elif result['type'] == 'fuzzy_match':
                        results['fuzzy_matches'].append(result['data'])
                except queue.Empty:
                    break

            # Calculer les statistiques
            results['statistics'] = self._calculate_final_statistics(results)
            results['session_info']['end_time'] = datetime.now().isoformat()

            self.logger.info("Threaded processing completed",
                           module="AdvancedOwnerResearchEngine",
                           processed=len(results['processed_domains']),
                           fuzzy_matches=len(results['fuzzy_matches']))

            return results

        except Exception as e:
            self.logger.error("Threaded processing failed",
                            module="AdvancedOwnerResearchEngine", error=str(e))
            return {'error': str(e)}

    def _domain_worker(self, domains, expected_owners, results_queue):
        """Worker thread pour traiter les domaines."""
        try:
            with self.thread_lock:
                thread_id = threading.current_thread().ident
                self.logger.debug("Domain worker started",
                                module="AdvancedOwnerResearchEngine", thread_id=thread_id)

            while True:
                # Obtenir le prochain domaine à traiter
                domain_to_process = None

                with self.thread_lock:
                    if domains:
                        domain_to_process = domains.pop(0)
                        self.metrics['domains_processed'] += 1

                if not domain_to_process:
                    break  # Plus de domaines à traiter

                try:
                    # Traiter le domaine
                    domain_result = self._process_single_domain(domain_to_process)

                    # Ajouter aux résultats
                    results_queue.put({
                        'type': 'domain_processed',
                        'data': domain_result
                    })

                    # Si on a un propriétaire attendu, faire la recherche floue
                    if domain_to_process in expected_owners:
                        expected_owner = expected_owners[domain_to_process]
                        actual_owner = domain_result.get('owner_info', {}).get('owner_name', '')

                        if actual_owner:
                            fuzzy_result = self._perform_fuzzy_search(
                                domain_to_process, actual_owner, expected_owner
                            )

                            results_queue.put({
                                'type': 'fuzzy_match',
                                'data': fuzzy_result
                            })

                    # Rate limiting
                    time.sleep(self.config['rate_limit_delay'])

                except Exception as e:
                    self.logger.error("Domain processing failed in worker",
                                    module="AdvancedOwnerResearchEngine",
                                    domain=domain_to_process, thread_id=thread_id, error=str(e))

                    # Ajouter un résultat d'erreur
                    results_queue.put({
                        'type': 'domain_processed',
                        'data': {
                            'domain': domain_to_process,
                            'error': str(e),
                            'processed_at': datetime.now().isoformat()
                        }
                    })

            with self.thread_lock:
                self.active_threads -= 1
                self.metrics['threading_stats']['threads_completed'] += 1

                self.logger.debug("Domain worker completed",
                                module="AdvancedOwnerResearchEngine", thread_id=thread_id)

        except Exception as e:
            with self.thread_lock:
                self.active_threads -= 1
                self.metrics['threading_stats']['threads_failed'] += 1

            self.logger.error("Domain worker failed",
                            module="AdvancedOwnerResearchEngine", error=str(e))

    def _process_single_domain(self, domain):
        """Traite un seul domaine."""
        try:
            self.logger.debug("Processing domain",
                            module="AdvancedOwnerResearchEngine", domain=domain)

            result = {
                'domain': domain,
                'processed_at': datetime.now().isoformat(),
                'owner_info': None,
                'cache_hit': False,
                'processing_time': 0,
                'confidence_score': 0.0
            }

            start_time = time.time()

            # Vérifier le cache d'abord
            cached_info = self.database.get_cached_owner(
                domain, self.config['cache_max_age_hours']
            )

            if cached_info:
                result['owner_info'] = cached_info
                result['cache_hit'] = True
                result['confidence_score'] = cached_info.get('confidence_score', 0.5)

                with self.thread_lock:
                    self.metrics['cache_hits'] += 1

                self.logger.debug("Domain info retrieved from cache",
                                module="AdvancedOwnerResearchEngine", domain=domain)
            else:
                # Effectuer la recherche WHOIS
                whois_info = self._perform_whois_lookup(domain)

                if whois_info:
                    result['owner_info'] = whois_info
                    result['confidence_score'] = whois_info.get('confidence_score', 0.5)

                    # Mettre en cache
                    self.database.cache_owner_info(domain, whois_info)

                    with self.thread_lock:
                        self.metrics['cache_misses'] += 1
                        self.metrics['whois_queries'] += 1

                self.logger.debug("Domain processed via WHOIS",
                                module="AdvancedOwnerResearchEngine",
                                domain=domain, found_owner=bool(whois_info))

            result['processing_time'] = time.time() - start_time

            return result

        except Exception as e:
            self.logger.error("Single domain processing failed",
                            module="AdvancedOwnerResearchEngine",
                            domain=domain, error=str(e))

            return {
                'domain': domain,
                'error': str(e),
                'processed_at': datetime.now().isoformat(),
                'processing_time': 0
            }

    def _perform_whois_lookup(self, domain):
        """Effectue une recherche WHOIS."""
        try:
            self.logger.debug("Performing WHOIS lookup",
                            module="AdvancedOwnerResearchEngine", domain=domain)

            # Déterminer le serveur WHOIS
            tld = domain.split('.')[-1].lower()
            whois_server = self.config['whois_servers'].get(tld, 'whois.iana.org')

            # Effectuer la requête WHOIS (implémentation simplifiée)
            whois_data = self._query_whois_server(domain, whois_server)

            if whois_data:
                # Parser les données WHOIS
                parsed_info = self._parse_whois_data(whois_data)
                parsed_info['raw_whois'] = whois_data
                parsed_info['source'] = 'whois'
                parsed_info['confidence_score'] = self._calculate_whois_confidence(parsed_info)

                return parsed_info

            return None

        except Exception as e:
            self.logger.error("WHOIS lookup failed",
                            module="AdvancedOwnerResearchEngine",
                            domain=domain, error=str(e))
            return None

    def _query_whois_server(self, domain, server, port=43):
        """Effectue une requête vers un serveur WHOIS."""
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config['request_timeout'])

            sock.connect((server, port))
            sock.send((domain + '\r\n').encode('utf-8'))

            response = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data

            sock.close()

            return response.decode('utf-8', errors='ignore')

        except Exception as e:
            self.logger.debug("WHOIS server query failed",
                            module="AdvancedOwnerResearchEngine",
                            domain=domain, server=server, error=str(e))
            return None

    def _parse_whois_data(self, whois_text):
        """Parse les données WHOIS."""
        try:
            info = {
                'owner_name': None,
                'registrar': None,
                'creation_date': None,
                'expiry_date': None,
                'emails': [],
                'phone': None,
                'address': None
            }

            lines = whois_text.split('\n')

            # Patterns de recherche
            patterns = {
                'owner_name': [
                    r'registrant.*?:\s*(.+)',
                    r'owner.*?:\s*(.+)',
                    r'organization.*?:\s*(.+)',
                    r'org.*?:\s*(.+)'
                ],
                'registrar': [
                    r'registrar.*?:\s*(.+)',
                    r'sponsor.*?:\s*(.+)'
                ],
                'creation_date': [
                    r'creation.*?date.*?:\s*(.+)',
                    r'created.*?:\s*(.+)',
                    r'registered.*?:\s*(.+)'
                ],
                'expiry_date': [
                    r'expir.*?date.*?:\s*(.+)',
                    r'expires.*?:\s*(.+)',
                    r'expire.*?:\s*(.+)'
                ]
            }

            # Email pattern
            email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.IGNORECASE)

            # Phone pattern
            phone_pattern = re.compile(r'phone.*?:\s*([+\d\s\-\(\)]+)', re.IGNORECASE)

            for line in lines:
                line_lower = line.strip().lower()

                # Chercher les informations spécifiques
                for field, field_patterns in patterns.items():
                    if info[field]:  # Déjà trouvé
                        continue

                    for pattern in field_patterns:
                        match = re.search(pattern, line_lower)
                        if match:
                            value = match.group(1).strip()
                            if value and value not in ['n/a', 'not available', 'none', '-']:
                                info[field] = value
                                break

                # Chercher les emails
                emails_found = email_pattern.findall(line)
                info['emails'].extend(emails_found)

                # Chercher le téléphone
                if not info['phone']:
                    phone_match = phone_pattern.search(line)
                    if phone_match:
                        info['phone'] = phone_match.group(1).strip()

            # Nettoyer les emails (supprimer doublons)
            info['emails'] = list(set(info['emails']))

            return info

        except Exception as e:
            self.logger.error("WHOIS parsing failed",
                            module="AdvancedOwnerResearchEngine", error=str(e))
            return {}

    def _calculate_whois_confidence(self, parsed_info):
        """Calcule un score de confiance pour les données WHOIS."""
        try:
            score = 0.0
            max_score = 6.0

            # Points pour chaque champ présent
            if parsed_info.get('owner_name'):
                score += 2.0  # Champ le plus important
            if parsed_info.get('registrar'):
                score += 1.0
            if parsed_info.get('creation_date'):
                score += 1.0
            if parsed_info.get('emails'):
                score += 1.0
            if parsed_info.get('phone'):
                score += 0.5
            if parsed_info.get('address'):
                score += 0.5

            return min(score / max_score, 1.0)

        except Exception:
            return 0.5  # Score par défaut

    def _perform_fuzzy_search(self, domain, actual_owner, expected_owner):
        """Effectue une recherche floue entre propriétaires."""
        try:
            self.logger.debug("Performing fuzzy search",
                            module="AdvancedOwnerResearchEngine",
                            domain=domain, actual_owner=actual_owner[:20],
                            expected_owner=expected_owner[:20])

            # Effectuer le matching flou
            match_result = self.fuzzy_matcher.compute_similarity(
                actual_owner, expected_owner
            )

            # Enrichir le résultat
            fuzzy_result = {
                'domain': domain,
                'actual_owner': actual_owner,
                'expected_owner': expected_owner,
                'match_score': match_result['global_score'],
                'match_quality': match_result['quality'],
                'threshold_category': match_result['threshold_category'],
                'algorithms_scores': match_result['algorithms'],
                'is_match': match_result['global_score'] >= self.config['min_confidence_score'],
                'processed_at': datetime.now().isoformat()
            }

            # Stocker dans la base de données
            self.database.store_fuzzy_search(
                actual_owner, expected_owner, match_result
            )

            with self.thread_lock:
                self.metrics['fuzzy_searches'] += 1
                if fuzzy_result['is_match']:
                    self.metrics['successful_matches'] += 1

            self.logger.debug("Fuzzy search completed",
                            module="AdvancedOwnerResearchEngine",
                            domain=domain, match_score=match_result['global_score'],
                            is_match=fuzzy_result['is_match'])

            return fuzzy_result

        except Exception as e:
            self.logger.error("Fuzzy search failed",
                            module="AdvancedOwnerResearchEngine",
                            domain=domain, error=str(e))

            return {
                'domain': domain,
                'actual_owner': actual_owner,
                'expected_owner': expected_owner,
                'error': str(e),
                'processed_at': datetime.now().isoformat()
            }

    def _calculate_final_statistics(self, results):
        """Calcule les statistiques finales."""
        try:
            stats = {
                'domains_processed': len(results['processed_domains']),
                'successful_owner_lookups': len([d for d in results['processed_domains']
                                               if d.get('owner_info') and not d.get('error')]),
                'cache_hits': self.metrics['cache_hits'],
                'cache_misses': self.metrics['cache_misses'],
                'whois_queries': self.metrics['whois_queries'],
                'fuzzy_searches_performed': len(results['fuzzy_matches']),
                'successful_fuzzy_matches': len([f for f in results['fuzzy_matches']
                                               if f.get('is_match', False)]),
                'threading_stats': dict(self.metrics['threading_stats']),
                'processing_time': time.time() - self.metrics['session_start']
            }

            # Calculer les moyennes
            if results['fuzzy_matches']:
                scores = [f.get('match_score', 0) for f in results['fuzzy_matches']
                         if 'match_score' in f]
                if scores:
                    stats['average_match_score'] = sum(scores) / len(scores)
                    stats['max_match_score'] = max(scores)
                    stats['min_match_score'] = min(scores)

            # Distribution des qualités de match
            quality_distribution = defaultdict(int)
            for match in results['fuzzy_matches']:
                quality = match.get('match_quality', 'unknown')
                quality_distribution[quality] += 1
            stats['match_quality_distribution'] = dict(quality_distribution)

            # Taux de succès
            if stats['domains_processed'] > 0:
                stats['owner_lookup_success_rate'] = (stats['successful_owner_lookups'] /
                                                    stats['domains_processed'])

            if stats['fuzzy_searches_performed'] > 0:
                stats['fuzzy_match_success_rate'] = (stats['successful_fuzzy_matches'] /
                                                   stats['fuzzy_searches_performed'])

            return stats

        except Exception as e:
            self.logger.error("Statistics calculation failed",
                            module="AdvancedOwnerResearchEngine", error=str(e))
            return {'error': str(e)}

    def _export_results(self, results, output_file, output_format):
        """Exporte les résultats."""
        try:
            self.logger.info("Exporting results",
                           module="AdvancedOwnerResearchEngine",
                           output_file=output_file, format=output_format)

            if output_format.lower() == 'json':
                self._export_json(results, output_file)
            elif output_format.lower() == 'csv':
                self._export_csv(results, output_file)
            else:
                self.logger.error("Unsupported export format",
                                module="AdvancedOwnerResearchEngine", format=output_format)
                return False

            self.logger.success("Results exported successfully",
                              module="AdvancedOwnerResearchEngine", output_file=output_file)
            return True

        except Exception as e:
            self.logger.error("Results export failed",
                            module="AdvancedOwnerResearchEngine",
                            output_file=output_file, error=str(e))
            return False

    def _export_json(self, results, output_file):
        """Exporte au format JSON."""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            self.logger.error("JSON export failed",
                            module="AdvancedOwnerResearchEngine", error=str(e))
            raise

    def _export_csv(self, results, output_file):
        """Exporte au format CSV."""
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)

                # En-têtes pour les domaines
                writer.writerow([
                    'Domain', 'Owner_Name', 'Registrar', 'Creation_Date',
                    'Expiry_Date', 'Emails', 'Phone', 'Cache_Hit',
                    'Processing_Time', 'Confidence_Score'
                ])

                # Données des domaines
                for domain_data in results.get('processed_domains', []):
                    owner_info = domain_data.get('owner_info', {})

                    emails = '; '.join(owner_info.get('emails', []))

                    writer.writerow([
                        domain_data.get('domain', ''),
                        owner_info.get('owner_name', ''),
                        owner_info.get('registrar', ''),
                        owner_info.get('creation_date', ''),
                        owner_info.get('expiry_date', ''),
                        emails,
                        owner_info.get('phone', ''),
                        domain_data.get('cache_hit', False),
                        domain_data.get('processing_time', 0),
                        domain_data.get('confidence_score', 0)
                    ])

                # Séparer les sections
                writer.writerow([])
                writer.writerow(['=== FUZZY MATCHES ==='])
                writer.writerow([
                    'Domain', 'Actual_Owner', 'Expected_Owner', 'Match_Score',
                    'Match_Quality', 'Is_Match', 'Threshold_Category'
                ])

                # Données des matches flous
                for match_data in results.get('fuzzy_matches', []):
                    writer.writerow([
                        match_data.get('domain', ''),
                        match_data.get('actual_owner', ''),
                        match_data.get('expected_owner', ''),
                        match_data.get('match_score', 0),
                        match_data.get('match_quality', ''),
                        match_data.get('is_match', False),
                        match_data.get('threshold_category', '')
                    ])

        except Exception as e:
            self.logger.error("CSV export failed",
                            module="AdvancedOwnerResearchEngine", error=str(e))
            raise

    def _finalize_metrics(self):
        """Finalise les métriques de session."""
        try:
            session_metrics = {
                'session_id': self.session_id,
                'search_type': 'owner_research',
                'total_searches': self.metrics['domains_processed'],
                'successful_matches': self.metrics['successful_matches'],
                'average_score': 0.0,  # À calculer si nécessaire
                'execution_time': time.time() - self.metrics['session_start']
            }

            # Stocker les métriques
            self.database.store_metrics(self.session_id, session_metrics)

            self.logger.info("Session metrics finalized",
                           module="AdvancedOwnerResearchEngine",
                           session_id=self.session_id)

        except Exception as e:
            self.logger.error("Metrics finalization failed",
                            module="AdvancedOwnerResearchEngine", error=str(e))

    def close(self):
        """Ferme le moteur et nettoie les ressources."""
        try:
            self.logger.info("Closing Advanced Owner Research Engine",
                           module="AdvancedOwnerResearchEngine")

            # Fermer la base de données
            if hasattr(self, 'database'):
                self.database.close()

            # Nettoyer les anciens data
            try:
                self.database.cleanup_old_data(30)  # 30 jours
            except Exception:
                pass  # Pas critique

            self.logger.success("Advanced Owner Research Engine closed successfully",
                              module="AdvancedOwnerResearchEngine")

        except Exception as e:
            self.logger.error("Engine closing failed",
                            module="AdvancedOwnerResearchEngine", error=str(e))

    def __del__(self):
        """Destructeur."""
        try:
            self.close()
        except Exception:
            pass


# Fonction principale pour utilisation en ligne de commande
def main():
    """Fonction principale."""
    try:
        import argparse

        parser = argparse.ArgumentParser(
            description="Advanced Owner Research Engine v2.1",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        parser.add_argument('-i', '--input', required=True,
                          help="Input file with domains")
        parser.add_argument('-e', '--expected',
                          help="File with expected owners (domain|owner format)")
        parser.add_argument('-o', '--output', required=True,
                          help="Output file for results")
        parser.add_argument('-f', '--format', choices=['json', 'csv'],
                          default='json', help="Output format")
        parser.add_argument('--debug', action='store_true',
                          help="Enable debug logging")
        parser.add_argument('--threads', type=int, default=10,
                          help="Maximum threads (default: 10)")
        parser.add_argument('--cache-hours', type=int, default=24,
                          help="Cache max age in hours (default: 24)")

        args = parser.parse_args()

        # Configuration
        config = {
            'max_threads': args.threads,
            'cache_max_age_hours': args.cache_hours
        }

        # Créer le moteur
        engine = AdvancedOwnerResearchEngine(
            debug=args.debug,
            config=config
        )

        try:
            # Effectuer la recherche
            results = engine.research_owner_from_file(
                args.input,
                args.expected,
                args.output,
                args.format
            )

            if 'error' in results:
                engine.logger.error("Research failed", error=results['error'])
                return 1

            # Afficher le résumé
            stats = results.get('statistics', {})
            engine.logger.success("Research completed successfully",
                                 domains_processed=stats.get('domains_processed', 0),
                                 successful_matches=stats.get('successful_fuzzy_matches', 0))

            return 0

        finally:
            engine.close()

    except KeyboardInterrupt:
        print("\nResearch interrupted by user")
        return 0
    except Exception as e:
        print("CRITICAL ERROR: {}".format(str(e)))
        return 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
