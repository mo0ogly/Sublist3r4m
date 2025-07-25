#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Suite Complet v2.1 - Tests Unitaires Professionnels

Suite de tests exhaustive pour:
- Sublist3r Enhanced
- Owner Research Engine
- SubBrute GUI Advanced
- Toutes les fonctionnalités et modules

Features:
- Tests unitaires complets avec coverage
- Tests d'intégration multi-composants
- Tests de performance et stress
- Tests de sécurité et validation
- Mocking des services externes
- Rapports détaillés avec métriques
- Tests de régression automatisés
- Validation des exports et formats

Author: Enhanced Security Team
License: MIT
"""

import sys
import os
import unittest
import tempfile
import shutil
import json
import csv
import time
import threading
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
import logging

# Python 2/3 compatibility
if sys.version_info[0] >= 3:
    from unittest.mock import Mock, patch, MagicMock
    from io import StringIO
else:
    try:
        from mock import Mock, patch, MagicMock
    except ImportError:
        print("ERROR: mock library required for Python 2. Install with: pip install mock")
        sys.exit(1)
    from StringIO import StringIO

# Ajouter le répertoire parent au path pour les imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Imports des modules à tester
try:
    from owner_research_engine import (
        AdvancedOwnerLogger, FuzzyMatcher, OwnerDatabase, 
        AdvancedOwnerResearchEngine
    )
    OWNER_ENGINE_AVAILABLE = True
except ImportError as e:
    print("WARNING: Owner Research Engine not available: {}".format(e))
    OWNER_ENGINE_AVAILABLE = False

try:
    from sublist3r_enhanced import (
        EnhancedLogger, SecurityValidator, ProgressBar,
        enhanced_main, write_file_enhanced
    )
    SUBLIST3R_ENHANCED_AVAILABLE = True
except ImportError as e:
    print("WARNING: Sublist3r Enhanced not available: {}".format(e))
    SUBLIST3R_ENHANCED_AVAILABLE = False


class TestLogger:
    """Logger simple pour les tests."""
    
    def __init__(self):
        self.messages = []
    
    def log(self, level, message, **kwargs):
        self.messages.append({
            'level': level,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'kwargs': kwargs
        })
    
    def debug(self, message, **kwargs):
        self.log('DEBUG', message, **kwargs)
    
    def info(self, message, **kwargs):
        self.log('INFO', message, **kwargs)
    
    def warning(self, message, **kwargs):
        self.log('WARNING', message, **kwargs)
    
    def error(self, message, **kwargs):
        self.log('ERROR', message, **kwargs)
    
    def critical(self, message, **kwargs):
        self.log('CRITICAL', message, **kwargs)
    
    def success(self, message, **kwargs):
        self.log('SUCCESS', message, **kwargs)
    
    def get_messages(self, level=None):
        if level:
            return [m for m in self.messages if m['level'] == level]
        return self.messages
    
    def clear(self):
        self.messages = []


class TestConfiguration:
    """Configuration centralisée pour les tests."""
    
    # Répertoires temporaires
    TEMP_DIR = None
    LOGS_DIR = None
    CACHE_DIR = None
    
    # Fichiers de test
    TEST_DOMAINS_FILE = None
    TEST_OWNERS_FILE = None
    TEST_OUTPUT_FILE = None
    
    # Données de test
    SAMPLE_DOMAINS = [
        'example.com',
        'test.example.com',
        'subdomain.example.org',
        'demo.test.net'
    ]
    
    SAMPLE_OWNERS = {
        'example.com': 'Example Corporation',
        'test.example.com': 'Test Company Ltd',
        'subdomain.example.org': 'Demo Organization',
        'demo.test.net': 'Network Solutions Inc'
    }
    
    SAMPLE_WHOIS_DATA = """
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.iana.org
Registrar URL: http://res-dom.iana.org
Updated Date: 2020-08-14T07:01:31Z
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2021-08-13T04:00:00Z
Registrar: RESERVED-Internet Assigned Numbers Authority
Registrar IANA ID: 376
Registrar Abuse Contact Email: ops@iana.org
Registrar Abuse Contact Phone: 
Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
DNSSEC: signedDelegation
DNSSEC DS Data: 31589 8 1 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE
DNSSEC DS Data: 31589 8 2 CDE0D742D6998AA554A92D890F8184C698CFAC8A26FA59875A990C03E576343C
DNSSEC DS Data: 43547 8 1 B6225AB2CC613E0DCA7962BDC2342EA4F1B56083
DNSSEC DS Data: 43547 8 2 615A64233543F66F44D68933625B17497C89A70E858ED76A2145997EDF96A918
DNSSEC DS Data: 31406 8 1 189968811E6EBA862DD6C209F75623D8D9ED9142
DNSSEC DS Data: 31406 8 2 F78CF3344F72137235098ECBBD08947C2C9001C7F6A085A17F518B5D8F6B916D
URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2021-02-19T17:30:12Z <<<
    """
    
    @classmethod
    def setup(cls):
        """Configure l'environnement de test."""
        try:
            # Créer les répertoires temporaires
            cls.TEMP_DIR = tempfile.mkdtemp(prefix='sublist3r_tests_')
            cls.LOGS_DIR = os.path.join(cls.TEMP_DIR, 'logs')
            cls.CACHE_DIR = os.path.join(cls.TEMP_DIR, 'cache')
            
            os.makedirs(cls.LOGS_DIR)
            os.makedirs(cls.CACHE_DIR)
            
            # Créer les fichiers de test
            cls._create_test_files()
            
            print("Test environment setup completed: {}".format(cls.TEMP_DIR))
            
        except Exception as e:
            print("ERROR: Failed to setup test environment: {}".format(e))
            raise
    
    @classmethod
    def _create_test_files(cls):
        """Crée les fichiers de test."""
        try:
            # Fichier de domaines
            cls.TEST_DOMAINS_FILE = os.path.join(cls.TEMP_DIR, 'test_domains.txt')
            with open(cls.TEST_DOMAINS_FILE, 'w') as f:
                for domain in cls.SAMPLE_DOMAINS:
                    f.write(domain + '\n')
            
            # Fichier de propriétaires attendus
            cls.TEST_OWNERS_FILE = os.path.join(cls.TEMP_DIR, 'test_owners.csv')
            with open(cls.TEST_OWNERS_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Domain', 'Expected_Owner'])
                for domain, owner in cls.SAMPLE_OWNERS.items():
                    writer.writerow([domain, owner])
            
            # Fichier de sortie
            cls.TEST_OUTPUT_FILE = os.path.join(cls.TEMP_DIR, 'test_output.json')
            
        except Exception as e:
            print("ERROR: Failed to create test files: {}".format(e))
            raise
    
    @classmethod
    def teardown(cls):
        """Nettoie l'environnement de test."""
        try:
            if cls.TEMP_DIR and os.path.exists(cls.TEMP_DIR):
                shutil.rmtree(cls.TEMP_DIR)
                print("Test environment cleaned up")
        except Exception as e:
            print("WARNING: Failed to cleanup test environment: {}".format(e))


@unittest.skipUnless(OWNER_ENGINE_AVAILABLE, "Owner Research Engine not available")
class TestAdvancedOwnerLogger(unittest.TestCase):
    """Tests pour AdvancedOwnerLogger."""
    
    def setUp(self):
        """Configuration avant chaque test."""
        self.temp_dir = tempfile.mkdtemp()
        self.log_dir = os.path.join(self.temp_dir, 'logs')
        
    def tearDown(self):
        """Nettoyage après chaque test."""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_logger_initialization(self):
        """Test l'initialisation du logger."""
        logger = AdvancedOwnerLogger(log_dir=self.log_dir, debug=True)
        
        self.assertIsNotNone(logger.logger)
        self.assertTrue(logger.debug_enabled)
        self.assertTrue(os.path.exists(self.log_dir))
        self.assertIsNotNone(logger.session_id)
        self.assertIn('owner_session_', logger.session_id)
    
    def test_logging_methods(self):
        """Test toutes les méthodes de logging."""
        logger = AdvancedOwnerLogger(log_dir=self.log_dir, debug=True)
        
        # Test chaque niveau
        logger.debug("Debug message", module="TestModule", test_param="value")
        logger.info("Info message", module="TestModule")
        logger.warning("Warning message", module="TestModule")
        logger.error("Error message", module="TestModule")
        logger.critical("Critical message", module="TestModule")
        logger.success("Success message", module="TestModule")
        
        # Vérifier les métriques
        metrics = logger.metrics
        self.assertEqual(metrics['total_messages'], 6)
        self.assertEqual(metrics['messages_by_level']['DEBUG'], 1)
        self.assertEqual(metrics['messages_by_level']['INFO'], 1)
        self.assertEqual(metrics['messages_by_level']['ERROR'], 1)
        self.assertEqual(metrics['errors_count'], 2)  # ERROR + CRITICAL
    
    def test_session_id_uniqueness(self):
        """Test l'unicité des IDs de session."""
        logger1 = AdvancedOwnerLogger(log_dir=self.log_dir)
        time.sleep(0.1)  # Assurer une différence de temps
        logger2 = AdvancedOwnerLogger(log_dir=self.log_dir)
        
        self.assertNotEqual(logger1.session_id, logger2.session_id)
    
    def test_log_file_creation(self):
        """Test la création des fichiers de log."""
        logger = AdvancedOwnerLogger(log_dir=self.log_dir)
        logger.info("Test message")
        
        # Vérifier que le fichier principal est créé
        main_log = os.path.join(self.log_dir, "owner_research.log")
        self.assertTrue(os.path.exists(main_log))
        
        # Vérifier le contenu
        with open(main_log, 'r') as f:
            content = f.read()
            self.assertIn("Test message", content)


@unittest.skipUnless(OWNER_ENGINE_AVAILABLE, "Owner Research Engine not available")
class TestFuzzyMatcher(unittest.TestCase):
    """Tests pour FuzzyMatcher."""
    
    def setUp(self):
        """Configuration avant chaque test."""
        self.logger = TestLogger()
        self.matcher = FuzzyMatcher(self.logger)
    
    def test_exact_match(self):
        """Test le matching exact."""
        # Matches exacts
        self.assertEqual(self.matcher.exact_match("test", "test"), 1.0)
        self.assertEqual(self.matcher.exact_match("Test", "TEST"), 1.0)
        self.assertEqual(self.matcher.exact_match("  test  ", "test"), 1.0)
        
        # Non-matches
        self.assertEqual(self.matcher.exact_match("test", "different"), 0.0)
        self.assertEqual(self.matcher.exact_match("", "test"), 0.0)
    
    def test_substring_match(self):
        """Test le matching par sous-chaîne."""
        # Sous-chaînes
        score = self.matcher.substring_match("test", "testing")
        self.assertGreater(score, 0.5)
        
        score = self.matcher.substring_match("corp", "corporation")
        self.assertGreater(score, 0.3)
        
        # Pas de sous-chaîne
        self.assertEqual(self.matcher.substring_match("test", "example"), 0.0)
    
    def test_sequence_match(self):
        """Test le matching par séquence."""
        # Chaînes similaires
        score = self.matcher.sequence_match("example", "exemple")
        self.assertGreater(score, 0.8)
        
        score = self.matcher.sequence_match("corporation", "corp")
        self.assertGreater(score, 0.3)
        
        # Chaînes très différentes
        score = self.matcher.sequence_match("abc", "xyz")
        self.assertLess(score, 0.3)
    
    def test_levenshtein_distance(self):
        """Test la distance de Levenshtein."""
        # Chaînes identiques
        self.assertEqual(self.matcher.levenshtein_distance("test", "test"), 1.0)
        
        # Chaînes similaires
        score = self.matcher.levenshtein_distance("test", "tests")
        self.assertGreater(score, 0.7)
        
        score = self.matcher.levenshtein_distance("example", "exemple")
        self.assertGreater(score, 0.8)
        
        # Chaînes très différentes
        score = self.matcher.levenshtein_distance("abc", "xyz")
        self.assertLess(score, 0.5)
    
    def test_soundex(self):
        """Test l'algorithme Soundex."""
        # Mots qui sonnent similaires
        soundex1 = self.matcher.soundex("Smith")
        soundex2 = self.matcher.soundex("Smyth")
        self.assertEqual(soundex1, soundex2)
        
        soundex1 = self.matcher.soundex("Johnson")
        soundex2 = self.matcher.soundex("Jonson")
        self.assertEqual(soundex1, soundex2)
        
        # Mots différents
        soundex1 = self.matcher.soundex("Smith")
        soundex2 = self.matcher.soundex("Brown")
        self.assertNotEqual(soundex1, soundex2)
    
    def test_jaro_winkler_similarity(self):
        """Test la similarité Jaro-Winkler."""
        # Chaînes identiques
        self.assertEqual(self.matcher.jaro_winkler_similarity("test", "test"), 1.0)
        
        # Chaînes similaires avec préfixe commun
        score = self.matcher.jaro_winkler_similarity("prefix_test", "prefix_demo")
        self.assertGreater(score, 0.5)
        
        # Chaînes différentes
        score = self.matcher.jaro_winkler_similarity("abc", "xyz")
        self.assertLess(score, 0.5)
    
    def test_ngram_similarity(self):
        """Test la similarité par n-grammes."""
        # Chaînes avec n-grammes communs
        score = self.matcher.ngram_similarity("testing", "tester", n=2)
        self.assertGreater(score, 0.5)
        
        score = self.matcher.ngram_similarity("example", "simple", n=2)
        self.assertGreater(score, 0.2)
        
        # Chaînes sans n-grammes communs
        score = self.matcher.ngram_similarity("abc", "xyz", n=2)
        self.assertEqual(score, 0.0)
    
    def test_compute_similarity_comprehensive(self):
        """Test la similarité globale avec tous les algorithmes."""
        # Test avec des noms de sociétés similaires
        result = self.matcher.compute_similarity(
            "Microsoft Corporation", 
            "Microsoft Corp"
        )
        
        self.assertIsInstance(result, dict)
        self.assertIn('global_score', result)
        self.assertIn('algorithms', result)
        self.assertIn('quality', result)
        
        # Score élevé attendu
        self.assertGreater(result['global_score'], 0.8)
        self.assertIn(result['quality'], ['excellent', 'very_good', 'good'])
        
        # Vérifier que plusieurs algorithmes ont été utilisés
        self.assertGreater(len(result['algorithms']), 3)
    
    def test_compute_similarity_different_strings(self):
        """Test avec des chaînes très différentes."""
        result = self.matcher.compute_similarity(
            "Apple Inc", 
            "Google LLC"
        )
        
        # Score faible attendu
        self.assertLess(result['global_score'], 0.5)
        self.assertIn(result['quality'], ['poor', 'very_poor'])
    
    def test_algorithm_configuration(self):
        """Test la configuration des algorithmes."""
        # Configuration personnalisée
        custom_config = {
            'exact': {'weight': 2.0, 'enabled': True},
            'substring': {'weight': 0.5, 'enabled': False},
            'sequence': {'weight': 1.5, 'enabled': True}
        }
        
        self.matcher.configure_algorithms(custom_config)
        
        # Vérifier que la configuration a été appliquée
        self.assertEqual(self.matcher.algorithms['exact']['weight'], 2.0)
        self.assertEqual(self.matcher.algorithms['substring']['enabled'], False)
        self.assertEqual(self.matcher.algorithms['sequence']['weight'], 1.5)
    
    def test_metrics_tracking(self):
        """Test le suivi des métriques."""
        initial_comparisons = self.matcher.metrics['comparisons_made']
        
        # Effectuer quelques comparaisons
        self.matcher.compute_similarity("test1", "test2")
        self.matcher.compute_similarity("test3", "test4")
        self.matcher.compute_similarity("identical", "identical")
        
        # Vérifier les métriques
        metrics = self.matcher.get_metrics()
        self.assertEqual(metrics['comparisons_made'], initial_comparisons + 3)
        self.assertGreaterEqual(metrics['matches_found'], 1)  # Au moins le match identique
    
    def test_edge_cases(self):
        """Test les cas limites."""
        # Chaînes vides
        result = self.matcher.compute_similarity("", "test")
        self.assertEqual(result['global_score'], 0.0)
        
        result = self.matcher.compute_similarity("test", "")
        self.assertEqual(result['global_score'], 0.0)
        
        result = self.matcher.compute_similarity("", "")
        self.assertEqual(result['global_score'], 0.0)
        
        # Chaînes None
        result = self.matcher.compute_similarity(None, "test")
        self.assertEqual(result['global_score'], 0.0)


@unittest.skipUnless(OWNER_ENGINE_AVAILABLE, "Owner Research Engine not available")
class TestOwnerDatabase(unittest.TestCase):
    """Tests pour OwnerDatabase."""
    
    def setUp(self):
        """Configuration avant chaque test."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, 'test_owner.db')
        self.logger = TestLogger()
        self.db = OwnerDatabase(self.db_path, self.logger)
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        self.db.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_database_initialization(self):
        """Test l'initialisation de la base de données."""
        self.assertIsNotNone(self.db.connection)
        self.assertTrue(os.path.exists(self.db_path))
        
        # Vérifier que les tables ont été créées
        cursor = self.db.connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        expected_tables = ['owner_cache', 'fuzzy_searches', 'search_metrics']
        for table in expected_tables:
            self.assertIn(table, tables)
    
    def test_cache_owner_info(self):
        """Test la mise en cache des informations de propriétaire."""
        owner_data = {
            'owner_name': 'Test Corporation',
            'registrar': 'Test Registrar',
            'creation_date': '2020-01-01',
            'expiry_date': '2025-01-01',
            'emails': ['admin@test.com', 'tech@test.com'],
            'phone': '+1-555-0123',
            'address': '123 Test St',
            'raw_whois': 'Raw WHOIS data...',
            'source': 'whois',
            'confidence_score': 0.85
        }
        
        # Mettre en cache
        result = self.db.cache_owner_info('test.com', owner_data)
        self.assertTrue(result)
        
        # Vérifier que les données ont été stockées
        cursor = self.db.connection.cursor()
        cursor.execute("SELECT * FROM owner_cache WHERE domain = ?", ('test.com',))
        row = cursor.fetchone()
        
        self.assertIsNotNone(row)
        self.assertEqual(row['domain'], 'test.com')
        self.assertEqual(row['owner_name'], 'Test Corporation')
        self.assertEqual(row['confidence_score'], 0.85)
    
    def test_get_cached_owner(self):
        """Test la récupération du cache."""
        # Mettre en cache des données
        owner_data = {
            'owner_name': 'Cached Corporation',
            'registrar': 'Cache Registrar',
            'emails': ['cache@test.com']
        }
        
        self.db.cache_owner_info('cached.com', owner_data)
        
        # Récupérer du cache
        cached = self.db.get_cached_owner('cached.com', max_age_hours=24)
        
        self.assertIsNotNone(cached)
        self.assertEqual(cached['domain'], 'cached.com')
        self.assertEqual(cached['owner_name'], 'Cached Corporation')
        self.assertIsInstance(cached['emails'], list)
        self.assertIn('cache@test.com', cached['emails'])
    
    def test_cache_expiration(self):
        """Test l'expiration du cache."""
        # Mettre en cache des données
        owner_data = {'owner_name': 'Expired Corporation'}
        self.db.cache_owner_info('expired.com', owner_data)
        
        # Récupérer avec un max_age très court
        cached = self.db.get_cached_owner('expired.com', max_age_hours=0)
        self.assertIsNone(cached)  # Doit être expiré
        
        # Récupérer avec un max_age normal
        cached = self.db.get_cached_owner('expired.com', max_age_hours=24)
        self.assertIsNotNone(cached)  # Doit être disponible
    
    def test_store_fuzzy_search(self):
        """Test le stockage des recherches floues."""
        match_result = {
            'global_score': 0.85,
            'quality': 'very_good',
            'algorithms': {'exact': 0.0, 'substring': 0.9, 'sequence': 0.8}
        }
        
        result = self.db.store_fuzzy_search(
            'Test Corporation', 
            'Test Corp', 
            match_result
        )
        self.assertTrue(result)
        
        # Vérifier le stockage
        cursor = self.db.connection.cursor()
        cursor.execute("SELECT * FROM fuzzy_searches WHERE search_query = ?", ('Test Corporation',))
        row = cursor.fetchone()
        
        self.assertIsNotNone(row)
        self.assertEqual(row['target_owner'], 'Test Corp')
        self.assertEqual(row['match_score'], 0.85)
        self.assertEqual(row['match_quality'], 'very_good')
    
    def test_get_search_history(self):
        """Test la récupération de l'historique."""
        # Ajouter plusieurs recherches
        for i in range(5):
            match_result = {
                'global_score': 0.5 + (i * 0.1),
                'quality': 'fair',
                'algorithms': {}
            }
            self.db.store_fuzzy_search(
                'Query {}'.format(i), 
                'Target {}'.format(i), 
                match_result
            )
        
        # Récupérer l'historique
        history = self.db.get_search_history(limit=3)
        
        self.assertEqual(len(history), 3)
        self.assertIsInstance(history[0], dict)
        self.assertIn('search_query', history[0])
        self.assertIn('algorithms_used', history[0])
    
    def test_store_metrics(self):
        """Test le stockage des métriques."""
        metrics_data = {
            'search_type': 'test_search',
            'total_searches': 100,
            'successful_matches': 75,
            'average_score': 0.78,
            'execution_time': 45.5
        }
        
        result = self.db.store_metrics('test_session_123', metrics_data)
        self.assertTrue(result)
        
        # Vérifier le stockage
        cursor = self.db.connection.cursor()
        cursor.execute("SELECT * FROM search_metrics WHERE session_id = ?", ('test_session_123',))
        row = cursor.fetchone()
        
        self.assertIsNotNone(row)
        self.assertEqual(row['total_searches'], 100)
        self.assertEqual(row['successful_matches'], 75)
        self.assertEqual(row['average_score'], 0.78)
    
    def test_cleanup_old_data(self):
        """Test le nettoyage des anciennes données."""
        # Ajouter des données
        owner_data = {'owner_name': 'Old Corporation'}
        self.db.cache_owner_info('old.com', owner_data)
        
        match_result = {'global_score': 0.5, 'quality': 'fair', 'algorithms': {}}
        self.db.store_fuzzy_search('Old Query', 'Old Target', match_result)
        
        # Vérifier qu'elles existent
        cached = self.db.get_cached_owner('old.com')
        self.assertIsNotNone(cached)
        
        history = self.db.get_search_history()
        self.assertGreater(len(history), 0)
        
        # Nettoyer avec 0 jours (tout supprimer)
        result = self.db.cleanup_old_data(days_old=0)
        self.assertTrue(result)
        
        # Vérifier que les données ont été supprimées
        cached = self.db.get_cached_owner('old.com')
        self.assertIsNone(cached)
        
        history = self.db.get_search_history()
        self.assertEqual(len(history), 0)


@unittest.skipUnless(OWNER_ENGINE_AVAILABLE, "Owner Research Engine not available")
class TestAdvancedOwnerResearchEngine(unittest.TestCase):
    """Tests pour AdvancedOwnerResearchEngine."""
    
    def setUp(self):
        """Configuration avant chaque test."""
        self.temp_dir = tempfile.mkdtemp()
        self.cache_db = os.path.join(self.temp_dir, 'test_cache.db')
        
        # Configuration de test
        self.config = {
            'max_threads': 2,  # Limiter pour les tests
            'request_timeout': 1,
            'rate_limit_delay': 0.1,
            'cache_max_age_hours': 1
        }
        
        self.engine = AdvancedOwnerResearchEngine(
            debug=True,
            cache_db=self.cache_db,
            config=self.config
        )
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        self.engine.close()
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_engine_initialization(self):
        """Test l'initialisation du moteur."""
        self.assertIsNotNone(self.engine.logger)
        self.assertIsNotNone(self.engine.fuzzy_matcher)
        self.assertIsNotNone(self.engine.database)
        self.assertIsNotNone(self.engine.session_id)
        self.assertIn('owner_research_', self.engine.session_id)
    
    def test_clean_domain(self):
        """Test le nettoyage des domaines."""
        # Domaines normaux
        self.assertEqual(self.engine._clean_domain('example.com'), 'example.com')
        self.assertEqual(self.engine._clean_domain('  Example.COM  '), 'example.com')
        
        # URLs
        self.assertEqual(
            self.engine._clean_domain('http://example.com/path'), 
            'example.com'
        )
        self.assertEqual(
            self.engine._clean_domain('https://subdomain.example.com:8080/'), 
            'subdomain.example.com'
        )
        
        # Cas invalides
        self.assertIsNone(self.engine._clean_domain(''))
        self.assertIsNone(self.engine._clean_domain(None))
    
    def test_is_valid_domain(self):
        """Test la validation des domaines."""
        # Domaines valides
        self.assertTrue(self.engine._is_valid_domain('example.com'))
        self.assertTrue(self.engine._is_valid_domain('sub.domain.example.org'))
        self.assertTrue(self.engine._is_valid_domain('test-domain.co.uk'))
        
        # Domaines invalides
        self.assertFalse(self.engine._is_valid_domain(''))
        self.assertFalse(self.engine._is_valid_domain('..'))
        self.assertFalse(self.engine._is_valid_domain('domain..com'))
        self.assertFalse(self.engine._is_valid_domain('-invalid.com'))
        self.assertFalse(self.engine._is_valid_domain('too' + 'o' * 250 + '.com'))
    
    def test_read_domains_file(self):
        """Test la lecture des fichiers de domaines."""
        # Créer un fichier de test
        domains_file = os.path.join(self.temp_dir, 'test_domains.txt')
        with open(domains_file, 'w') as f:
            f.write('example.com\n')
            f.write('# This is a comment\n')
            f.write('test.example.org\n')
            f.write('  spaced.domain.net  \n')
            f.write('invalid..domain\n')
            f.write('https://url.domain.com/path\n')
        
        domains = self.engine._read_domains_file(domains_file)
        
        expected_domains = [
            'example.com',
            'test.example.org',
            'spaced.domain.net',
            'url.domain.com'
        ]
        
        self.assertEqual(len(domains), 4)
        for domain in expected_domains:
            self.assertIn(domain, domains)
    
    def test_read_expected_owners_file_csv(self):
        """Test la lecture du fichier CSV des propriétaires."""
        # Créer un fichier CSV de test
        owners_file = os.path.join(self.temp_dir, 'test_owners.csv')
        with open(owners_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Domain', 'Expected_Owner'])
            writer.writerow(['example.com', 'Example Corporation'])
            writer.writerow(['test.org', 'Test Organization'])
        
        owners = self.engine._read_expected_owners_file(owners_file)
        
        expected_owners = {
            'example.com': 'Example Corporation',
            'test.org': 'Test Organization'
        }
        
        self.assertEqual(owners, expected_owners)
    
    def test_read_expected_owners_file_text(self):
        """Test la lecture du fichier texte des propriétaires."""
        # Créer un fichier texte de test
        owners_file = os.path.join(self.temp_dir, 'test_owners.txt')
        with open(owners_file, 'w') as f:
            f.write('example.com|Example Corporation\n')
            f.write('test.org:Test Organization\n')
            f.write('# Comment line\n')
            f.write('demo.net\tDemo Network\n')
        
        owners = self.engine._read_expected_owners_file(owners_file)
        
        expected_owners = {
            'example.com': 'Example Corporation',
            'test.org': 'Test Organization',
            'demo.net': 'Demo Network'
        }
        
        self.assertEqual(owners, expected_owners)
    
    @patch('owner_research_engine.AdvancedOwnerResearchEngine._query_whois_server')
    def test_perform_whois_lookup(self, mock_whois):
        """Test la recherche WHOIS avec mock."""
        # Configurer le mock
        mock_whois.return_value = TestConfiguration.SAMPLE_WHOIS_DATA
        
        # Effectuer la recherche
        result = self.engine._perform_whois_lookup('example.com')
        
        # Vérifier le résultat
        self.assertIsNotNone(result)
        self.assertIn('raw_whois', result)
        self.assertIn('source', result)
        self.assertEqual(result['source'], 'whois')
        self.assertIn('confidence_score', result)
    
    def test_parse_whois_data(self):
        """Test le parsing des données WHOIS."""
        whois_data = TestConfiguration.SAMPLE_WHOIS_DATA
        
        parsed = self.engine._parse_whois_data(whois_data)
        
        # Vérifier que les champs principaux sont présents
        self.assertIn('owner_name', parsed)
        self.assertIn('registrar', parsed)
        self.assertIn('creation_date', parsed)
        self.assertIn('expiry_date', parsed)
        self.assertIn('emails', parsed)
        
        # Vérifier les valeurs spécifiques du sample
        self.assertIn('ops@iana.org', parsed['emails'])
        self.assertIn('1995-08-14', parsed.get('creation_date', ''))
    
    def test_calculate_whois_confidence(self):
        """Test le calcul du score de confiance WHOIS."""
        # Données complètes
        complete_data = {
            'owner_name': 'Test Corp',
            'registrar': 'Test Registrar',
            'creation_date': '2020-01-01',
            'emails': ['admin@test.com'],
            'phone': '+1-555-0123',
            'address': '123 Test St'
        }
        
        score = self.engine._calculate_whois_confidence(complete_data)
        self.assertGreater(score, 0.8)  # Score élevé pour données complètes
        
        # Données partielles
        partial_data = {
            'owner_name': 'Test Corp'
        }
        
        score = self.engine._calculate_whois_confidence(partial_data)
        self.assertLess(score, 0.5)  # Score plus faible pour données partielles
        
        # Données vides
        empty_data = {}
        score = self.engine._calculate_whois_confidence(empty_data)
        self.assertEqual(score, 0.0)
    
    @patch('owner_research_engine.AdvancedOwnerResearchEngine._perform_whois_lookup')
    def test_process_single_domain(self, mock_whois):
        """Test le traitement d'un seul domaine avec mock."""
        # Configurer le mock
        mock_whois_result = {
            'owner_name': 'Mock Corporation',
            'registrar': 'Mock Registrar',
            'confidence_score': 0.8
        }
        mock_whois.return_value = mock_whois_result
        
        # Traiter le domaine
        result = self.engine._process_single_domain('test.com')
        
        # Vérifier le résultat
        self.assertIn('domain', result)
        self.assertEqual(result['domain'], 'test.com')
        self.assertIn('owner_info', result)
        self.assertIn('processed_at', result)
        self.assertIn('processing_time', result)
        self.assertFalse(result.get('cache_hit', True))  # Première fois, pas de cache
        
        # Vérifier les données du propriétaire
        owner_info = result['owner_info']
        self.assertEqual(owner_info['owner_name'], 'Mock Corporation')
        self.assertEqual(owner_info['confidence_score'], 0.8)
    
    def test_perform_fuzzy_search(self):
        """Test la recherche floue."""
        # Effectuer une recherche floue
        result = self.engine._perform_fuzzy_search(
            'test.com',
            'Microsoft Corporation',
            'Microsoft Corp'
        )
        
        # Vérifier le résultat
        self.assertIn('domain', result)
        self.assertEqual(result['domain'], 'test.com')
        self.assertIn('actual_owner', result)
        self.assertIn('expected_owner', result)
        self.assertIn('match_score', result)
        self.assertIn('match_quality', result)
        self.assertIn('is_match', result)
        self.assertIn('algorithms_scores', result)
        
        # Score élevé attendu pour ces noms similaires
        self.assertGreater(result['match_score'], 0.8)
        self.assertTrue(result['is_match'])
    
    def test_session_id_generation(self):
        """Test la génération d'ID de session."""
        session_id = self.engine._generate_session_id()
        
        self.assertIsInstance(session_id, str)
        self.assertIn('owner_research_', session_id)
        self.assertGreater(len(session_id), 20)  # Assez long pour être unique
    
    def test_metrics_tracking(self):
        """Test le suivi des métriques."""
        initial_metrics = dict(self.engine.metrics)
        
        # Simuler du traitement
        with self.engine.thread_lock:
            self.engine.metrics['domains_processed'] += 1
            self.engine.metrics['cache_hits'] += 1
            self.engine.metrics['fuzzy_searches'] += 1
        
        # Vérifier que les métriques ont été mises à jour
        self.assertEqual(
            self.engine.metrics['domains_processed'], 
            initial_metrics['domains_processed'] + 1
        )
        self.assertEqual(
            self.engine.metrics['cache_hits'], 
            initial_metrics['cache_hits'] + 1
        )


@unittest.skipUnless(SUBLIST3R_ENHANCED_AVAILABLE, "Sublist3r Enhanced not available")
class TestSecurityValidator(unittest.TestCase):
    """Tests pour SecurityValidator."""
    
    def setUp(self):
        """Configuration avant chaque test."""
        self.logger = TestLogger()
        self.validator = SecurityValidator(self.logger)
    
    def test_validate_domain_valid(self):
        """Test la validation de domaines valides."""
        valid_domains = [
            'example.com',
            'subdomain.example.org',
            'test-domain.co.uk',
            'a.b.c.d.example.net'
        ]
        
        for domain in valid_domains:
            is_valid, clean_domain, error = self.validator.validate_domain(domain)
            self.assertTrue(is_valid, "Domain {} should be valid".format(domain))
            self.assertIsNotNone(clean_domain)
            self.assertIsNone(error)
    
    def test_validate_domain_invalid(self):
        """Test la validation de domaines invalides."""
        invalid_domains = [
            '',  # Vide
            'a',  # Trop court
            'domain..com',  # Double point
            '-invalid.com',  # Commence par tiret
            'invalid-.com',  # Finit par tiret
            'domain.com/path',  # Contient un chemin
            'a' * 255,  # Trop long
        ]
        
        for domain in invalid_domains:
            is_valid, clean_domain, error = self.validator.validate_domain(domain)
            self.assertFalse(is_valid, "Domain {} should be invalid".format(domain))
            self.assertIsNotNone(error)
    
    def test_validate_domain_dangerous(self):
        """Test la détection de domaines dangereux."""
        dangerous_domains = [
            'example.com; rm -rf /',
            'example.com`whoami`',
            'example.com$(id)',
            'example.com|cat /etc/passwd'
        ]
        
        for domain in dangerous_domains:
            is_valid, clean_domain, error = self.validator.validate_domain(domain)
            self.assertFalse(is_valid, "Dangerous domain {} should be rejected".format(domain))
            self.assertIn("dangerous", error.lower())
    
    def test_validate_domain_url_cleaning(self):
        """Test le nettoyage des URLs."""
        test_cases = [
            ('http://example.com', 'example.com'),
            ('https://subdomain.example.org/path', 'subdomain.example.org'),
            ('example.com:8080', 'example.com'),
            ('  EXAMPLE.COM  ', 'example.com')
        ]
        
        for input_domain, expected_output in test_cases:
            is_valid, clean_domain, error = self.validator.validate_domain(input_domain)
            self.assertTrue(is_valid)
            self.assertEqual(clean_domain, expected_output)
    
    def test_validate_file_path_valid(self):
        """Test la validation de chemins valides."""
        valid_paths = [
            'test.txt',
            'subdir/test.txt',
            'data/input/domains.txt',
            '/absolute/path/file.txt'
        ]
        
        for path in valid_paths:
            is_valid, clean_path, error = self.validator.validate_file_path(path)
            self.assertTrue(is_valid, "Path {} should be valid".format(path))
            self.assertIsNotNone(clean_path)
            self.assertIsNone(error)
    
    def test_validate_file_path_dangerous(self):
        """Test la détection de chemins dangereux."""
        dangerous_paths = [
            '../../../etc/passwd',
            'file.txt; rm -rf /',
            'test`whoami`.txt',
            'file$(id).txt'
        ]
        
        for path in dangerous_paths:
            is_valid, clean_path, error = self.validator.validate_file_path(path)
            self.assertFalse(is_valid, "Dangerous path {} should be rejected".format(path))
            self.assertIsNotNone(error)
    
    def test_validate_port_list_valid(self):
        """Test la validation de listes de ports valides."""
        valid_port_lists = [
            '80',
            '80,443',
            '22,80,443,8080',
            '1,65535'  # Limites extrêmes
        ]
        
        for ports_str in valid_port_lists:
            is_valid, ports, error = self.validator.validate_port_list(ports_str)
            self.assertTrue(is_valid, "Port list {} should be valid".format(ports_str))
            self.assertIsInstance(ports, list)
            self.assertIsNone(error)
    
    def test_validate_port_list_invalid(self):
        """Test la validation de listes de ports invalides."""
        invalid_port_lists = [
            '0',  # Port 0 invalide
            '65536',  # Port trop élevé
            '80,abc',  # Contient du texte
            'a,b,c',  # Tout texte
            '80; rm -rf /',  # Injection de commande
        ]
        
        for ports_str in invalid_port_lists:
            is_valid, ports, error = self.validator.validate_port_list(ports_str)
            self.assertFalse(is_valid, "Port list {} should be invalid".format(ports_str))
            self.assertIsNotNone(error)
    
    def test_validate_port_list_too_many(self):
        """Test la limitation du nombre de ports."""
        # Créer une liste avec plus de 100 ports
        many_ports = ','.join(str(i) for i in range(1, 102))
        
        is_valid, ports, error = self.validator.validate_port_list(many_ports)
        self.assertFalse(is_valid)
        self.assertIn("too many", error.lower())
    
    def test_security_event_logging(self):
        """Test l'enregistrement des événements de sécurité."""
        # Déclencher un événement de sécurité
        self.validator.validate_domain('dangerous.com; rm -rf /')
        
        # Vérifier que l'événement a été loggé
        error_messages = self.logger.get_messages('ERROR')
        security_events = [msg for msg in error_messages if 'SECURITY_EVENT' in msg['message']]
        
        self.assertGreater(len(security_events), 0)
        self.assertIn('DANGEROUS_PATTERN', security_events[0]['message'])


@unittest.skipUnless(SUBLIST3R_ENHANCED_AVAILABLE, "Sublist3r Enhanced not available")
class TestProgressBar(unittest.TestCase):
    """Tests pour ProgressBar."""
    
    def setUp(self):
        """Configuration avant chaque test."""
        # Capturer stdout pour les tests
        self.original_stdout = sys.stdout
        sys.stdout = StringIO()
    
    def tearDown(self):
        """Restaurer stdout."""
        sys.stdout = self.original_stdout
    
    def test_progress_bar_initialization(self):
        """Test l'initialisation de la barre de progression."""
        progress = ProgressBar(total=100, width=20, prefix="Test")
        
        self.assertEqual(progress.total, 100)
        self.assertEqual(progress.width, 20)
        self.assertEqual(progress.prefix, "Test")
        self.assertEqual(progress.current, 0)
    
    def test_progress_bar_update(self):
        """Test la mise à jour de la barre de progression."""
        progress = ProgressBar(total=10, width=10)
        
        # Mettre à jour avec une valeur absolue
        progress.update(current=5)
        self.assertEqual(progress.current, 5)
        
        # Mettre à jour avec un incrément
        progress.update(increment=2)
        self.assertEqual(progress.current, 7)
        
        # S'assurer qu'on ne dépasse pas le total
        progress.update(increment=10)
        self.assertEqual(progress.current, 10)
    
    def test_progress_bar_finish(self):
        """Test la finalisation de la barre de progression."""
        progress = ProgressBar(total=50)
        progress.update(current=25)
        
        progress.finish()
        self.assertEqual(progress.current, 50)
    
    def test_progress_bar_zero_total(self):
        """Test avec un total de zéro."""
        progress = ProgressBar(total=0)
        progress.update(current=5)  # Ne devrait pas causer d'erreur
        
        # Aucune exception ne doit être levée
        self.assertEqual(progress.current, 0)


@unittest.skipUnless(SUBLIST3R_ENHANCED_AVAILABLE, "Sublist3r Enhanced not available")
class TestFileWriteEnhanced(unittest.TestCase):
    """Tests pour write_file_enhanced."""
    
    def setUp(self):
        """Configuration avant chaque test."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Mock du security validator et logger
        self.mock_validator = Mock()
        self.mock_validator.validate_file_path.return_value = (True, 'test.txt', None)
        
        self.mock_logger = Mock()
        
        # Patcher les globals
        self.patcher1 = patch('sublist3r_enhanced.security_validator', self.mock_validator)
        self.patcher2 = patch('sublist3r_enhanced.logger', self.mock_logger)
        
        self.patcher1.start()
        self.patcher2.start()
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        self.patcher1.stop()
        self.patcher2.stop()
        
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_write_txt_format(self):
        """Test l'écriture au format TXT."""
        output_file = os.path.join(self.temp_dir, 'test.txt')
        subdomains = ['example.com', 'test.example.com', 'demo.example.org']
        
        self.mock_validator.validate_file_path.return_value = (True, output_file, None)
        
        result = write_file_enhanced(output_file, subdomains, 'txt')
        self.assertTrue(result)
        
        # Vérifier le contenu
        with open(output_file, 'r') as f:
            content = f.read()
            for subdomain in subdomains:
                self.assertIn(subdomain, content)
    
    def test_write_csv_format(self):
        """Test l'écriture au format CSV."""
        output_file = os.path.join(self.temp_dir, 'test.csv')
        subdomains = ['example.com', 'test.example.com']
        metadata = {'tool': 'Test Tool', 'timestamp': '2024-01-01T00:00:00'}
        
        self.mock_validator.validate_file_path.return_value = (True, output_file, None)
        
        result = write_file_enhanced(output_file, subdomains, 'csv', metadata)
        self.assertTrue(result)
        
        # Vérifier le contenu CSV
        with open(output_file, 'r') as f:
            content = f.read()
            self.assertIn('Subdomain', content)  # En-tête
            self.assertIn('example.com', content)
            self.assertIn('Test Tool', content)  # Métadonnées
    
    def test_write_json_format(self):
        """Test l'écriture au format JSON."""
        output_file = os.path.join(self.temp_dir, 'test.json')
        subdomains = ['example.com', 'test.example.com']
        metadata = {'tool': 'Test Tool'}
        
        self.mock_validator.validate_file_path.return_value = (True, output_file, None)
        
        result = write_file_enhanced(output_file, subdomains, 'json', metadata)
        self.assertTrue(result)
        
        # Vérifier le contenu JSON
        with open(output_file, 'r') as f:
            data = json.load(f)
            
            self.assertIn('metadata', data)
            self.assertIn('subdomains', data)
            self.assertEqual(data['metadata']['tool'], 'Test Tool')
            self.assertEqual(len(data['subdomains']), 2)
    
    def test_write_xml_format(self):
        """Test l'écriture au format XML."""
        output_file = os.path.join(self.temp_dir, 'test.xml')
        subdomains = ['example.com']
        
        self.mock_validator.validate_file_path.return_value = (True, output_file, None)
        
        result = write_file_enhanced(output_file, subdomains, 'xml')
        self.assertTrue(result)
        
        # Vérifier le contenu XML
        with open(output_file, 'r') as f:
            content = f.read()
            self.assertIn('<?xml version="1.0"', content)
            self.assertIn('<sublist3r_results', content)
            self.assertIn('example.com', content)
    
    def test_write_html_format(self):
        """Test l'écriture au format HTML."""
        output_file = os.path.join(self.temp_dir, 'test.html')
        subdomains = ['example.com']
        
        self.mock_validator.validate_file_path.return_value = (True, output_file, None)
        
        result = write_file_enhanced(output_file, subdomains, 'html')
        self.assertTrue(result)
        
        # Vérifier le contenu HTML
        with open(output_file, 'r') as f:
            content = f.read()
            self.assertIn('<!DOCTYPE html>', content)
            self.assertIn('Sublist3r Enhanced Results', content)
            self.assertIn('example.com', content)
    
    def test_invalid_file_path(self):
        """Test avec un chemin de fichier invalide."""
        self.mock_validator.validate_file_path.return_value = (False, None, "Invalid path")
        
        result = write_file_enhanced('invalid/path', ['example.com'], 'txt')
        self.assertFalse(result)
    
    def test_empty_subdomains(self):
        """Test avec une liste vide de sous-domaines."""
        output_file = os.path.join(self.temp_dir, 'empty.txt')
        self.mock_validator.validate_file_path.return_value = (True, output_file, None)
        
        result = write_file_enhanced(output_file, [], 'txt')
        self.assertFalse(result)
    
    def test_unsupported_format(self):
        """Test avec un format non supporté."""
        output_file = os.path.join(self.temp_dir, 'test.xyz')
        self.mock_validator.validate_file_path.return_value = (True, output_file, None)
        
        result = write_file_enhanced(output_file, ['example.com'], 'xyz')
        self.assertFalse(result)


class TestIntegration(unittest.TestCase):
    """Tests d'intégration multi-composants."""
    
    @classmethod
    def setUpClass(cls):
        """Configuration une seule fois pour tous les tests d'intégration."""
        TestConfiguration.setup()
    
    @classmethod
    def tearDownClass(cls):
        """Nettoyage après tous les tests d'intégration."""
        TestConfiguration.teardown()
    
    @unittest.skipUnless(OWNER_ENGINE_AVAILABLE, "Owner Research Engine not available")
    def test_full_owner_research_workflow(self):
        """Test du workflow complet de recherche de propriétaires."""
        # Configuration
        config = {
            'max_threads': 2,
            'request_timeout': 1,
            'rate_limit_delay': 0.1
        }
        
        cache_db = os.path.join(TestConfiguration.CACHE_DIR, 'integration_test.db')
        
        # Créer le moteur
        engine = AdvancedOwnerResearchEngine(
            debug=True,
            cache_db=cache_db,
            config=config
        )
        
        try:
            # Mock des lookups WHOIS
            with patch.object(engine, '_perform_whois_lookup') as mock_whois:
                mock_whois.return_value = {
                    'owner_name': 'Test Corporation',
                    'registrar': 'Test Registrar',
                    'emails': ['admin@test.com'],
                    'confidence_score': 0.8
                }
                
                # Effectuer la recherche
                results = engine.research_owner_from_file(
                    TestConfiguration.TEST_DOMAINS_FILE,
                    TestConfiguration.TEST_OWNERS_FILE,
                    TestConfiguration.TEST_OUTPUT_FILE,
                    'json'
                )
                
                # Vérifier les résultats
                self.assertIsInstance(results, dict)
                self.assertNotIn('error', results)
                self.assertIn('processed_domains', results)
                self.assertIn('fuzzy_matches', results)
                self.assertIn('statistics', results)
                
                # Vérifier que le fichier de sortie a été créé
                self.assertTrue(os.path.exists(TestConfiguration.TEST_OUTPUT_FILE))
                
                # Vérifier le contenu du fichier JSON
                with open(TestConfiguration.TEST_OUTPUT_FILE, 'r') as f:
                    output_data = json.load(f)
                    self.assertIn('processed_domains', output_data)
                    self.assertGreater(len(output_data['processed_domains']), 0)
        
        finally:
            engine.close()
    
    @unittest.skipUnless(OWNER_ENGINE_AVAILABLE, "Owner Research Engine not available")
    def test_fuzzy_matching_integration(self):
        """Test l'intégration du matching flou avec la base de données."""
        # Créer les composants
        logger = TestLogger()
        fuzzy_matcher = FuzzyMatcher(logger)
        
        db_path = os.path.join(TestConfiguration.CACHE_DIR, 'fuzzy_test.db')
        database = OwnerDatabase(db_path, logger)
        
        try:
            # Test de matching avec différents niveaux de similarité
            test_cases = [
                ('Microsoft Corporation', 'Microsoft Corp', 'high'),
                ('Apple Inc', 'Apple Incorporated', 'medium'),
                ('Google LLC', 'Facebook Inc', 'low')
            ]
            
            for actual, expected, expected_level in test_cases:
                # Effectuer le matching
                result = fuzzy_matcher.compute_similarity(actual, expected)
                
                # Stocker dans la base de données
                success = database.store_fuzzy_search(actual, expected, result)
                self.assertTrue(success)
                
                # Vérifier le niveau de score
                if expected_level == 'high':
                    self.assertGreater(result['global_score'], 0.8)
                elif expected_level == 'medium':
                    self.assertGreater(result['global_score'], 0.5)
                # Pour 'low', pas de vérification spécifique
            
            # Récupérer l'historique
            history = database.get_search_history()
            self.assertEqual(len(history), 3)
            
            # Vérifier que toutes les recherches sont présentes
            search_queries = [h['search_query'] for h in history]
            self.assertIn('Microsoft Corporation', search_queries)
            self.assertIn('Apple Inc', search_queries)
            self.assertIn('Google LLC', search_queries)
        
        finally:
            database.close()
    
    def test_cache_performance(self):
        """Test des performances du cache."""
        if not OWNER_ENGINE_AVAILABLE:
            self.skipTest("Owner Research Engine not available")
        
        db_path = os.path.join(TestConfiguration.CACHE_DIR, 'performance_test.db')
        database = OwnerDatabase(db_path, TestLogger())
        
        try:
            # Mesurer le temps d'insertion
            start_time = time.time()
            
            for i in range(100):
                owner_data = {
                    'owner_name': 'Test Corporation {}'.format(i),
                    'registrar': 'Test Registrar',
                    'confidence_score': 0.5 + (i % 50) / 100.0
                }
                database.cache_owner_info('test{}.com'.format(i), owner_data)
            
            insert_time = time.time() - start_time
            
            # Mesurer le temps de récupération
            start_time = time.time()
            
            for i in range(100):
                cached = database.get_cached_owner('test{}.com'.format(i))
                self.assertIsNotNone(cached)
            
            retrieval_time = time.time() - start_time
            
            # Vérifier que les opérations sont raisonnablement rapides
            self.assertLess(insert_time, 5.0)  # Moins de 5 secondes pour 100 insertions
            self.assertLess(retrieval_time, 2.0)  # Moins de 2 secondes pour 100 récupérations
            
            print("Cache performance: Insert={:.2f}s, Retrieval={:.2f}s".format(
                insert_time, retrieval_time))
        
        finally:
            database.close()


class TestPerformance(unittest.TestCase):
    """Tests de performance et stress."""
    
    @unittest.skipUnless(OWNER_ENGINE_AVAILABLE, "Owner Research Engine not available")
    def test_fuzzy_matcher_performance(self):
        """Test des performances du FuzzyMatcher."""
        logger = TestLogger()
        matcher = FuzzyMatcher(logger)
        
        # Test avec un grand nombre de comparaisons
        test_strings = [
            'Microsoft Corporation',
            'Apple Inc',
            'Google LLC',
            'Amazon Web Services',
            'Facebook Inc',
            'Oracle Corporation',
            'IBM Corporation',
            'Intel Corporation'
        ]
        
        start_time = time.time()
        
        # Effectuer toutes les comparaisons possibles
        comparisons = 0
        for i, str1 in enumerate(test_strings):
            for str2 in test_strings[i+1:]:
                result = matcher.compute_similarity(str1, str2)
                self.assertIn('global_score', result)
                comparisons += 1
        
        elapsed_time = time.time() - start_time
        
        # Vérifier que les performances sont acceptables
        comparisons_per_second = comparisons / elapsed_time
        self.assertGreater(comparisons_per_second, 10)  # Au moins 10 comparaisons/sec
        
        print("Fuzzy matching performance: {:.1f} comparisons/second".format(comparisons_per_second))
    
    @unittest.skipUnless(OWNER_ENGINE_AVAILABLE, "Owner Research Engine not available")
    def test_database_concurrent_access(self):
        """Test l'accès concurrent à la base de données."""
        db_path = os.path.join(tempfile.gettempdir(), 'concurrent_test.db')
        
        # Fonction pour worker thread
        def database_worker(worker_id, results):
            try:
                database = OwnerDatabase(db_path, TestLogger())
                
                # Effectuer des opérations
                for i in range(10):
                    owner_data = {
                        'owner_name': 'Worker {} Corp {}'.format(worker_id, i),
                        'confidence_score': 0.5
                    }
                    
                    domain = 'worker{}-test{}.com'.format(worker_id, i)
                    success = database.cache_owner_info(domain, owner_data)
                    
                    if success:
                        # Essayer de récupérer immédiatement
                        cached = database.get_cached_owner(domain)
                        if cached:
                            results[worker_id] = results.get(worker_id, 0) + 1
                
                database.close()
                
            except Exception as e:
                print("Worker {} failed: {}".format(worker_id, e))
        
        # Lancer plusieurs threads
        threads = []
        results = {}
        
        for worker_id in range(5):
            thread = threading.Thread(target=database_worker, args=(worker_id, results))
            threads.append(thread)
            thread.start()
        
        # Attendre que tous les threads se terminent
        for thread in threads:
            thread.join(timeout=10)  # Timeout de sécurité
        
        # Vérifier que tous les workers ont réussi au moins quelques opérations
        self.assertEqual(len(results), 5)
        for worker_id, count in results.items():
            self.assertGreater(count, 5, "Worker {} didn't complete enough operations".format(worker_id))
        
        # Nettoyer
        try:
            os.remove(db_path)
        except:
            pass


class TestSecurity(unittest.TestCase):
    """Tests de sécurité."""
    
    @unittest.skipUnless(SUBLIST3R_ENHANCED_AVAILABLE, "Sublist3r Enhanced not available")
    def test_injection_prevention(self):
        """Test la prévention des injections."""
        logger = TestLogger()
        validator = SecurityValidator(logger)
        
        # Tests d'injection de commandes
        malicious_inputs = [
            'example.com; rm -rf /',
            'example.com`whoami`',
            'example.com$(id)',
            'example.com|cat /etc/passwd',
            'example.com&& echo pwned',
            'example.com || echo hacked'
        ]
        
        for malicious_input in malicious_inputs:
            is_valid, clean_domain, error = validator.validate_domain(malicious_input)
            self.assertFalse(is_valid, "Malicious input should be rejected: {}".format(malicious_input))
            self.assertIsNotNone(error)
            
            # Vérifier que l'événement de sécurité a été loggé
            security_logs = [msg for msg in logger.get_messages() if 'SECURITY_EVENT' in msg.get('message', '')]
            self.assertGreater(len(security_logs), 0)
    
    @unittest.skipUnless(SUBLIST3R_ENHANCED_AVAILABLE, "Sublist3r Enhanced not available")
    def test_path_traversal_prevention(self):
        """Test la prévention du path traversal."""
        logger = TestLogger()
        validator = SecurityValidator(logger)
        
        # Tests de path traversal
        malicious_paths = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            '/etc/passwd',
            '\\windows\\system32\\config\\sam',
            'file.txt/../../../etc/passwd'
        ]
        
        for malicious_path in malicious_paths:
            is_valid, clean_path, error = validator.validate_file_path(malicious_path)
            self.assertFalse(is_valid, "Malicious path should be rejected: {}".format(malicious_path))
            self.assertIsNotNone(error)
    
    def test_input_length_limits(self):
        """Test les limites de longueur des entrées."""
        if not SUBLIST3R_ENHANCED_AVAILABLE:
            self.skipTest("Sublist3r Enhanced not available")
        
        logger = TestLogger()
        validator = SecurityValidator(logger)
        
        # Test avec un domaine très long
        very_long_domain = 'a' * 300 + '.com'
        is_valid, clean_domain, error = validator.validate_domain(very_long_domain)
        self.assertFalse(is_valid)
        self.assertIn('too long', error.lower())
        
        # Test avec trop de ports
        too_many_ports = ','.join(str(i) for i in range(1, 200))
        is_valid, ports, error = validator.validate_port_list(too_many_ports)
        self.assertFalse(is_valid)
        self.assertIn('too many', error.lower())


class TestReports:
    """Génération de rapports de tests."""
    
    @staticmethod
    def generate_test_report(test_results):
        """Génère un rapport de tests détaillé."""
        try:
            report = {
                'test_session': {
                    'timestamp': datetime.now().isoformat(),
                    'python_version': sys.version,
                    'platform': sys.platform
                },
                'test_results': test_results,
                'summary': {
                    'total_tests': len(test_results),
                    'passed': len([r for r in test_results if r.get('status') == 'passed']),
                    'failed': len([r for r in test_results if r.get('status') == 'failed']),
                    'skipped': len([r for r in test_results if r.get('status') == 'skipped'])
                }
            }
            
            # Calculer le taux de réussite
            if report['summary']['total_tests'] > 0:
                report['summary']['success_rate'] = (
                    report['summary']['passed'] / report['summary']['total_tests']
                ) * 100
            
            return report
            
        except Exception as e:
            return {'error': 'Failed to generate report: {}'.format(str(e))}
    
    @staticmethod
    def save_report(report, output_file):
        """Sauvegarde le rapport au format JSON."""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            return True
        except Exception as e:
            print("Failed to save report: {}".format(e))
            return False


def create_test_suite():
    """Crée la suite de tests complète."""
    suite = unittest.TestSuite()
    
    # Tests unitaires de base
    if OWNER_ENGINE_AVAILABLE:
        suite.addTest(unittest.makeSuite(TestAdvancedOwnerLogger))
        suite.addTest(unittest.makeSuite(TestFuzzyMatcher))
        suite.addTest(unittest.makeSuite(TestOwnerDatabase))
        suite.addTest(unittest.makeSuite(TestAdvancedOwnerResearchEngine))
    
    if SUBLIST3R_ENHANCED_AVAILABLE:
        suite.addTest(unittest.makeSuite(TestSecurityValidator))
        suite.addTest(unittest.makeSuite(TestProgressBar))
        suite.addTest(unittest.makeSuite(TestFileWriteEnhanced))
    
    # Tests d'intégration
    suite.addTest(unittest.makeSuite(TestIntegration))
    
    # Tests de performance
    suite.addTest(unittest.makeSuite(TestPerformance))
    
    # Tests de sécurité
    suite.addTest(unittest.makeSuite(TestSecurity))
    
    return suite


def run_tests_with_coverage():
    """Exécute les tests avec mesure de couverture."""
    try:
        # Essayer d'importer coverage
        import coverage
        
        # Initialiser la mesure de couverture
        cov = coverage.Coverage()
        cov.start()
        
        # Exécuter les tests
        suite = create_test_suite()
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        # Arrêter la mesure et générer le rapport
        cov.stop()
        cov.save()
        
        print("\n" + "="*50)
        print("COVERAGE REPORT")
        print("="*50)
        cov.report()
        
        return result
        
    except ImportError:
        print("Coverage module not available. Running tests without coverage measurement.")
        print("Install with: pip install coverage")
        
        # Exécuter les tests sans coverage
        suite = create_test_suite()
        runner = unittest.TextTestRunner(verbosity=2)
        return runner.run(suite)


def main():
    """Fonction principale pour exécuter les tests."""
    try:
        print("="*60)
        print("SUBLIST3R ENHANCED - SUITE DE TESTS COMPLETE v2.1")
        print("="*60)
        print("Tests unitaires, intégration, performance et sécurité")
        print()
        
        # Vérifier les dépendances
        print("Vérification des modules disponibles:")
        print("- Owner Research Engine: {}".format("✓" if OWNER_ENGINE_AVAILABLE else "✗"))
        print("- Sublist3r Enhanced: {}".format("✓" if SUBLIST3R_ENHANCED_AVAILABLE else "✗"))
        print()
        
        if not (OWNER_ENGINE_AVAILABLE or SUBLIST3R_ENHANCED_AVAILABLE):
            print("ERREUR: Aucun module de test disponible!")
            return 1
        
        # Configuration de l'environnement de test
        print("Configuration de l'environnement de test...")
        TestConfiguration.setup()
        
        try:
            # Exécuter les tests
            print("Exécution des tests...")
            result = run_tests_with_coverage()
            
            # Générer le rapport
            print("\n" + "="*50)
            print("RESUME DES TESTS")
            print("="*50)
            print("Tests exécutés: {}".format(result.testsRun))
            print("Succès: {}".format(result.testsRun - len(result.failures) - len(result.errors)))
            print("Échecs: {}".format(len(result.failures)))
            print("Erreurs: {}".format(len(result.errors)))
            
            if result.skipped:
                print("Ignorés: {}".format(len(result.skipped)))
            
            # Calculer le taux de réussite
            if result.testsRun > 0:
                success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / 
                              result.testsRun) * 100
                print("Taux de réussite: {:.1f}%".format(success_rate))
            
            # Afficher les détails des échecs
            if result.failures:
                print("\n" + "="*30)
                print("ECHECS DÉTAILLÉS")
                print("="*30)
                for test, traceback in result.failures:
                    print("ECHEC: {}".format(test))
                    print(traceback)
                    print("-" * 30)
            
            # Afficher les détails des erreurs
            if result.errors:
                print("\n" + "="*30)
                print("ERREURS DÉTAILLÉES")
                print("="*30)
                for test, traceback in result.errors:
                    print("ERREUR: {}".format(test))
                    print(traceback)
                    print("-" * 30)
            
            print("\n" + "="*60)
            
            # Code de retour basé sur le résultat
            if result.failures or result.errors:
                print("❌ CERTAINS TESTS ONT ÉCHOUÉ")
                return 1
            else:
                print("✅ TOUS LES TESTS ONT RÉUSSI")
                return 0
                
        finally:
            # Nettoyer l'environnement de test
            TestConfiguration.teardown()
    
    except KeyboardInterrupt:
        print("\n❌ Tests interrompus par l'utilisateur")
        return 1
    except Exception as e:
        print("❌ ERREUR CRITIQUE: {}".format(str(e)))
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())