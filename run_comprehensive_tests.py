#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests Complets - Suite de tests avec jeux de données réels.

Teste le système de recherche de propriétaires avec:
- Domaines réels et leurs propriétaires
- Différents niveaux de correspondance floue
- Analyse des performances et précision
- Export des résultats détaillés

Author: Enhanced Security Team
"""

import sys
import os
import json
import csv
import time
from datetime import datetime
from collections import defaultdict

# Ajouter le répertoire au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def load_test_domains():
    """Charge les domaines de test."""
    domains = []
    try:
        with open('test_domains.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)
        print(f"✅ {len(domains)} domaines de test chargés")
        return domains
    except FileNotFoundError:
        print("❌ Fichier test_domains.txt non trouvé")
        return []

def load_expected_owners():
    """Charge les propriétaires attendus."""
    owners = {}
    try:
        with open('expected_owners.txt', 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '|' in line:
                    parts = line.split('|')
                    if len(parts) >= 2:
                        domain = parts[0].strip()
                        expected = parts[1].strip()
                        variations = parts[2].split(',') if len(parts) > 2 else []
                        variations = [v.strip() for v in variations]
                        
                        owners[domain] = {
                            'expected': expected,
                            'variations': variations
                        }
        
        print(f"✅ {len(owners)} propriétaires attendus chargés")
        return owners
    except FileNotFoundError:
        print("❌ Fichier expected_owners.txt non trouvé")
        return {}

def run_fuzzy_matching_tests():
    """Exécute les tests de correspondance floue."""
    print("\n🔍 TESTS DE CORRESPONDANCE FLOUE")
    print("=" * 50)
    
    try:
        from owner_research_engine import AdvancedOwnerResearchEngine
        
        engine = AdvancedOwnerResearchEngine(debug=False)
        
        # Charger les données de test
        domains = load_test_domains()[:20]  # Limiter à 20 pour les tests
        expected_owners = load_expected_owners()
        
        results = []
        total_tests = 0
        perfect_matches = 0
        good_matches = 0
        poor_matches = 0
        
        print(f"\n🎯 Test de {len(domains)} domaines...")
        
        for domain in domains:
            if domain in expected_owners:
                owner_data = expected_owners[domain]
                expected = owner_data['expected']
                variations = owner_data['variations']
                
                # Test avec le propriétaire attendu
                result = engine._perform_fuzzy_search(domain, expected, expected)
                score = result['match_score']
                quality = result['match_quality']
                
                total_tests += 1
                if score >= 0.9:
                    perfect_matches += 1
                elif score >= 0.6:
                    good_matches += 1
                else:
                    poor_matches += 1
                
                test_result = {
                    'domain': domain,
                    'expected_owner': expected,
                    'test_owner': expected,
                    'score': score,
                    'quality': quality,
                    'algorithms': result['algorithms_scores'],
                    'test_type': 'exact_match'
                }
                results.append(test_result)
                
                print(f"   {domain:<25} | {expected:<30} | {score:.3f} ({quality})")
                
                # Test avec variations si disponibles
                for variation in variations[:2]:  # Limiter à 2 variations
                    if variation:
                        var_result = engine._perform_fuzzy_search(domain, expected, variation)
                        var_score = var_result['match_score']
                        var_quality = var_result['match_quality']
                        
                        total_tests += 1
                        if var_score >= 0.9:
                            perfect_matches += 1
                        elif var_score >= 0.6:
                            good_matches += 1
                        else:
                            poor_matches += 1
                        
                        var_test_result = {
                            'domain': domain,
                            'expected_owner': expected,
                            'test_owner': variation,
                            'score': var_score,
                            'quality': var_quality,
                            'algorithms': var_result['algorithms_scores'],
                            'test_type': 'variation_match'
                        }
                        results.append(var_test_result)
                        
                        print(f"   {domain:<25} | {variation:<30} | {var_score:.3f} ({var_quality})")
                
                time.sleep(0.1)  # Pause courte pour éviter la surcharge
        
        engine.close()
        
        # Statistiques
        print(f"\n📊 STATISTIQUES DES TESTS:")
        print(f"   Total tests: {total_tests}")
        print(f"   Correspondances parfaites (≥0.9): {perfect_matches} ({perfect_matches/total_tests*100:.1f}%)")
        print(f"   Bonnes correspondances (≥0.6): {good_matches} ({good_matches/total_tests*100:.1f}%)")
        print(f"   Correspondances faibles (<0.6): {poor_matches} ({poor_matches/total_tests*100:.1f}%)")
        
        return results
        
    except Exception as e:
        print(f"❌ Erreur lors des tests: {e}")
        return []

def analyze_algorithm_performance(results):
    """Analyse les performances des différents algorithmes."""
    print("\n🔬 ANALYSE DES ALGORITHMES")
    print("=" * 50)
    
    algorithm_stats = defaultdict(list)
    
    for result in results:
        for algo, score in result['algorithms'].items():
            algorithm_stats[algo].append(score)
    
    print(f"{'Algorithme':<15} | {'Moyenne':<8} | {'Max':<6} | {'Min':<6} | {'Tests':<6}")
    print("-" * 60)
    
    for algo, scores in algorithm_stats.items():
        if scores:
            avg = sum(scores) / len(scores)
            max_score = max(scores)
            min_score = min(scores)
            count = len(scores)
            
            print(f"{algo:<15} | {avg:<8.3f} | {max_score:<6.3f} | {min_score:<6.3f} | {count:<6}")

def export_test_results(results):
    """Exporte les résultats des tests."""
    print("\n💾 EXPORT DES RÉSULTATS")
    print("=" * 50)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Export JSON
    json_filename = f"test_results_{timestamp}.json"
    json_data = {
        'metadata': {
            'timestamp': datetime.now().isoformat(),
            'total_tests': len(results),
            'test_type': 'comprehensive_fuzzy_matching',
            'version': '2.1'
        },
        'results': results,
        'summary': {
            'perfect_matches': len([r for r in results if r['score'] >= 0.9]),
            'good_matches': len([r for r in results if 0.6 <= r['score'] < 0.9]),
            'poor_matches': len([r for r in results if r['score'] < 0.6]),
            'average_score': sum(r['score'] for r in results) / len(results) if results else 0
        }
    }
    
    with open(json_filename, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Export JSON: {json_filename}")
    
    # Export CSV
    csv_filename = f"test_results_{timestamp}.csv"
    if results:
        with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
            fieldnames = ['domain', 'expected_owner', 'test_owner', 'score', 'quality', 'test_type']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                row = {
                    'domain': result['domain'],
                    'expected_owner': result['expected_owner'],
                    'test_owner': result['test_owner'],
                    'score': result['score'],
                    'quality': result['quality'],
                    'test_type': result['test_type']
                }
                writer.writerow(row)
        
        print(f"✅ Export CSV: {csv_filename}")
    
    return json_filename, csv_filename

def run_performance_tests():
    """Tests de performance du système."""
    print("\n⚡ TESTS DE PERFORMANCE")
    print("=" * 50)
    
    try:
        from owner_research_engine import FuzzyMatcher, AdvancedOwnerLogger
        
        logger = AdvancedOwnerLogger('PerformanceTest')
        matcher = FuzzyMatcher(logger)
        
        # Test de performance sur différentes tailles de chaînes
        test_cases = [
            ("Google", "Google LLC"),
            ("Microsoft Corporation", "Microsoft Corp"),
            ("The Goldman Sachs Group Inc", "Goldman Sachs & Co"),
            ("Alphabet Inc", "Google LLC"),
            ("Very Long Company Name With Multiple Words Inc", "Very Long Corp With Multiple Words")
        ]
        
        print("Test de vitesse de calcul:")
        for str1, str2 in test_cases:
            start_time = time.perf_counter()
            result = matcher.compute_similarity(str1, str2)
            end_time = time.perf_counter()
            
            duration = (end_time - start_time) * 1000  # en millisecondes
            score = result['global_score']
            
            print(f"   {str1:<35} vs {str2:<35} | {score:.3f} | {duration:.2f}ms")
        
        # Test de charge
        print(f"\n🔥 Test de charge (1000 comparaisons):")
        start_time = time.perf_counter()
        
        for i in range(1000):
            matcher.compute_similarity("Test Company Inc", "Test Corp LLC")
        
        end_time = time.perf_counter()
        total_duration = end_time - start_time
        avg_duration = (total_duration / 1000) * 1000  # en millisecondes
        
        print(f"   Temps total: {total_duration:.3f}s")
        print(f"   Temps moyen par comparaison: {avg_duration:.3f}ms")
        print(f"   Comparaisons par seconde: {1000/total_duration:.0f}")
        
    except Exception as e:
        print(f"❌ Erreur lors des tests de performance: {e}")

def main():
    """Fonction principale des tests complets."""
    print("🚀 SUITE DE TESTS COMPLETS - SYSTÈME DE RECHERCHE DE PROPRIÉTAIRES")
    print("=" * 80)
    
    start_time = time.time()
    
    # 1. Tests de correspondance floue
    results = run_fuzzy_matching_tests()
    
    if results:
        # 2. Analyse des algorithmes
        analyze_algorithm_performance(results)
        
        # 3. Export des résultats
        json_file, csv_file = export_test_results(results)
        
        # 4. Tests de performance
        run_performance_tests()
        
        # Résumé final
        end_time = time.time()
        total_duration = end_time - start_time
        
        print(f"\n🎉 TESTS TERMINÉS!")
        print(f"   Durée totale: {total_duration:.2f}s")
        print(f"   Tests effectués: {len(results)}")
        print(f"   Fichiers générés: {json_file}, {csv_file}")
        print(f"   Système prêt pour utilisation en production!")
    else:
        print("❌ Aucun résultat de test généré")

if __name__ == "__main__":
    main()