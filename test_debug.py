#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de test pour débugger et vérifier le fonctionnement.
Utilisable directement depuis VS Code ou ligne de commande.
"""

import sys
import os

# Ajouter le répertoire courant au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_sublist3r_enhanced():
    """Test du Sublist3r Enhanced."""
    print("🧪 Test Sublist3r Enhanced...")
    try:
        from sublist3r_enhanced import EnhancedLogger, SecurityValidator
        
        logger = EnhancedLogger('TestDebug', debug=True)
        logger.info("Sublist3r Enhanced importé avec succès!")
        
        validator = SecurityValidator(logger)
        result = validator.validate_domain("example.com")
        logger.success(f"Validation domaine: {result[0]}")
        
        return True
    except Exception as e:
        print(f"❌ Erreur Sublist3r Enhanced: {e}")
        return False

def test_owner_research():
    """Test du moteur de recherche de propriétaires."""
    print("🔍 Test Owner Research Engine...")
    try:
        from owner_research_engine import AdvancedOwnerResearchEngine
        
        engine = AdvancedOwnerResearchEngine(debug=True)
        print("✅ Owner Research Engine initialisé!")
        
        # Test rapide de fuzzy matching
        result = engine._perform_fuzzy_search("test.com", "Test Corp", "test corporation")
        print(f"✅ Fuzzy match score: {result['match_score']:.3f}")
        
        engine.close()
        return True
    except Exception as e:
        print(f"❌ Erreur Owner Research: {e}")
        return False

def test_original_sublist3r():
    """Test du Sublist3r original."""
    print("📋 Test Sublist3r Original...")
    try:
        # Simulation d'import du sublist3r original
        sublist_path = os.path.join(os.path.dirname(__file__), 'sublist3r.py')
        if os.path.exists(sublist_path):
            print("✅ Sublist3r original trouvé!")
            print("💡 Usage: python3 sublist3r.py -d example.com")
            return True
        else:
            print("❌ Sublist3r original non trouvé")
            return False
    except Exception as e:
        print(f"❌ Erreur Sublist3r original: {e}")
        return False

def main():
    """Fonction principale de test."""
    print("🚀 TESTS DE DÉBUGGAGE - SUBLIST3R SYSTEM")
    print("=" * 50)
    
    print(f"📁 Répertoire de travail: {os.getcwd()}")
    print(f"🐍 Version Python: {sys.version}")
    print()
    
    # Tests des composants
    tests = [
        ("Sublist3r Enhanced", test_sublist3r_enhanced),
        ("Owner Research Engine", test_owner_research), 
        ("Sublist3r Original", test_original_sublist3r)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"❌ ERREUR dans {test_name}: {e}")
            results.append((test_name, False))
    
    # Résumé des résultats
    print("\n" + "="*60)
    print("📊 RÉSUMÉ DES TESTS:")
    
    all_passed = True
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"   {status} {test_name}")
        if not success:
            all_passed = False
    
    print("\n" + "="*60)
    if all_passed:
        print("🎉 TOUS LES TESTS SONT PASSÉS!")
        print("💡 Vous pouvez maintenant utiliser VS Code pour débugger:")
        print("   1. Ouvrez VS Code")
        print("   2. Allez dans Run > Start Debugging (F5)")
        print("   3. Choisissez 'Sublist3r Enhanced - Debug Mode'")
    else:
        print("⚠️  CERTAINS TESTS ONT ÉCHOUÉ!")
        print("🔧 Vérifiez les erreurs ci-dessus et corrigez-les")
    
    print("\n🏁 Tests terminés!")

if __name__ == "__main__":
    main()