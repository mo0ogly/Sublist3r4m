#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de diagnostic et correction des erreurs de résolution de variables.

Corrige les erreurs communes de type:
- variable $file not resolved
- undefined variable references
- shell expansion issues

Author: Enhanced Security Team
"""

import os
import sys
import re
import glob
from pathlib import Path

def find_variable_references(file_path):
    """Trouve toutes les références de variables dans un fichier."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        # Patterns pour différents types de variables
        patterns = [
            r'\$\{?([a-zA-Z_][a-zA-Z0-9_]*)\}?',  # $var ou ${var}
            r'\$\([^)]+\)',  # $(command)
            r'%([^%]+)%',    # %var% (Windows style)
        ]
        
        variables = set()
        for pattern in patterns:
            matches = re.findall(pattern, content)
            if isinstance(matches[0] if matches else None, str):
                variables.update(matches)
        
        return list(variables)
    except Exception as e:
        print(f"❌ Erreur lecture {file_path}: {e}")
        return []

def check_python_files():
    """Vérifie les fichiers Python pour des erreurs de variables."""
    python_files = glob.glob("**/*.py", recursive=True)
    issues = []
    
    for py_file in python_files:
        try:
            with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Recherche des erreurs communes
            if '$file' in content:
                issues.append(f"⚠️  {py_file}: contient '$file' - possible erreur de variable")
            
            if re.search(r'\$[a-zA-Z_][a-zA-Z0-9_]*(?!\()', content):
                variables = re.findall(r'\$([a-zA-Z_][a-zA-Z0-9_]*)', content)
                issues.append(f"⚠️  {py_file}: variables shell détectées: {variables}")
        
        except Exception as e:
            issues.append(f"❌ {py_file}: erreur de lecture - {e}")
    
    return issues

def fix_common_issues():
    """Corrige les erreurs communes de variables."""
    fixes_applied = []
    
    # Recherche des fichiers avec des erreurs de variables courantes
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith(('.py', '.sh', '.bash')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    original_content = content
                    
                    # Corrections communes
                    if '$file not resolved' in content.lower():
                        # Si c'est dans un commentaire ou string, on l'ignore
                        continue
                    
                    # Remplace $file par une référence correcte si contexte le permet
                    if '$file' in content and file.endswith('.py'):
                        content = content.replace('$file', '"$file"')  # Quote la variable
                        fixes_applied.append(f"✅ {file_path}: ajout de quotes autour de $file")
                    
                    # Écrit les corrections si nécessaire
                    if content != original_content:
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                
                except Exception as e:
                    print(f"❌ Erreur traitement {file_path}: {e}")
    
    return fixes_applied

def main():
    """Fonction principale de diagnostic."""
    print("🔍 DIAGNOSTIC DES VARIABLES NON RÉSOLUES")
    print("=" * 50)
    
    # 1. Vérification des fichiers Python
    print("\n📄 Vérification des fichiers Python...")
    python_issues = check_python_files()
    
    if python_issues:
        print("⚠️  Problèmes détectés:")
        for issue in python_issues[:10]:  # Limite à 10 pour éviter le spam
            print(f"   {issue}")
        if len(python_issues) > 10:
            print(f"   ... et {len(python_issues) - 10} autres problèmes")
    else:
        print("✅ Aucun problème de variable détecté dans les fichiers Python")
    
    # 2. Vérification des variables d'environnement
    print("\n🌍 Variables d'environnement avec 'file':")
    for key, value in os.environ.items():
        if 'file' in key.lower():
            print(f"   {key}={value}")
    
    # 3. Recherche de fichiers avec des patterns suspects
    print("\n🔍 Recherche de patterns suspects...")
    suspicious_files = []
    
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file.endswith(('.py', '.sh', '.bash', '.txt')):
                file_path = os.path.join(root, file)
                variables = find_variable_references(file_path)
                if 'file' in variables:
                    suspicious_files.append((file_path, variables))
    
    if suspicious_files:
        print("⚠️  Fichiers avec références à 'file':")
        for file_path, variables in suspicious_files:
            print(f"   {file_path}: {variables}")
    else:
        print("✅ Aucune référence suspecte à 'file' trouvée")
    
    # 4. Application des corrections
    print("\n🔧 Application des corrections automatiques...")
    fixes = fix_common_issues()
    
    if fixes:
        print("✅ Corrections appliquées:")
        for fix in fixes:
            print(f"   {fix}")
    else:
        print("ℹ️  Aucune correction automatique nécessaire")
    
    # 5. Recommandations
    print("\n💡 RECOMMANDATIONS:")
    print("   1. Vérifiez que toutes les variables shell sont correctement définies")
    print("   2. Utilisez des quotes autour des chemins de fichiers")
    print("   3. Préférez os.path.join() aux concaténations de chemins")
    print("   4. Testez vos scripts avant utilisation")
    
    print("\n✨ Diagnostic terminé!")

if __name__ == "__main__":
    main()