#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SubBrute Advanced GUI Launcher v2.1
Lanceur avancé avec toutes les fonctionnalités demandées

Fonctionnalités complètes:
- Interface à onglets moderne avec configuration, résultats, statistiques et logs
- Recherche automatique de propriétaires de domaines via WHOIS
- Extraction d'adresses email depuis les DNS records
- Export sophistiqué en CSV, JSON, XML et HTML
- Gestion d'erreurs blindée avec try/except exhaustifs
- Logging avancé avec rotation et horodatage
- Fenêtres popup pour résultats détaillés
- Validation de sécurité pour toutes les entrées
- Sauvegarde automatique avec horodatage
- Statistiques en temps réel avec graphiques
"""

import os
import sys
import traceback
from datetime import datetime


def check_dependencies():
    """Vérifie toutes les dépendances requises."""
    print("🔍 Vérification des dépendances...")

    missing_deps = []

    # Vérifier Python version
    if sys.version_info < (2, 7):
        missing_deps.append("Python 2.7+ ou Python 3.x requis")

    # Vérifier Tkinter
    try:
        import tkinter  # noqa: F401
        import tkinter.ttk  # noqa: F401
        print("✅ Tkinter disponible")
    except ImportError as e:
        missing_deps.append("Tkinter: {}".format(str(e)))

    # Vérifier les modules standard
    required_modules = [
        'threading', 'time', 'json', 'csv', 'datetime',
        'collections', 'logging', 'tempfile', 'socket',
        'subprocess', 'platform', 'hashlib', 're'
    ]

    for module in required_modules:
        try:
            __import__(module)
        except ImportError as e:
            missing_deps.append("Module {}: {}".format(module, str(e)))

    # Vérifier les handlers de logging
    try:
        from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler  # noqa: F401
        print("✅ Handlers de logging avancés disponibles")
    except ImportError as e:
        missing_deps.append("Logging handlers: {}".format(str(e)))

    # Vérifier xml.etree.ElementTree
    try:
        import xml.etree.ElementTree  # noqa: F401
        print("✅ Support XML disponible")
    except ImportError as e:
        missing_deps.append("XML support: {}".format(str(e)))

    return missing_deps

def show_error_message(title, message):
    """Affiche un message d'erreur avec fallback."""
    print("❌ ERREUR: {}".format(title))
    print("=" * 60)
    print(message)
    print("=" * 60)

    # Essayer d'afficher une boîte de dialogue si possible
    try:
        if sys.version_info[0] >= 3:
            import tkinter.messagebox as messagebox
        else:
            import tkMessageBox as messagebox

        root = None
        if sys.version_info[0] >= 3:
            import tkinter
            root = tkinter.Tk()
        else:
            import Tkinter
            root = Tkinter.Tk()

        root.withdraw()
        messagebox.showerror(title, message)
        root.destroy()
    except Exception:
        pass

def create_directories():
    """Crée les répertoires nécessaires."""
    try:
        directories = ['logs', 'exports', 'sessions']
        for directory in directories:
            if not os.path.exists(directory):
                os.makedirs(directory)
                print("📁 Répertoire créé: {}".format(directory))
        return True
    except Exception as e:
        print("❌ Erreur création répertoires: {}".format(str(e)))
        return False

def check_files():
    """Vérifie la présence des fichiers requis."""
    print("🔍 Vérification des fichiers...")

    required_files = [
        'subbrute.py',
        'names.txt',
        'resolvers.txt'
    ]

    optional_files = [
        'subbrute_gui.py',
        'gui_simple.py',
        'subbrute_gui_advanced.py'
    ]

    missing_required = []
    missing_optional = []

    for file_path in required_files:
        if not os.path.exists(file_path):
            missing_required.append(file_path)
        else:
            print("✅ Fichier trouvé: {}".format(file_path))

    for file_path in optional_files:
        if not os.path.exists(file_path):
            missing_optional.append(file_path)
        else:
            print("✅ Fichier trouvé: {}".format(file_path))

    return missing_required, missing_optional

def launch_gui_version(version="advanced"):
    """Lance la version spécifiée de l'interface."""
    try:
        print("🚀 Lancement de SubBrute GUI version '{}'...".format(version))

        if version == "advanced":
            # Lancer la version avancée complète
            try:
                print("📊 Chargement des composants avancés...")

                # Importer et lancer
                import subbrute_gui_advanced
                return subbrute_gui_advanced.main_advanced()

            except ImportError as e:
                print("⚠️  Version avancée non disponible: {}".format(str(e)))
                print("📱 Basculement vers la version standard...")
                version = "standard"

        if version == "standard":
            # Lancer la version standard
            try:
                import tkinter as tk

                import subbrute_gui
                root = tk.Tk()

                subbrute_gui.SubBruteGUI(root)
                root.mainloop()
                return 0

            except ImportError as e:
                print("⚠️  Version standard non disponible: {}".format(str(e)))
                print("📱 Basculement vers la version simple...")
                version = "simple"

        if version == "simple":
            # Lancer la version simple
            try:
                import gui_simple
                return gui_simple.main()

            except ImportError as e:
                print("❌ Aucune version GUI disponible: {}".format(str(e)))
                return 1

        print("❌ Version '{}' inconnue".format(version))
        return 1

    except Exception as e:
        print("❌ Erreur lors du lancement: {}".format(str(e)))
        print("Traceback: {}".format(traceback.format_exc()))
        return 1

def show_welcome_message():
    """Affiche le message de bienvenue."""
    welcome = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                      SubBrute Advanced GUI v2.1                              ║
║               Interface Graphique Professionnelle Complète                   ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  🚀 FONCTIONNALITÉS AVANCÉES:                                                ║
║  • Interface à onglets moderne (Configuration, Résultats, Stats, Logs)      ║
║  • Recherche automatique de propriétaires de domaines via WHOIS             ║
║  • Extraction d'adresses email depuis les DNS records                       ║
║  • Export sophistiqué: CSV, JSON, XML, HTML avec métadonnées                ║
║  • Gestion d'erreurs blindée avec logging complet                           ║
║  • Fenêtres popup pour résultats détaillés                                  ║
║  • Validation de sécurité pour toutes les entrées                           ║
║  • Sauvegarde automatique avec horodatage                                   ║
║  • Statistiques en temps réel avec progression                              ║
║                                                                               ║
║  🔍 RECHERCHE DE PROPRIÉTAIRES:                                              ║
║  • Analyse WHOIS automatique pour chaque domaine découvert                  ║
║  • Extraction d'emails depuis SPF, TXT et autres records DNS                ║
║  • Géolocalisation des adresses IP                                          ║
║  • Cache intelligent pour optimiser les performances                        ║
║                                                                               ║
║  💾 EXPORT ET SAUVEGARDE:                                                    ║
║  • CSV: Compatible Excel/LibreOffice                                        ║
║  • JSON: Format structuré avec métadonnées complètes                       ║
║  • XML: Format standardisé pour intégration                                 ║
║  • HTML: Rapport web interactif prêt à partager                            ║
║                                                                               ║
║  🛡️  SÉCURITÉ:                                                               ║
║  • Validation stricte des domaines d'entrée                                 ║
║  • Protection contre les injections et attaques                             ║
║  • Logging des événements de sécurité                                       ║
║  • Limitation des ressources système                                        ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
    print(welcome)

def main():
    """Point d'entrée principal du lanceur avancé."""
    try:
        print("SubBrute Advanced GUI Launcher v2.1")
        print("Démarrage le: {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        print("Python version: {}".format(sys.version))
        print("Plateforme: {}".format(sys.platform))
        print()

        # Afficher le message de bienvenue
        show_welcome_message()

        # Vérifier les dépendances
        missing_deps = check_dependencies()
        if missing_deps:
            error_msg = "Dépendances manquantes:\\n\\n" + "\\n".join(missing_deps)
            error_msg += "\\n\\nInstallation recommandée:\\n"
            error_msg += "• Ubuntu/Debian: sudo apt-get install python3-tk python3-dev\\n"
            error_msg += "• CentOS/RHEL: sudo yum install python3-tkinter\\n"
            error_msg += "• Windows: Tkinter inclus avec Python\\n"
            error_msg += "• macOS: brew install python-tk"

            show_error_message("Dépendances Manquantes", error_msg)
            return 1

        print("✅ Toutes les dépendances sont disponibles\\n")

        # Créer les répertoires nécessaires
        if not create_directories():
            print("⚠️  Avertissement: Impossible de créer certains répertoires")

        print()

        # Vérifier les fichiers
        missing_required, missing_optional = check_files()

        if missing_required:
            error_msg = "Fichiers requis manquants:\\n\\n" + "\\n".join(missing_required)
            error_msg += (
                "\\n\\nAssurez-vous d'être dans le bon répertoire"
                " et que tous les fichiers SubBrute sont présents."
            )

            show_error_message("Fichiers Manquants", error_msg)
            return 1

        if missing_optional:
            print("⚠️  Fichiers optionnels manquants: {}".format(", ".join(missing_optional)))

        print("✅ Fichiers requis présents\\n")

        # Déterminer la version à lancer
        version = "advanced"

        # Permettre de spécifier la version via argument
        if len(sys.argv) > 1:
            if sys.argv[1] in ["--simple", "-s"]:
                version = "simple"
            elif sys.argv[1] in ["--standard", "-t"]:
                version = "standard"
            elif sys.argv[1] in ["--advanced", "-a"]:
                version = "advanced"
            elif sys.argv[1] in ["--help", "-h"]:
                print("""Usage: python launch_advanced_gui.py [options]

Options:
  --advanced, -a    Lancer la version avancée complète (défaut)
  --standard, -t    Lancer la version standard
  --simple, -s      Lancer la version simple et compatible
  --help, -h        Afficher cette aide

La version avancée inclut toutes les fonctionnalités:
• Recherche de propriétaires et emails
• Export multi-formats sophistiqué
• Logging avancé avec rotation
• Fenêtres popup détaillées
• Validation de sécurité complète
• Statistiques temps réel
""")
                return 0

        print("🎯 Version sélectionnée: {}".format(version))
        print("🚀 Lancement en cours...\\n")

        # Lancer l'interface
        return launch_gui_version(version)

    except KeyboardInterrupt:
        print("\\n⏹️  Application interrompue par l'utilisateur")
        return 0
    except Exception as e:
        error_msg = "Erreur fatale dans le lanceur:\\n\\n{}\\n\\nTraceback:\\n{}".format(
            str(e), traceback.format_exc()
        )
        show_error_message("Erreur Fatale", error_msg)
        return 1

if __name__ == "__main__":
    sys.exit(main())
