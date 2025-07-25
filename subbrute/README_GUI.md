# SubBrute GUI v2.0

Une interface graphique moderne et sophistiquée pour l'énumération de sous-domaines avec SubBrute.

## 🚀 Fonctionnalités

### Interface à Onglets
- **⚙ Configuration** : Paramètres avancés avec options détaillées
- **📊 Résultats** : Affichage en temps réel avec filtrage et recherche
- **📈 Statistiques** : Métriques de performance et graphiques en temps réel
- **📝 Logs** : Journalisation complète avec filtrage par niveau

### Fonctionnalités Avancées
- **Interface moderne** avec tooltips et système d'aide intégré
- **Barres de progression** en temps réel
- **Export sophistiqué** : CSV, JSON, XML, HTML avec métadonnées
- **Statistiques détaillées** : taux de réussite, IPs uniques, types d'enregistrements
- **Gestion multi-processus** : jusqu'à 64 processus simultanés
- **Logging coloré** : différents niveaux avec sauvegarde automatique
- **Filtrage avancé** : recherche par nom d'hôte, IP, ou les deux
- **Détection de wildcards** : filtrage automatique des réponses wildcards

## 📋 Prérequis

### Dépendances Python
```bash
# Ubuntu/Debian
sudo apt-get install python-tk python3-tk python-ttk

# CentOS/RHEL
sudo yum install tkinter python3-tkinter

# Windows
# Tkinter est inclus avec Python par défaut
```

### Modules Python Requis
- `tkinter` / `Tkinter` (Python 2/3)
- `threading`
- `queue` / `Queue`
- `json`
- `csv`
- `xml.etree.ElementTree`
- `datetime`
- `collections`

## 🎯 Installation

1. **Cloner le repository**
   ```bash
   git clone <repository-url>
   cd subbrute
   ```

2. **Installer les dépendances**
   ```bash
   # Ubuntu/Debian
   sudo apt-get install python-tk python3-tk
   
   # Ou pour Python 3 seulement
   sudo apt-get install python3-tk
   ```

3. **Lancer l'interface**
   ```bash
   # Version complète (si toutes les dépendances sont installées)
   python subbrute_gui.py
   
   # Version simplifiée (compatible Python 2/3)
   python gui_simple.py
   
   # Lanceur avec vérification des dépendances
   python launch_gui.py
   ```

## 🔧 Configuration

### Onglet Configuration

#### Configuration de la Cible
- **Domaine Cible** : Domaine à énumérer (ex: example.com)
- **Type d'Enregistrement DNS** : A, AAAA, CNAME, MX, TXT, SOA
- **Fichier de Sous-domaines** : Liste de mots (names.txt par défaut)
- **Fichier de Résolveurs** : Liste des serveurs DNS (resolvers.txt par défaut)

#### Configuration de Performance
- **Nombre de Processus** : 1-64 processus simultanés (16 par défaut)
- **Timeout** : Délai d'expiration DNS en secondes (2.0 par défaut)
- **Tentatives** : Nombre de tentatives pour les requêtes échouées (3 par défaut)

#### Options Avancées
- **Logging Verbose** : Journalisation détaillée
- **Sauvegarde des Logs** : Sauvegarde automatique dans un fichier
- **Filtrage des Wildcards** : Filtrage automatique des réponses wildcards
- **Export en Temps Réel** : Export automatique des résultats

## 📊 Utilisation

### Démarrage d'une Énumération

1. **Configurer la cible** dans l'onglet Configuration
2. **Ajuster les paramètres** selon vos besoins
3. **Cliquer sur "▶ Start Enumeration"** ou appuyer sur `Ctrl+S`
4. **Surveiller la progression** via la barre de statut
5. **Consulter les résultats** dans l'onglet Résultats

### Visualisation des Résultats

#### Onglet Résultats
- **Liste des sous-domaines** découverts en temps réel
- **Filtrage** par nom d'hôte ou adresse IP
- **Double-clic** sur un résultat pour les détails
- **Compteur de résultats** avec filtrage

#### Colonnes Affichées
- **Hostname** : Nom du sous-domaine découvert
- **Type** : Type d'enregistrement DNS
- **IP Addresses** : Adresses IP associées
- **Timestamp** : Heure de découverte

### Statistiques en Temps Réel

#### Métriques Principales
- **Total des Sous-domaines Traités**
- **Recherches Réussies**
- **Recherches Échouées**
- **Réponses Wildcards Filtrées**
- **Adresses IP Uniques**
- **Serveurs DNS Utilisés**

#### Métriques de Performance
- **Requêtes par Seconde**
- **Temps Écoulé**
- **ETA (Estimation du Temps Restant)**

## 💾 Export des Résultats

### Formats Supportés

#### CSV (Comma-Separated Values)
```csv
Hostname,Record Type,IP Addresses,Timestamp
www.example.com,A,"192.168.1.1, 192.168.1.2",14:30:25
mail.example.com,A,192.168.1.3,14:30:26
```

#### JSON (JavaScript Object Notation)
```json
{
  "metadata": {
    "target": "example.com",
    "export_time": "2024-01-15T14:30:00",
    "total_results": 125,
    "statistics": {
      "successful_lookups": 125,
      "unique_ips": 45,
      "record_types": {"A": 120, "AAAA": 5}
    }
  },
  "results": [...]
}
```

#### XML (eXtensible Markup Language)
```xml
<?xml version="1.0" encoding="utf-8"?>
<subbrute_results>
  <metadata>
    <target>example.com</target>
    <export_time>2024-01-15T14:30:00</export_time>
    <total_results>125</total_results>
  </metadata>
  <results>...</results>
</subbrute_results>
```

#### HTML (Rapport Web)
- Rapport web interactif avec statistiques
- Tableau formaté avec styles CSS
- Graphiques et métriques visuelles
- Prêt pour impression ou partage

## ⌨️ Raccourcis Clavier

| Raccourci | Action |
|-----------|--------|
| `Ctrl+S` | Démarrer l'énumération |
| `Ctrl+Q` | Quitter l'application |
| `F1` | Afficher l'aide |
| `F5` | Actualiser les statistiques |

## 🎨 Interface Utilisateur

### Thème et Couleurs
- **Interface moderne** avec thème "clam"
- **Couleurs codées** :
  - 🟢 Vert : Informations et succès
  - 🟡 Jaune : Avertissements
  - 🔴 Rouge : Erreurs critiques
  - 🔵 Bleu : Éléments d'action

### Tooltips Intelligents
- **Aide contextuelle** sur tous les éléments
- **Délai personnalisable** (500ms par défaut)
- **Style moderne** avec bordures et ombres

### Barres de Progression
- **Progression indéterminée** pendant l'énumération
- **Statut en temps réel** dans la barre de statut
- **Indicateur de tâche actuelle**

## 🔍 Fonctionnalités de Filtrage

### Onglet Résultats
- **Filtrage par texte** : recherche instantanée
- **Options de filtre** :
  - Par nom d'hôte uniquement
  - Par adresse IP uniquement
  - Les deux (recherche globale)
- **Compteur dynamique** : résultats filtrés/total

### Onglet Logs
- **Filtrage par niveau** : DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Recherche textuelle** dans les messages
- **Auto-scroll** optionnel
- **Limitation de taille** : garde les 1000 dernières entrées

## 📈 Monitoring et Debugging

### Logs Détaillés
```
[14:30:25.123] INFO     | Enumeration started for target: example.com
[14:30:25.456] DEBUG    | Initializing NameServerVerifier for target: example.com
[14:30:25.789] DEBUG    | Using DNS record type: A
[14:30:26.012] INFO     | NameServerVerifier initialized with 150 nameservers to test
[14:30:26.345] DEBUG    | Starting verification of 150 nameservers
```

### Gestion des Erreurs
- **Validation des entrées** : vérification des domaines et fichiers
- **Gestion des exceptions** : capture et affichage des erreurs
- **Messages informatifs** : aide contextuelle pour résoudre les problèmes
- **Récupération gracieuse** : continuation après erreurs non-critiques

## 🛠️ Personnalisation

### Configuration Avancée
```python
# Personnalisation des timeouts
resolver.timeout = 2.0
resolver.lifetime = 5.0

# Nombre optimal de processus (basé sur CPU/RAM)
process_count = min(multiprocessing.cpu_count() * 2, 32)

# Taille du buffer de nameservers
resolver_queue_size = 2
```

### Thèmes et Styles
```python
# Configuration des couleurs
COLORS = {
    'DEBUG': '\033[36m',    # Cyan
    'INFO': '\033[32m',     # Vert
    'WARNING': '\033[33m',  # Jaune
    'ERROR': '\033[31m',    # Rouge
    'CRITICAL': '\033[35m', # Magenta
}

# Styles TTK personnalisés
style.configure('Accent.TButton', background='#0078d4', foreground='white')
style.configure('Success.TLabel', foreground='#107c10')
```

## 🚨 Dépannage

### Problèmes Courants

#### "No module named tkinter"
```bash
# Ubuntu/Debian
sudo apt-get install python3-tk

# CentOS/RHEL
sudo yum install python3-tkinter
```

#### "Permission denied" sur les fichiers
```bash
chmod +x subbrute_gui.py
chmod +r names.txt resolvers.txt
```

#### Interface qui ne s'affiche pas
```bash
# Vérifier DISPLAY (Linux)
echo $DISPLAY

# Tester X11 forwarding (SSH)
ssh -X user@server
```

### Debug Mode
```python
# Activer le debug détaillé
logger = ColoredLogger(debug=True)

# Niveau de logging personnalisé
logging.basicConfig(level=logging.DEBUG)
```

## 📚 Architecture Technique

### Classes Principales

#### `SubBruteGUI`
- Interface principale avec gestion des onglets
- Coordination des processus d'énumération
- Gestion des événements et callbacks

#### `ModernTooltip`
- Tooltips stylés avec délai personnalisable
- Gestion des événements souris
- Positionnement intelligent

#### `GUILogger`
- Logger intégré pour l'interface
- Queue thread-safe pour les messages
- Formatage et coloration des logs

#### `NameServerVerifier`
- Vérification des serveurs DNS
- Détection des wildcards
- Tests de latence et fiabilité

#### `DNSLookupWorker`
- Processus de résolution DNS
- Gestion des timeouts et retries
- Filtrage des résultats

### Communication Inter-Processus
```python
# Queues thread-safe
result_queue = queue.Queue()
log_queue = queue.Queue()
stats_queue = queue.Queue()

# Partage de données avec multiprocessing
wildcards = multiprocessing.Manager().dict()
spider_blacklist = multiprocessing.Manager().dict()
```

## 🔒 Sécurité

### Bonnes Pratiques
- **Validation des entrées** : vérification des domaines et paramètres
- **Limitation des ressources** : nombre maximum de processus
- **Gestion des timeouts** : évite les blocages infinis
- **Filtrage des wildcards** : évite les faux positifs

### Usage Éthique
- **Respecter les serveurs DNS** : ne pas surcharger
- **Usage légitime uniquement** : tests de sécurité autorisés
- **Respecter les robots.txt** : si applicable
- **Limitation du taux** : éviter la détection comme attaque

## 📖 Exemples d'Usage

### Énumération Simple
```bash
# Lancer l'interface
python subbrute_gui.py

# 1. Entrer "example.com" comme cible
# 2. Sélectionner type d'enregistrement "A"
# 3. Cliquer sur "Start Enumeration"
# 4. Surveiller les résultats en temps réel
```

### Configuration Avancée
```bash
# Énumération avec 32 processus
# 1. Onglet Configuration
# 2. Définir "Process Count" à 32
# 3. Activer "Verbose Logging"
# 4. Définir timeout personnalisé à 3.0 secondes
```

### Export Professionnel
```bash
# Export au format JSON avec métadonnées
# 1. Compléter l'énumération
# 2. Cliquer sur "JSON" dans la barre d'outils
# 3. Choisir l'emplacement de sauvegarde
# 4. Le fichier inclut statistiques et métadonnées
```

## 🤝 Contribution

### Structure du Code
```
subbrute/
├── subbrute_gui.py          # Interface principale
├── gui_simple.py            # Version simplifiée
├── launch_gui.py            # Lanceur avec vérifications
├── subbrute.py              # Moteur principal
├── names.txt                # Liste de sous-domaines
├── resolvers.txt            # Liste de serveurs DNS
└── README_GUI.md            # Cette documentation
```

### Standards de Code
- **Docstrings** : documentation complète en anglais
- **Type hints** : annotations de type Python 3.6+
- **Error handling** : gestion robuste des exceptions
- **Logging** : utilisation du système de logging intégré

## 📄 License

MIT License - Voir le fichier LICENSE pour les détails.

## 👥 Crédits

- **SubBrute original** : rook et contributeurs
- **Interface GUI** : Enhanced SubBrute Team
- **Contributions** : JordanMilne, KxCode, rc0r, memoryprint, ppaulojr

---

**Note** : Cette interface nécessite l'installation de Tkinter. Sur certains systèmes Linux, il peut être nécessaire d'installer le paquet `python-tk` ou `python3-tk` séparément.

Pour plus d'informations et de support, consultez la documentation du projet ou ouvrez une issue sur le repository GitHub.