# SubBrute Advanced GUI v2.1 - Documentation Complète

## 🚀 Vue d'Ensemble

SubBrute Advanced GUI v2.1 est une interface graphique professionnelle et blindée pour l'énumération de sous-domaines. Cette version avancée inclut toutes les fonctionnalités demandées et répond aux exigences les plus strictes en matière de robustesse, sécurité et fonctionnalités.

### ✨ Nouvelles Fonctionnalités Avancées

#### 🔍 Recherche de Propriétaires et Emails
- **Analyse WHOIS automatique** : Recherche automatique du propriétaire pour chaque domaine découvert
- **Extraction d'emails avancée** : Extraction depuis les records DNS (SPF, TXT, MX)
- **Cache intelligent** : Optimisation des performances avec mise en cache des résultats
- **Géolocalisation IP** : Localisation géographique des adresses IP découvertes

#### 📊 Interface Utilisateur Moderne
- **Onglets professionnels** : Configuration, Résultats, Statistiques, Logs
- **Fenêtres popup détaillées** : Affichage complet des informations pour chaque résultat
- **Barres de progression** : Suivi en temps réel de l'avancement
- **Filtrage avancé** : Recherche et filtrage sophistiqués des résultats

#### 💾 Export Multi-Formats
- **CSV** : Format compatible Excel/LibreOffice avec toutes les données
- **JSON** : Format structuré avec métadonnées complètes et statistiques
- **XML** : Format standardisé pour intégration avec d'autres outils
- **HTML** : Rapport web interactif avec mise en forme professionnelle

#### 🛡️ Sécurité et Robustesse
- **Validation complète** : Vérification stricte de toutes les entrées utilisateur
- **Gestion d'erreurs blindée** : Try/catch exhaustifs sur toutes les opérations
- **Logging de sécurité** : Enregistrement de tous les événements sensibles
- **Protection contre injections** : Validation et sanitisation des données

#### 📝 Logging Avancé
- **Rotation automatique** : Gestion intelligente de la taille des fichiers de log
- **Niveaux détaillés** : DEBUG, INFO, WARNING, ERROR, CRITICAL, SECURITY
- **Horodatage précis** : Timestamps avec millisecondes
- **Sauvegarde automatique** : Archivage des sessions avec horodatage

## 📋 Installation et Démarrage

### Prérequis Système

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install python3 python3-tk python3-dev

# CentOS/RHEL
sudo yum install python3 python3-tkinter python3-devel

# macOS (avec Homebrew)
brew install python-tk

# Windows
# Tkinter est inclus avec Python par défaut
```

### Lancement Rapide

```bash
# Lancer la version avancée complète (recommandé)
python launch_advanced_gui.py

# Ou avec l'option explicite
python launch_advanced_gui.py --advanced

# Autres options disponibles
python launch_advanced_gui.py --help
```

### Vérification de l'Installation

Le lanceur vérifie automatiquement :
- ✅ Version Python compatible (2.7+ ou 3.x)
- ✅ Disponibilité de Tkinter et ttk
- ✅ Modules Python requis
- ✅ Handlers de logging avancés
- ✅ Support XML pour l'export
- ✅ Présence des fichiers SubBrute

## 🔧 Configuration Avancée

### Onglet Configuration

#### Section Cible
- **Domaine Cible** : Domaine principal à énumérer (ex: example.com)
- **Type DNS** : A, AAAA, CNAME, MX, TXT, SOA
- **Validation automatique** : Vérification de sécurité en temps réel

#### Section Fichiers
- **Fichier de Sous-domaines** : Liste de mots (names.txt par défaut)
- **Fichier de Résolveurs** : Serveurs DNS à utiliser (resolvers.txt par défaut)
- **Parcourir** : Sélection graphique de fichiers avec validation

#### Section Performance
- **Nombre de Processus** : 1-64 processus simultanés (16 par défaut)
- **Timeout DNS** : Délai d'expiration en secondes (2.0 par défaut)
- **Tentatives** : Nombre de retries pour les échecs (3 par défaut)

#### Options Avancées
- ☑️ **Logging Verbose** : Journalisation détaillée avec DEBUG
- ☑️ **Activer WHOIS** : Recherche automatique des propriétaires
- ☑️ **Géolocalisation** : Localisation des adresses IP
- ☑️ **Export Automatique** : Sauvegarde automatique des résultats
- ☑️ **Sauvegarde des Logs** : Archivage avec rotation
- ☑️ **Filtrage Wildcards** : Suppression des faux positifs

## 📊 Utilisation des Résultats

### Onglet Résultats

#### Colonnes Affichées
| Colonne | Description | Exemple |
|---------|-------------|---------|
| **Nom d'Hôte** | Sous-domaine découvert | www.example.com |
| **Type** | Type d'enregistrement DNS | A, CNAME, MX |
| **Adresses IP** | IPs associées au domaine | 192.168.1.1, 192.168.1.2 |
| **Propriétaire** | Propriétaire du domaine (WHOIS) | Example Corp |
| **Emails** | Adresses email extraites | admin@example.com |
| **Heure** | Timestamp de découverte | 14:30:25 |

#### Fonctionnalités Interactives
- **Double-clic** : Affiche une fenêtre popup avec détails complets
- **Filtrage en temps réel** : Recherche instantanée dans tous les champs
- **Tri par colonnes** : Clic sur les en-têtes pour trier
- **Sélection multiple** : Ctrl+clic pour sélectionner plusieurs résultats

#### Recherche de Propriétaires
- **Bouton "🔍 Rechercher Propriétaires"** : Lance la recherche WHOIS pour tous les résultats
- **Traitement par lot** : Recherche optimisée avec cache et délais
- **Mise à jour automatique** : Actualisation en temps réel des résultats

### Fenêtres Popup Détaillées

Chaque résultat peut être examiné en détail via une fenêtre popup contenant :

#### Onglet Informations de Base
- Nom d'hôte complet
- Type d'enregistrement DNS
- Liste complète des adresses IP
- Timestamp de découverte
- Temps de réponse DNS
- TTL (Time To Live)

#### Onglet WHOIS
- **Propriétaire du domaine** : Nom et organisation
- **Registrar** : Bureau d'enregistrement
- **Dates importantes** : Création, expiration, mise à jour
- **Serveurs de noms** : Liste des nameservers
- **Contacts** : Administratif, technique, facturation
- **Statut du domaine** : Active, suspended, etc.

#### Onglet Géolocalisation
- **Localisation par IP** : Pays, région, ville
- **Informations réseau** : FAI, organisation
- **Coordonnées GPS** : Latitude, longitude (si disponibles)
- **Timezone** : Fuseau horaire de la localisation

#### Onglet Ports
- **Scan de ports intégré** : Ports communs (21, 22, 80, 443, etc.)
- **Configuration personnalisée** : Liste de ports à scanner
- **Résultats détaillés** : État (ouvert/fermé), service détecté
- **Temps de réponse** : Latence par port

## 📈 Statistiques Avancées

### Onglet Statistiques

#### Métriques Principales
- **Domaines Découverts** : Nombre total de sous-domaines trouvés
- **Adresses IP Uniques** : Nombre d'IPs distinctes
- **Taux de Succès** : Pourcentage de requêtes réussies
- **Temps Écoulé** : Durée totale d'exécution (HH:MM:SS)
- **Requêtes/sec** : Débit moyen de traitement
- **Serveurs DNS Utilisés** : Nombre de résolveurs actifs

#### Métriques Détaillées
- **Distribution par Type** : Répartition des types d'enregistrements
- **Analyse Temporelle** : Évolution du taux de découverte
- **Performance DNS** : Temps de réponse moyen par résolveur
- **Géolocalisation** : Répartition géographique des résultats
- **Détection de Patterns** : Identification de sous-domaines similaires

#### Graphiques en Temps Réel
- **Progression** : Courbe de découverte au fil du temps
- **Répartition** : Camembert des types d'enregistrements
- **Performance** : Histogramme des temps de réponse
- **Géographie** : Carte de répartition des IPs (si données disponibles)

#### Export des Statistiques
- **JSON complet** : Toutes les métriques avec métadonnées
- **CSV résumé** : Statistiques principales tabulées
- **Rapport HTML** : Présentation graphique professionnelle

## 📝 Système de Logs Avancé

### Onglet Logs

#### Fonctionnalités de Filtrage
- **Par niveau** : DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Par module** : Filtrage par composant de l'application
- **Recherche textuelle** : Recherche dans le contenu des messages
- **Filtrage temporel** : Par période (dernière heure, jour, etc.)

#### Niveaux de Log Détaillés

| Niveau | Couleur | Usage | Exemple |
|--------|---------|--------|---------|
| **DEBUG** | Cyan | Débogage détaillé | DNS query for www.example.com |
| **INFO** | Vert | Informations générales | Enumeration started for target |
| **WARNING** | Jaune | Avertissements non critiques | Timeout for resolver 8.8.8.8 |
| **ERROR** | Rouge | Erreurs récupérables | Failed to parse WHOIS response |
| **CRITICAL** | Magenta | Erreurs critiques | Unable to initialize DNS resolver |
| **SECURITY** | Rouge Clair | Événements sécurité | Invalid domain input detected |
| **SUCCESS** | Vert Clair | Succès importants | Enumeration completed successfully |

#### Fonctionnalités Avancées
- **Auto-scroll** : Suivi automatique des nouveaux logs
- **Limitation de taille** : Conservation des 1000 dernières entrées
- **Export sélectif** : Sauvegarde des logs filtrés
- **Horodatage précis** : Millisecondes incluses
- **Contexte enrichi** : Module, fonction, ligne de code

### Logging sur Fichier

#### Fichiers Générés
- **subbrute_main.log** : Log principal avec rotation (10MB max)
- **subbrute_errors.log** : Erreurs uniquement (5MB max)
- **session_YYYYMMDD_HHMMSS.log** : Log de session horodaté
- **performance.log** : Métriques de performance (rotation quotidienne)
- **security.log** : Événements de sécurité (2MB max, 10 backups)

#### Rotation Automatique
- **Par taille** : Rotation quand le fichier atteint la limite
- **Par temps** : Rotation quotidienne pour les logs de performance
- **Compression** : Archivage automatique des anciens logs
- **Rétention** : Conservation configurable des historiques

## 💾 Export Multi-Formats

### Format CSV (Excel/LibreOffice)

```csv
Hostname,Type,IP_Addresses,Owner,Emails,Timestamp,Response_Time,TTL
www.example.com,A,"192.168.1.1,192.168.1.2",Example Corp,admin@example.com,14:30:25,50ms,300
mail.example.com,A,192.168.1.10,Example Corp,postmaster@example.com,14:30:26,75ms,600
```

**Caractéristiques** :
- Compatible avec Excel, LibreOffice Calc, Google Sheets
- Encodage UTF-8 pour les caractères spéciaux
- Guillemets automatiques pour les champs multi-valeurs
- En-têtes descriptifs en français

### Format JSON (Structuré avec Métadonnées)

```json
{
  "metadata": {
    "target": "example.com",
    "export_time": "2024-01-15T14:30:00.123456",
    "total_results": 125,
    "session_id": "session_20240115_143000_abc123",
    "version": "SubBrute Advanced GUI v2.1",
    "statistics": {
      "successful_queries": 125,
      "failed_queries": 15,
      "unique_ips": 45,
      "unique_domains": 125,
      "execution_time": 180.5,
      "dns_servers_used": ["8.8.8.8", "1.1.1.1"],
      "record_types": {"A": 120, "AAAA": 5}
    }
  },
  "results": [
    {
      "hostname": "www.example.com",
      "record_type": "A",
      "addresses": ["192.168.1.1", "192.168.1.2"],
      "timestamp": "14:30:25.123",
      "response_time_ms": 50,
      "ttl": 300,
      "whois_info": {
        "owner": "Example Corp",
        "registrar": "Example Registrar",
        "creation_date": "2020-01-01",
        "expiry_date": "2025-01-01",
        "emails": ["admin@example.com", "tech@example.com"]
      },
      "geolocation": {
        "country": "France",
        "region": "Île-de-France",
        "city": "Paris",
        "isp": "OVH SAS"
      }
    }
  ]
}
```

**Avantages** :
- Format standardisé facilement parsable
- Métadonnées complètes avec statistiques
- Informations WHOIS et géolocalisation intégrées
- Horodatage précis avec millisecondes
- Encodage UTF-8 natif

### Format XML (Intégration Système)

```xml
<?xml version="1.0" encoding="utf-8"?>
<subbrute_results version="2.1">
  <metadata>
    <target>example.com</target>
    <export_time>2024-01-15T14:30:00.123456</export_time>
    <total_results>125</total_results>
    <session_id>session_20240115_143000_abc123</session_id>
    <statistics>
      <successful_queries>125</successful_queries>
      <unique_ips>45</unique_ips>
      <execution_time>180.5</execution_time>
    </statistics>
  </metadata>
  <results>
    <result id="1">
      <hostname>www.example.com</hostname>
      <record_type>A</record_type>
      <addresses>
        <address>192.168.1.1</address>
        <address>192.168.1.2</address>
      </addresses>
      <whois_info>
        <owner>Example Corp</owner>
        <emails>
          <email>admin@example.com</email>
        </emails>
      </whois_info>
    </result>
  </results>
</subbrute_results>
```

**Usage** :
- Intégration avec des outils d'analyse XML
- Compatible avec des parsers standards
- Structure hiérarchique claire
- Validation XSD possible

### Format HTML (Rapport Web Interactif)

Génère un rapport HTML complet avec :

#### Fonctionnalités du Rapport HTML
- **En-tête professionnel** : Logo, titre, informations de session
- **Résumé exécutif** : Statistiques clés avec graphiques
- **Tableau interactif** : Tri, filtrage, recherche JavaScript
- **Styles CSS modernes** : Design responsive et professionnel
- **Graphiques intégrés** : Charts.js pour les visualisations
- **Export PDF** : Bouton d'impression optimisé
- **Méta-informations** : SEO et métadonnées complètes

#### Structure du Rapport
1. **Page de couverture** : Résumé exécutif avec métriques clés
2. **Tableau des résultats** : Tous les domaines avec détails complets
3. **Analyse statistique** : Graphiques et tendances
4. **Annexes techniques** : Configuration utilisée, logs d'erreurs
5. **Glossaire** : Définitions des termes techniques

## 🔍 Fonctionnalités de Recherche

### Recherche WHOIS Avancée

#### Sources de Données
- **Serveurs WHOIS officiels** : .com, .net, .org, .fr, .uk, etc.
- **Fallback intelligent** : Serveurs alternatifs en cas d'échec
- **Cache local** : Évite les requêtes répétitives
- **Rate limiting** : Respect des limites des serveurs

#### Informations Extraites
- **Propriétaire** : Nom complet ou organisation
- **Registrar** : Bureau d'enregistrement du domaine
- **Dates importantes** : Création, expiration, dernière mise à jour
- **Contacts** : Administrateur, technique, facturation
- **Serveurs de noms** : Liste des nameservers autoritaires
- **Statut** : clientTransferProhibited, clientUpdateProhibited, etc.

#### Parsing Intelligent
- **Multi-format** : Support des différents formats WHOIS
- **Multi-langue** : Reconnaissance des réponses en différentes langues
- **Validation** : Vérification de la cohérence des données
- **Nettoyage** : Suppression des doublons et normalisation

### Extraction d'Emails

#### Sources DNS
- **Records TXT/SPF** : `v=spf1 include:_spf.example.com`
- **Records MX** : Déduction d'emails courants sur les serveurs mail
- **Records SOA** : Email de l'administrateur DNS
- **Records DMARC** : `v=DMARC1; p=none; rua=mailto:dmarc@example.com`

#### Patterns Communs
- **Administratifs** : admin@, administrator@, webmaster@
- **Techniques** : tech@, support@, it@, noc@
- **Marketing** : info@, contact@, hello@, sales@
- **Sécurité** : security@, abuse@, postmaster@

#### Validation et Nettoyage
- **Format RFC** : Validation selon les standards RFC 5322
- **Domaine valide** : Vérification de l'existence du domaine
- **Déduplication** : Suppression des emails identiques
- **Blacklist** : Exclusion des emails génériques sans valeur

### Géolocalisation IP

#### Fournisseurs de Données
- **ip-api.com** : Service gratuit avec limites raisonnables
- **Fallback local** : Base de données locale si disponible
- **Rate limiting** : Respect des quotas API
- **Cache persistant** : Sauvegarde locale des résultats

#### Informations Géographiques
- **Pays** : Code ISO et nom complet
- **Région/État** : Division administrative principale
- **Ville** : Localité la plus proche
- **Coordonnées GPS** : Latitude et longitude approximatives
- **Fuseau horaire** : UTC offset de la région

#### Informations Réseau
- **FAI** : Fournisseur d'accès Internet
- **Organisation** : Entité propriétaire de la plage IP
- **ASN** : Autonomous System Number
- **Type de réseau** : Commercial, éducatif, gouvernemental, etc.

## 🛡️ Sécurité et Validation

### Validation des Entrées

#### Domaines
- **Format RFC** : Vérification selon les standards DNS
- **Longueur** : 3-253 caractères maximum
- **Caractères autorisés** : Alphanumériques, tirets, points
- **Structure** : Au moins deux parties séparées par un point
- **Blacklist** : Exclusion des domaines malveillants connus

#### Chemins de Fichiers
- **Traversal de répertoire** : Blocage des `../` et similaires
- **Caractères dangereux** : Interdiction des caractères shell
- **Normalisation** : Conversion en chemin absolu sécurisé
- **Existence** : Vérification de l'existence et des permissions

#### Paramètres Numériques
- **Type** : Validation du type entier ou flottant
- **Plages** : Respect des limites min/max définies
- **Débordement** : Protection contre les valeurs extrêmes
- **Injection** : Sanitisation contre les attaques

### Protection contre les Injections

#### Injection de Commandes
- **Caractères interdits** : `;`, `|`, `&`, `$`, `` ` ``, `(`, `)`
- **Validation stricte** : Whitelist des caractères autorisés
- **Échappement** : Échappement sécurisé si nécessaire
- **Isolation** : Exécution dans un environnement restreint

#### Injection SQL/NoSQL
- **Paramètres liés** : Utilisation de requêtes préparées
- **Validation de type** : Vérification du type de données
- **Échappement** : Échappement des caractères spéciaux
- **Limitation** : Restriction des opérations autorisées

#### Cross-Site Scripting (XSS)
- **Encodage HTML** : Conversion des caractères spéciaux
- **Validation d'URL** : Vérification des protocoles autorisés
- **Sanitisation** : Nettoyage du contenu utilisateur
- **CSP** : Content Security Policy pour les exports HTML

### Logging de Sécurité

#### Événements Tracés
- **Tentatives d'injection** : Détection et enregistrement
- **Échecs de validation** : Inputs refusés avec détails
- **Accès aux fichiers** : Lectures/écritures de fichiers sensibles
- **Erreurs système** : Exceptions et erreurs critiques

#### Format des Logs de Sécurité
```
[2024-01-15 14:30:25.123] SECURITY | SecurityValidator | validate_domain() | 
SECURITY_EVENT: DANGEROUS_PATTERN_DETECTED - Dangerous pattern in domain | 
domain=example.com;rm -rf / | pattern=; | source_ip=127.0.0.1
```

#### Analyse et Alertes
- **Détection de patterns** : Identification d'attaques répétées
- **Seuils d'alerte** : Déclenchement d'alertes après X tentatives
- **Notification** : Envoi d'emails ou messages pour les incidents critiques
- **Archivage** : Conservation long terme des logs de sécurité

## ⚡ Performance et Optimisation

### Optimisations Réseau

#### Gestion des Connexions
- **Pool de connexions** : Réutilisation des connexions DNS
- **Timeout adaptatif** : Ajustement selon la latence réseau
- **Retry intelligent** : Backoff exponentiel pour les échecs
- **Load balancing** : Répartition sur plusieurs résolveurs

#### Cache Multi-Niveaux
- **Cache DNS** : Résultats DNS avec TTL respecté
- **Cache WHOIS** : Informations de propriétaire (24h)
- **Cache géolocalisation** : Localisation IP (7 jours)
- **Cache de validation** : Résultats de validation des domaines

### Optimisations Mémoire

#### Gestion des Données
- **Streaming** : Traitement par chunks pour les gros volumes
- **Compression** : Compression des données en mémoire
- **Garbage collection** : Nettoyage proactif des objets inutiles
- **Limitation** : Limites de mémoire configurable

#### Structures de Données
- **Sets pour unicité** : Déduplication efficace des IPs
- **Dictionnaires ordonnés** : Préservation de l'ordre d'insertion
- **Queues thread-safe** : Communication inter-thread optimisée
- **Indexes** : Indexation des résultats pour recherche rapide

### Monitoring des Performances

#### Métriques Collectées
- **Temps de réponse DNS** : Par résolveur et par requête
- **Débit de traitement** : Requêtes par seconde
- **Utilisation mémoire** : Peak et moyenne par processus
- **Utilisation CPU** : Pourcentage par core
- **I/O disque** : Lecture/écriture des logs et exports

#### Profiling Intégré
- **Hotspots** : Identification des fonctions coûteuses
- **Call graph** : Analyse des chaînes d'appels
- **Memory profiling** : Détection des fuites mémoire
- **I/O profiling** : Optimisation des accès disque

## 🔧 Configuration et Personnalisation

### Fichier de Configuration JSON

```json
{
  "application": {
    "theme": "modern",
    "language": "fr",
    "auto_save": true,
    "session_timeout": 3600
  },
  "logging": {
    "level": "INFO",
    "rotation_size": "10MB",
    "retention_days": 30,
    "enable_security_log": true
  },
  "network": {
    "dns_timeout": 2.0,
    "dns_retries": 3,
    "max_concurrent": 16,
    "rate_limit_whois": 0.5
  },
  "security": {
    "enable_validation": true,
    "strict_mode": true,
    "blocked_domains": ["localhost", "127.0.0.1"],
    "max_input_length": 253
  },
  "export": {
    "default_format": "json",
    "include_metadata": true,
    "auto_timestamp": true,
    "compress_large_files": true
  },
  "ui": {
    "window_size": "1400x900",
    "font_family": "Arial",
    "font_size": 10,
    "tooltip_delay": 500
  }
}
```

### Variables d'Environnement

```bash
# Configuration des logs
export SUBBRUTE_LOG_LEVEL=DEBUG
export SUBBRUTE_LOG_DIR=/var/log/subbrute
export SUBBRUTE_LOG_ROTATION=10MB

# Configuration réseau
export SUBBRUTE_DNS_TIMEOUT=3.0
export SUBBRUTE_MAX_PROCESSES=32
export SUBBRUTE_RATE_LIMIT=0.5

# Configuration sécurité
export SUBBRUTE_STRICT_MODE=true
export SUBBRUTE_ENABLE_WHOIS=true
export SUBBRUTE_ENABLE_GEOLOC=true

# Configuration UI
export SUBBRUTE_THEME=dark
export SUBBRUTE_LANGUAGE=fr
export SUBBRUTE_WINDOW_SIZE=1600x1000
```

### Personnalisation de l'Interface

#### Thèmes Disponibles
- **Modern** : Thème par défaut avec couleurs modernes
- **Dark** : Interface sombre pour réduire la fatigue oculaire
- **Classic** : Interface classique Windows 95 style
- **High Contrast** : Contraste élevé pour l'accessibilité

#### Couleurs Personnalisables
```python
THEME_COLORS = {
    'modern': {
        'primary': '#0078d4',
        'success': '#107c10',
        'warning': '#ff8c00',
        'error': '#d13438',
        'background': '#ffffff',
        'text': '#323130'
    },
    'dark': {
        'primary': '#0086f0',
        'success': '#00cc44',
        'warning': '#ffaa00',
        'error': '#ff4444',
        'background': '#1e1e1e',
        'text': '#ffffff'
    }
}
```

#### Polices et Tailles
- **Famille de police** : Arial, Helvetica, Consolas, Monaco
- **Tailles** : 8pt à 16pt selon l'élément
- **Styles** : Normal, gras, italique pour la hiérarchisation
- **Rendu** : Antialiasing et ClearType sur Windows

## 📊 Intégrations et API

### Export vers Outils Externes

#### Splunk
```json
{
  "sourcetype": "subbrute:results",
  "index": "security",
  "host": "subbrute-scanner",
  "time": "2024-01-15T14:30:25.123456",
  "event": {
    "hostname": "www.example.com",
    "ip_addresses": ["192.168.1.1"],
    "owner": "Example Corp",
    "country": "France"
  }
}
```

#### Elasticsearch
```json
PUT /subbrute-results/_doc/1
{
  "@timestamp": "2024-01-15T14:30:25.123456Z",
  "target": "example.com",
  "subdomain": "www.example.com",
  "ip_addresses": ["192.168.1.1", "192.168.1.2"],
  "dns_type": "A",
  "whois": {
    "owner": "Example Corp",
    "registrar": "Example Registrar"
  },
  "geolocation": {
    "country": "France",
    "city": "Paris",
    "coordinates": [2.3522, 48.8566]
  }
}
```

#### MISP (Malware Information Sharing Platform)
- **Attributs** : Domains, IPs, emails comme indicators
- **Tags** : Classification automatique selon le contexte
- **Relations** : Liens entre domaines, IPs et propriétaires
- **Events** : Création d'événements pour chaque campagne

### APIs de Sortie

#### REST API Endpoint
```bash
# Démarrer une énumération
POST /api/v1/enumerations
{
  "target": "example.com",
  "record_type": "A",
  "enable_whois": true
}

# Récupérer les résultats
GET /api/v1/enumerations/{id}/results
{
  "status": "completed",
  "results": [...],
  "statistics": {...}
}
```

#### WebSocket pour Temps Réel
```javascript
const ws = new WebSocket('ws://localhost:8080/api/v1/stream');
ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  if (data.type === 'new_result') {
    console.log('Nouveau sous-domaine:', data.hostname);
  }
};
```

### Intégration CI/CD

#### Script Jenkins
```groovy
pipeline {
    agent any
    stages {
        stage('Subdomain Enumeration') {
            steps {
                script {
                    sh '''
                        python launch_advanced_gui.py --batch \
                            --target ${TARGET_DOMAIN} \
                            --output results.json \
                            --enable-whois \
                            --max-processes 32
                    '''
                    
                    def results = readJSON file: 'results.json'
                    if (results.metadata.total_results > 100) {
                        slackSend "⚠️ Large subdomain footprint detected: ${results.metadata.total_results} domains"
                    }
                }
            }
        }
    }
}
```

#### GitHub Actions
```yaml
name: Subdomain Enumeration
on:
  schedule:
    - cron: '0 2 * * 1'  # Tous les lundis à 2h
  
jobs:
  enumerate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install python3-tk
      
      - name: Run enumeration
        run: |
          python launch_advanced_gui.py --batch \
            --target ${{ secrets.TARGET_DOMAIN }} \
            --output /tmp/results.json
      
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: enumeration-results
          path: /tmp/results.json
```

## 🚨 Alertes et Notifications

### Système d'Alertes Intégré

#### Types d'Alertes
- **Nouveaux domaines** : Notification pour chaque nouveau sous-domaine
- **IPs sensibles** : Alerte pour les IPs dans des plages critiques
- **Propriétaires suspects** : Détection de propriétaires dans une blacklist
- **Erreurs critiques** : Notification des erreurs système importantes
- **Seuils dépassés** : Alerte quand un seuil de résultats est atteint

#### Canaux de Notification
- **Email SMTP** : Envoi d'emails avec rapports détaillés
- **Webhook** : POST HTTP vers des URLs configurées
- **Slack** : Intégration native avec canaux Slack
- **Teams** : Notifications Microsoft Teams
- **Syslog** : Envoi vers serveurs syslog centralisés

### Configuration des Alertes

```json
{
  "alerts": {
    "enabled": true,
    "email": {
      "smtp_server": "smtp.example.com",
      "smtp_port": 587,
      "username": "alerts@example.com",
      "password": "secret",
      "recipients": ["security@example.com"],
      "subject_prefix": "[SubBrute Alert]"
    },
    "slack": {
      "webhook_url": "https://hooks.slack.com/services/...",
      "channel": "#security-alerts",
      "username": "SubBrute Bot"
    },
    "thresholds": {
      "new_domains_per_minute": 10,
      "total_domains_warning": 500,
      "total_domains_critical": 1000,
      "error_rate_percent": 5
    },
    "filters": {
      "suspicious_ips": ["192.168.0.0/16", "10.0.0.0/8"],
      "blocked_owners": ["Suspicious Corp", "Known Bad Actor"],
      "alert_keywords": ["admin", "test", "dev", "staging"]
    }
  }
}
```

### Exemples de Messages d'Alerte

#### Email HTML
```html
<!DOCTYPE html>
<html>
<head>
    <title>SubBrute Alert - New Subdomains Discovered</title>
</head>
<body>
    <h1>🚨 SubBrute Security Alert</h1>
    <p><strong>Target:</strong> example.com</p>
    <p><strong>Time:</strong> 2024-01-15 14:30:25</p>
    <p><strong>Alert Type:</strong> New Subdomains Discovered</p>
    
    <h2>Summary</h2>
    <ul>
        <li>Total new domains: 15</li>
        <li>Suspicious IPs detected: 2</li>
        <li>New emails found: 8</li>
    </ul>
    
    <h2>High Priority Findings</h2>
    <table border="1">
        <tr><th>Domain</th><th>IP</th><th>Owner</th><th>Risk</th></tr>
        <tr><td>admin.example.com</td><td>192.168.1.100</td><td>Unknown</td><td>High</td></tr>
    </table>
</body>
</html>
```

#### Message Slack
```json
{
  "channel": "#security-alerts",
  "username": "SubBrute Bot",
  "icon_emoji": ":warning:",
  "attachments": [
    {
      "color": "warning",
      "title": "New Subdomains Discovered",
      "fields": [
        {
          "title": "Target",
          "value": "example.com",
          "short": true
        },
        {
          "title": "New Domains",
          "value": "15",
          "short": true
        }
      ],
      "actions": [
        {
          "type": "button",
          "text": "View Full Report",
          "url": "https://dashboard.example.com/reports/12345"
        }
      ]
    }
  ]
}
```

## 🔧 Dépannage et Maintenance

### Problèmes Courants et Solutions

#### Interface Graphique

**Problème** : "No module named tkinter"
```bash
# Solution Ubuntu/Debian
sudo apt-get install python3-tk

# Solution CentOS/RHEL
sudo yum install python3-tkinter

# Vérification
python3 -c "import tkinter; print('Tkinter OK')"
```

**Problème** : Interface qui ne s'affiche pas sur SSH
```bash
# Activer X11 forwarding
ssh -X user@server

# Vérifier DISPLAY
echo $DISPLAY

# Test X11
xeyes  # Doit afficher des yeux qui suivent la souris
```

**Problème** : Police d'affichage incorrecte
```python
# Forcer une police spécifique
export SUBBRUTE_FONT_FAMILY="DejaVu Sans"
export SUBBRUTE_FONT_SIZE=12
```

#### Réseau et DNS

**Problème** : Timeouts DNS fréquents
```json
{
  "network": {
    "dns_timeout": 5.0,
    "dns_retries": 5,
    "rate_limit_dns": 1.0
  }
}
```

**Problème** : Serveurs DNS bloqués
```bash
# Utiliser des résolveurs alternatifs
echo "1.1.1.1" > custom_resolvers.txt
echo "8.8.8.8" >> custom_resolvers.txt
echo "9.9.9.9" >> custom_resolvers.txt
```

**Problème** : Rate limiting WHOIS
```json
{
  "network": {
    "rate_limit_whois": 2.0,
    "whois_timeout": 10.0,
    "enable_whois_cache": true
  }
}
```

#### Performance

**Problème** : Utilisation mémoire excessive
```json
{
  "performance": {
    "max_results_in_memory": 10000,
    "enable_result_streaming": true,
    "garbage_collect_interval": 60
  }
}
```

**Problème** : CPU à 100%
```json
{
  "network": {
    "max_concurrent": 8,
    "rate_limit_dns": 0.1
  }
}
```

### Logs de Diagnostic

#### Activation du Debug Complet
```bash
export SUBBRUTE_LOG_LEVEL=DEBUG
export SUBBRUTE_DEBUG_ALL=true
python launch_advanced_gui.py --debug
```

#### Analyse des Logs
```bash
# Erreurs critiques
grep "CRITICAL\|ERROR" logs/subbrute_main.log

# Problèmes réseau
grep "timeout\|connection\|refused" logs/subbrute_main.log

# Problèmes de sécurité
grep "SECURITY" logs/security.log

# Performance
grep "PERFORMANCE" logs/performance.log
```

#### Commandes de Diagnostic
```bash
# Vérifier l'environnement Python
python --version
python -m tkinter  # Test Tkinter

# Vérifier la connectivité DNS
nslookup google.com 8.8.8.8
dig @1.1.1.1 google.com

# Vérifier les permissions
ls -la names.txt resolvers.txt
ls -la logs/

# Espace disque
df -h .
du -sh logs/ exports/

# Processus en cours
ps aux | grep python
netstat -tulpn | grep python
```

### Maintenance Préventive

#### Nettoyage Automatique
```bash
#!/bin/bash
# Script de nettoyage hebdomadaire

# Nettoyer les logs anciens (>30 jours)
find logs/ -name "*.log*" -mtime +30 -delete

# Compresser les gros fichiers de log
find logs/ -name "*.log" -size +10M -exec gzip {} \;

# Nettoyer le cache temporaire
rm -rf /tmp/subbrute_cache_*

# Nettoyer les exports anciens (>7 jours)
find exports/ -name "*.json" -mtime +7 -delete
find exports/ -name "*.csv" -mtime +7 -delete

echo "Nettoyage terminé: $(date)"
```

#### Mise à Jour des Dépendances
```bash
# Mettre à jour les listes de résolveurs
curl -s https://public-dns.info/nameservers.csv | \
  awk -F',' '{print $1}' | head -50 > resolvers.txt

# Mettre à jour la wordlist
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt \
  -O names.txt

# Vérifier les mises à jour de sécurité
python -m pip list --outdated
```

#### Monitoring de Santé
```bash
#!/bin/bash
# Vérification de santé système

# Vérifier l'espace disque
DISK_USAGE=$(df -h . | awk 'NR==2 {print $5}' | sed 's/%//')
if [ $DISK_USAGE -gt 90 ]; then
    echo "ALERTE: Espace disque critique ($DISK_USAGE%)"
fi

# Vérifier la mémoire
MEM_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [ $MEM_USAGE -gt 85 ]; then
    echo "ALERTE: Utilisation mémoire élevée ($MEM_USAGE%)"
fi

# Vérifier les logs d'erreur récents
ERROR_COUNT=$(grep -c "ERROR\|CRITICAL" logs/subbrute_main.log | tail -1000)
if [ $ERROR_COUNT -gt 50 ]; then
    echo "ALERTE: Nombre d'erreurs élevé ($ERROR_COUNT)"
fi

echo "Vérification de santé terminée: $(date)"
```

## 📞 Support et Contact

### Communauté et Documentation
- 📖 **Documentation complète** : [README_ADVANCED.md](README_ADVANCED.md)
- 🎯 **Guide de démarrage rapide** : [QUICKSTART.md](QUICKSTART.md)
- 🔧 **Guide de dépannage** : [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- 💡 **FAQ** : [FAQ.md](FAQ.md)

### Contribution au Projet
- 🐛 **Signaler un bug** : Issues GitHub avec template détaillé
- ✨ **Demander une fonctionnalité** : Feature requests avec spécifications
- 🔀 **Contribuer au code** : Pull requests avec tests inclus
- 📝 **Améliorer la documentation** : Corrections et ajouts bienvenus

### Sécurité
- 🔒 **Signaler une vulnérabilité** : security@subbrute-project.org
- 🛡️ **Politique de sécurité** : [SECURITY.md](SECURITY.md)
- 🔐 **GPG Key** : Signature des releases officielles

---

**SubBrute Advanced GUI v2.1** - Interface professionnelle blindée pour l'énumération de sous-domaines avec recherche de propriétaires, export sophistiqué et fonctionnalités avancées.

*Développé avec ❤️ par l'équipe Enhanced SubBrute - Licence MIT*