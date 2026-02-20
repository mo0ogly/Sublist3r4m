"""Main entry point and CLI for JARVIS Intelligence."""
from __future__ import annotations

import argparse
import csv
import json
import os
import signal
import sys
import time
from datetime import datetime

from jarvis.enumerators import (
    CertificateTransparencyEnum,
    DNSBruteForceEnum,
    EnhancedGoogleEnum,
    PlaywrightGoogleEnum,
    SecurityTrailsEnum,
    ThreatCrowdEnum,
    VirusTotalEnum,
    WaybackMachineEnum,
)
from jarvis.logger import EnhancedLogger, colors
from jarvis.scanner import EnhancedPortScanner
from jarvis.security import SecurityValidator

# External modules with fallback handling
try:
    from subbrute import subbrute
except ImportError:
    subbrute = None

# Module-level globals
logger = None
security_validator = None


def initialize_globals(debug: bool = False, no_color: bool = False) -> None:
    """Initialise les instances globales."""
    global logger, security_validator

    try:
        if no_color:
            colors.disable()

        logger = EnhancedLogger(debug=debug)
        security_validator = SecurityValidator(logger)

        # Propagate globals to sub-modules that need them
        import jarvis.base as _base_mod
        _base_mod.set_globals(logger, security_validator)

        import jarvis.scanner as _scanner_mod
        _scanner_mod.set_globals(logger)

        logger.info("Global utilities initialized", module="Main")

    except Exception as e:
        print("CRITICAL: Failed to initialize globals: {}".format(str(e)))
        raise


def jarvis_banner() -> None:
    """Affiche le banner JARVIS avec bouclier et boussole."""
    banner_text = """{}{}
    \U0001f6e1\ufe0f                 _              _____   _____  \U0001f9ed
    \u2694\ufe0f               | |     /\\     |  __ \\ /  ___| \U0001f5e1\ufe0f
      \U0001f50d           | |    /  \\    | |__) |\\ `--.
                   | |   / /\\ \\   |  _  /  `--. \\
                  _| |_ / ____ \\  | | \\ \\ /\\__/ /
                 |_____/_/____\\_\\ |_|  \\_\\\\____/

    {}\U0001f6e1\ufe0f  JARVIS - Just Another Robust Vulnerability Intelligence System{}
    {}\U0001f9ed Advanced Intelligence & Security Analysis Platform v1.0{}

    {}\U0001f680 Professional Domain Intelligence & Configuration Analysis{}
    {}\U0001f512 Specialized in: AWS \u2022 Active Directory \u2022 Exchange \u2022 Linux{}
    {}\U0001f916 AI-Ready Intelligence Collection & Attribution Analysis{}
    {}\U0001f4ca Multi-Source Data Correlation \u2022 WHOIS \u2022 DNS \u2022 Certificates{}

    {}\u2696\ufe0f  Non-Commercial License \u2022 Created by m0ogly@proton.me{}
    {}\U0001f3af Cybersecurity Intelligence \u2022 Infrastructure Assessment{}

    """.format(
        colors.CYAN, colors.BOLD,
        colors.YELLOW, colors.WHITE,
        colors.GREEN, colors.WHITE,
        colors.BLUE, colors.WHITE,
        colors.MAGENTA, colors.WHITE,
        colors.RED, colors.WHITE,
        colors.CYAN, colors.WHITE,
        colors.DIM, colors.WHITE,
        colors.GREEN, colors.WHITE
    )

    print(banner_text)


def parser_error(errmsg: str) -> None:
    """Gestionnaire d'erreur personnalise pour argparse."""
    try:
        jarvis_banner()
        print("{}Usage: python {} [Options] use -h for help{}".format(
            colors.YELLOW, sys.argv[0], colors.WHITE))
        print("{}Error: {}{}".format(colors.RED, errmsg, colors.WHITE))

        if logger:
            logger.error("Argument parsing error", module="ArgumentParser", error=errmsg)

        sys.exit(1)

    except Exception as e:
        print("CRITICAL: Error in parser_error: {}".format(str(e)))
        sys.exit(1)


def enhanced_parse_args() -> argparse.Namespace:
    """Parser d'arguments ameliore avec validation."""
    try:
        parser = argparse.ArgumentParser(
            description="JARVIS Intelligence v1.0 - Professional Subdomain Enumeration Tool",
            epilog="Example: python {} -d google.com -v -o results.json --format json".format(sys.argv[0]),
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        parser.error = parser_error
        parser._optionals.title = "OPTIONS"

        # Options principales
        parser.add_argument('-d', '--domain',
                          help="Domain name to enumerate subdomains (required)",
                          required=True, metavar="DOMAIN")

        parser.add_argument('-b', '--bruteforce',
                          help='Enable subbrute bruteforce module',
                          action='store_true', default=False)

        parser.add_argument('-p', '--ports',
                          help='Scan found subdomains against specified TCP ports (comma-separated)',
                          metavar="PORTS")

        parser.add_argument('-v', '--verbose',
                          help='Enable verbose output with real-time results',
                          action='store_true', default=False)

        parser.add_argument('-t', '--threads',
                          help='Number of threads for bruteforce (default: 30)',
                          type=int, default=30, metavar="NUM")

        parser.add_argument('-e', '--engines',
                          help='Comma-separated list of search engines to use or preset: fast, complete, free, apis',
                          metavar="ENGINES")

        parser.add_argument('--preset',
                          help='Use predefined engine combinations: fast, complete, free, apis, exhaustive',
                          choices=['fast', 'complete', 'free', 'apis', 'exhaustive'],
                          metavar="PRESET")

        parser.add_argument('--extract-emails',
                          help='Extract emails from WHOIS and certificates',
                          action='store_true', default=False)

        parser.add_argument('--extract-owners',
                          help='Extract owner/organization information',
                          action='store_true', default=False)

        parser.add_argument('--stats-file',
                          help='Save detailed statistics to file',
                          metavar="FILE")

        parser.add_argument('--include-ips',
                          help='Include resolved IP addresses in output',
                          action='store_true', default=False)

        parser.add_argument('--intelligence',
                          help='Collect full domain intelligence for AI analysis (WHOIS, DNS, certificates, etc.)',
                          action='store_true', default=False)

        parser.add_argument('--ai-export',
                          help='Export data formatted for AI analysis',
                          metavar="FILE")

        # Options de sortie ameliorees
        parser.add_argument('-o', '--output',
                          help='Save results to file',
                          metavar="FILE")

        parser.add_argument('--format',
                          help='Output format: txt, csv, json, xml, html (default: txt)',
                          choices=['txt', 'csv', 'json', 'xml', 'html'],
                          default='txt')

        parser.add_argument('--no-color',
                          help='Disable colored output',
                          action='store_true', default=False)

        # Options avancees
        parser.add_argument('--timeout',
                          help='HTTP request timeout in seconds (default: 25)',
                          type=int, default=25, metavar="SECONDS")

        parser.add_argument('--delay',
                          help='Delay between requests in seconds (default: 0)',
                          type=float, default=0, metavar="SECONDS")

        parser.add_argument('--user-agent',
                          help='Custom User-Agent string',
                          metavar="AGENT")

        parser.add_argument('--debug',
                          help='Enable debug logging',
                          action='store_true', default=False)

        parser.add_argument('--silent',
                          help='Silent mode - only output results',
                          action='store_true', default=False)

        parser.add_argument('--statistics',
                          help='Show detailed statistics at the end',
                          action='store_true', default=False)

        parser.add_argument('--save-session',
                          help='Save session data for resuming',
                          action='store_true', default=False)

        parser.add_argument('--load-session',
                          help='Load previous session data',
                          metavar="SESSION_FILE")

        return parser.parse_args()

    except SystemExit:
        raise
    except Exception as e:
        print("{}CRITICAL: Failed to parse arguments: {}{}".format(colors.RED, str(e), colors.WHITE))
        if logger:
            logger.critical("Argument parsing failed", module="ArgumentParser", error=str(e))
        sys.exit(1)


def write_file_enhanced(
    filename: str,
    subdomains: list[str],
    output_format: str = 'txt',
    metadata: dict[str, object] | None = None,
) -> bool:
    """
    Ecriture de fichier amelioree avec support multi-formats.

    Args:
        filename: Nom du fichier de sortie
        subdomains: Liste des sous-domaines
        output_format: Format de sortie (txt, csv, json, xml, html)
        metadata: Metadonnees a inclure
    """
    try:
        if not subdomains:
            logger.warning("No subdomains to write", module="FileWriter")
            return False

        # Validation du chemin de fichier
        is_valid, safe_filename, error_msg = security_validator.validate_file_path(filename)
        if not is_valid:
            logger.error("Invalid output filename", module="FileWriter", error=error_msg)
            return False

        logger.info("Writing {} subdomains to {} format".format(len(subdomains), output_format.upper()),
                   module="FileWriter", filename=safe_filename)

        # Preparer les metadonnees par defaut
        default_metadata = {
            'timestamp': datetime.now().isoformat(),
            'total_subdomains': len(subdomains),
            'tool': 'JARVIS Intelligence v1.0',
            'format_version': '1.0'
        }

        if metadata:
            default_metadata.update(metadata)

        # Ecriture selon le format
        if output_format == 'txt':
            return _write_txt(safe_filename, subdomains)
        elif output_format == 'csv':
            return _write_csv(safe_filename, subdomains, default_metadata)
        elif output_format == 'json':
            return _write_json(safe_filename, subdomains, default_metadata)
        elif output_format == 'xml':
            return _write_xml(safe_filename, subdomains, default_metadata)
        elif output_format == 'html':
            return _write_html(safe_filename, subdomains, default_metadata)
        else:
            logger.error("Unsupported output format", module="FileWriter", format=output_format)
            return False

    except Exception as e:
        logger.error("File writing failed", module="FileWriter", error=str(e))
        return False


def _write_txt(filename, subdomains):
    """Ecriture au format texte."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for subdomain in subdomains:
                f.write(subdomain + os.linesep)
        return True
    except Exception as e:
        logger.error("TXT writing failed", module="FileWriter", error=str(e))
        return False


def _write_csv(filename, subdomains, metadata):
    """Ecriture au format CSV."""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # En-tetes avec metadonnees
            writer.writerow(['# JARVIS Intelligence Results'])
            writer.writerow(['# Generated:', metadata.get('timestamp', 'Unknown')])
            writer.writerow(['# Total Subdomains:', metadata.get('total_subdomains', 0)])
            writer.writerow([])  # Ligne vide

            # En-tetes des donnees
            writer.writerow(['Subdomain', 'Discovery_Time', 'Status'])

            # Donnees
            for subdomain in subdomains:
                writer.writerow([subdomain, datetime.now().strftime('%H:%M:%S'), 'Found'])

        return True
    except Exception as e:
        logger.error("CSV writing failed", module="FileWriter", error=str(e))
        return False


def _write_json(filename, subdomains, metadata):
    """Ecriture au format JSON."""
    try:
        data = {
            'metadata': metadata,
            'subdomains': [
                {
                    'domain': subdomain,
                    'discovered_at': datetime.now().isoformat(),
                    'status': 'active'
                }
                for subdomain in subdomains
            ]
        }

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        return True
    except Exception as e:
        logger.error("JSON writing failed", module="FileWriter", error=str(e))
        return False


def _write_xml(filename, subdomains, metadata):
    """Ecriture au format XML."""
    try:
        import xml.etree.ElementTree as ET

        # Creer la structure XML
        root = ET.Element('sublist3r_results', version='2.1')

        # Metadonnees
        meta_elem = ET.SubElement(root, 'metadata')
        for key, value in metadata.items():
            elem = ET.SubElement(meta_elem, key)
            elem.text = str(value)

        # Resultats
        results_elem = ET.SubElement(root, 'subdomains')
        for subdomain in subdomains:
            subdomain_elem = ET.SubElement(results_elem, 'subdomain')
            subdomain_elem.set('discovered_at', datetime.now().isoformat())
            subdomain_elem.text = subdomain

        # Ecriture avec indentation
        _indent_xml(root)
        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)

        return True
    except Exception as e:
        logger.error("XML writing failed", module="FileWriter", error=str(e))
        return False


def _write_html(filename, subdomains, metadata):
    """Ecriture au format HTML."""
    try:
        html_template = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JARVIS Intelligence Results</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                   color: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; }}
        .metadata {{ background: white; padding: 15px; border-radius: 5px; margin-bottom: 20px;
                     box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        .results {{ background: white; border-radius: 5px; overflow: hidden;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background-color: #4CAF50; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 12px; border-bottom: 1px solid #ddd; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        tr:hover {{ background-color: #e8f5e8; }}
        .count {{ font-size: 24px; font-weight: bold; color: #4CAF50; }}
        .footer {{ text-align: center; margin-top: 20px; color: #666; }}
        .search-box {{ margin: 20px 0; }}
        .search-box input {{ padding: 10px; width: 300px; border: 1px solid #ddd; border-radius: 5px; }}
    </style>
    <script>
        function searchSubdomains() {{
            var input = document.getElementById('searchInput');
            var filter = input.value.toUpperCase();
            var table = document.getElementById('subdomainsTable');
            var rows = table.getElementsByTagName('tr');

            for (var i = 1; i < rows.length; i++) {{
                var cell = rows[i].getElementsByTagName('td')[0];
                if (cell) {{
                    var textValue = cell.textContent || cell.innerText;
                    if (textValue.toUpperCase().indexOf(filter) > -1) {{
                        rows[i].style.display = '';
                    }} else {{
                        rows[i].style.display = 'none';
                    }}
                }}
            }}
        }}
    </script>
</head>
<body>
    <div class="header">
        <h1>JARVIS Intelligence Results</h1>
        <p>Professional Subdomain Enumeration Report</p>
    </div>

    <div class="metadata">
        <h2>Metadata</h2>
        <p><strong>Generated:</strong> {timestamp}</p>
        <p><strong>Total Subdomains:</strong> <span class="count">{total_subdomains}</span></p>
        <p><strong>Tool:</strong> {tool}</p>
    </div>

    <div class="search-box">
        <input type="text" id="searchInput" onkeyup="searchSubdomains()"
               placeholder="Search subdomains...">
    </div>

    <div class="results">
        <table id="subdomainsTable">
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>Discovery Time</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
    </div>

    <div class="footer">
        <p>Generated by <strong>JARVIS Intelligence v1.0</strong> - Enhanced Security Edition</p>
        <p>Original tool by Ahmed Aboul-Ela - Enhanced by Security Team</p>
    </div>
</body>
</html>"""

        # Generer les lignes du tableau
        table_rows = ""
        discovery_time = datetime.now().strftime('%H:%M:%S')

        for subdomain in subdomains:
            table_rows += "<tr><td>{}</td><td>{}</td><td>Active</td></tr>\\n".format(
                subdomain, discovery_time)

        # Remplacer les variables dans le template
        html_content = html_template.format(
            timestamp=metadata.get('timestamp', 'Unknown'),
            total_subdomains=metadata.get('total_subdomains', 0),
            tool=metadata.get('tool', 'JARVIS Intelligence'),
            table_rows=table_rows
        )

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return True
    except Exception as e:
        logger.error("HTML writing failed", module="FileWriter", error=str(e))
        return False


def _indent_xml(elem, level=0):
    """Indente le XML pour un affichage lisible."""
    try:
        i = "\\n" + level * "  "
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = i + "  "
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
            for elem in elem:
                _indent_xml(elem, level + 1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i
    except Exception:
        pass  # Continue even if indentation fails


def subdomain_sorting_key_enhanced(hostname: str) -> tuple[list[str], int] | tuple[list[str], int, str]:
    """
    Cle de tri amelioree pour les sous-domaines.

    Trie par:
    1. Domaine de droite a gauche
    2. 'www' en premier dans chaque groupe
    3. Ordre alphabetique pour les autres
    """
    try:
        if not hostname or not isinstance(hostname, str):
            return ([], 999)  # Mettre les entrees invalides a la fin

        parts = hostname.lower().split('.')[::-1]  # Inverser pour trier de droite a gauche

        # Prioriser 'www' dans chaque niveau
        if len(parts) > 1 and parts[-1] == 'www':
            return (parts[:-1], 0, parts[-1])  # 'www' en premier

        return (parts, 1, '')  # Autres sous-domaines apres 'www'

    except Exception as e:
        logger.error("Sorting key generation failed", module="Sorting", hostname=hostname, error=str(e))
        return ([], 999)  # Fallback pour les erreurs


def enhanced_main(domain: str, threads: int = 30, output_file: str | None = None, output_format: str = 'txt',
                 ports: str | None = None, silent: bool = False, verbose: bool = True, enable_bruteforce: bool = True,
                 engines: str | None = None, timeout: int = 25, delay: int = 0, user_agent: str | None = None,
                 statistics: bool = False, debug: bool = False, extract_emails: bool = False,
                 extract_owners: bool = False, stats_file: str | None = None, include_ips: bool = False,
                 intelligence: bool = False, ai_export: str | None = None) -> list[str]:
    """
    Fonction principale amelioree de JARVIS Intelligence.

    Args:
        domain: Domaine cible
        threads: Nombre de threads pour le bruteforce
        output_file: Fichier de sortie
        output_format: Format de sortie
        ports: Liste de ports a scanner
        silent: Mode silencieux
        verbose: Mode verbose
        enable_bruteforce: Activer le bruteforce
        engines: Moteurs de recherche a utiliser
        timeout: Timeout des requetes
        delay: Delai entre les requetes
        user_agent: User-Agent personnalise
        statistics: Afficher les statistiques
        debug: Mode debug

    Returns:
        list: Liste des sous-domaines trouves
    """
    try:
        # Initialiser les variables globales
        initialize_globals(debug=debug, no_color=silent)

        logger.info("Starting JARVIS Intelligence", module="Main", domain=domain)

        # Validation du domaine
        is_valid, clean_domain, error_msg = security_validator.validate_domain(domain)
        if not is_valid:
            error_text = "{}Domain validation failed: {}{}".format(colors.RED, error_msg, colors.WHITE)
            if not silent:
                print(error_text)
            logger.error("Domain validation failed", module="Main", domain=domain, error=error_msg)
            return []

        # Validation des ports si specifies
        port_list = []
        if ports:
            is_valid_ports, port_list, port_error = security_validator.validate_port_list(ports)
            if not is_valid_ports:
                error_text = "{}Port validation failed: {}{}".format(colors.RED, port_error, colors.WHITE)
                if not silent:
                    print(error_text)
                logger.error("Port validation failed", module="Main", ports=ports, error=port_error)
                return []

        # Affichage des informations
        if not silent:
            print("{}{}Target Domain: {}{}{}".format(
                colors.BLUE, colors.BOLD, colors.WHITE,
                clean_domain, colors.WHITE))
            if verbose:
                print("{}Verbose mode enabled - showing real-time results{}".format(colors.YELLOW, colors.WHITE))
            if enable_bruteforce:
                print("{}Bruteforce module enabled{}".format(colors.GREEN, colors.WHITE))
            if port_list:
                print("{}Port scanning enabled for {} ports{}".format(colors.CYAN, len(port_list), colors.WHITE))

        # Structures de donnees pour les resultats
        search_results = set()
        bruteforce_results = set()
        all_subdomains = set()

        # Metriques globales
        global_metrics = {
            'start_time': time.time(),
            'engines_used': [],
            'total_requests': 0,
            'total_errors': 0,
            'bruteforce_enabled': enable_bruteforce,
            'port_scan_enabled': bool(port_list)
        }

        # Configuration des moteurs de recherche
        available_engines = {
            'google': PlaywrightGoogleEnum,
            'google-simple': EnhancedGoogleEnum,  # Version simple sans Playwright
            'crt': CertificateTransparencyEnum,  # Certificate Transparency (gratuit)
            'securitytrails': SecurityTrailsEnum,  # SecurityTrails API (cle requise)
            'virustotal': VirusTotalEnum,  # VirusTotal API (cle requise)
            'dns': DNSBruteForceEnum,  # DNS Brute Force (gratuit)
            'wayback': WaybackMachineEnum,  # Archives web (gratuit)
            'threatcrowd': ThreatCrowdEnum,  # Threat intelligence (gratuit)
        }

        selected_engines = []
        if engines:
            engine_names = [name.strip().lower() for name in engines.split(',')]
            for engine_name in engine_names:
                if engine_name in available_engines:
                    selected_engines.append((engine_name, available_engines[engine_name]))
                else:
                    logger.warning("Unknown engine ignored", module="Main", engine=engine_name)
        else:
            # Utiliser tous les moteurs disponibles par defaut
            selected_engines = list(available_engines.items())

        if not selected_engines:
            logger.warning("No valid engines selected, using default", module="Main")
            selected_engines = [('crt', CertificateTransparencyEnum)]

        # Enumeration avec les moteurs de recherche
        if not silent:
            print("{}Starting enumeration with {} engines{}".format(
                colors.GREEN, len(selected_engines), colors.WHITE))

        engine_results = {}
        for engine_name, engine_class in selected_engines:
            try:
                if not silent:
                    print("{}Processing with {} engine{}".format(colors.BLUE, engine_name.title(), colors.WHITE))

                # Initialiser l'enumerateur
                enumerator = engine_class(
                    clean_domain,
                    silent=silent,
                    verbose=verbose,
                    timeout=timeout,
                    delay=delay,
                    user_agent=user_agent
                )

                # Executer l'enumeration
                engine_subdomains = enumerator.enumerate()
                engine_results[engine_name] = {
                    'subdomains': engine_subdomains,
                    'metrics': enumerator.get_metrics()
                }

                # Ajouter aux resultats de recherche
                search_results.update(engine_subdomains)

                # Mettre a jour les metriques globales
                global_metrics['engines_used'].append(engine_name)
                global_metrics['total_requests'] += enumerator.metrics['requests_sent']
                global_metrics['total_errors'] += enumerator.metrics['requests_failed']

                logger.info("Engine completed", module="Main", engine=engine_name,
                          found=len(engine_subdomains))

            except Exception as e:
                logger.error("Engine failed", module="Main", engine=engine_name, error=str(e))
                continue

        # Bruteforce avec SubBrute si active
        if enable_bruteforce and subbrute:
            try:
                if not silent:
                    print("{}Starting bruteforce module{}".format(colors.GREEN, colors.WHITE))

                # Configuration du bruteforce
                record_type = False  # Utiliser le type par defaut
                path_to_file = os.path.dirname(os.path.realpath(__file__))
                # Go up one level from jarvis/ to the project root
                project_root = os.path.dirname(path_to_file)
                subs_file = os.path.join(project_root, 'subbrute', 'names.txt')
                resolvers_file = os.path.join(project_root, 'subbrute', 'resolvers.txt')

                # Verifier l'existence des fichiers
                if not os.path.exists(subs_file):
                    logger.warning("Subdomains file not found", module="Main", file=subs_file)
                if not os.path.exists(resolvers_file):
                    logger.warning("Resolvers file not found", module="Main", file=resolvers_file)

                if os.path.exists(subs_file) and os.path.exists(resolvers_file):
                    # Executer le bruteforce
                    bf_results = subbrute.print_target(
                        clean_domain, record_type, subs_file, resolvers_file,
                        threads, False, False, list(search_results), verbose
                    )

                    if bf_results:
                        bruteforce_results.update(bf_results)
                        logger.info("Bruteforce completed", module="Main", found=len(bf_results))
                else:
                    logger.warning("Bruteforce skipped due to missing files", module="Main")

            except Exception as e:
                logger.error("Bruteforce failed", module="Main", error=str(e))

        # Combiner tous les resultats
        all_subdomains.update(search_results)
        all_subdomains.update(bruteforce_results)

        # Trier les resultats
        final_subdomains = sorted(list(all_subdomains), key=subdomain_sorting_key_enhanced)

        # Affichage des resultats
        if not silent:
            print("{}{}Total unique subdomains found: {}{}{}".format(
                colors.GREEN, colors.BOLD, len(final_subdomains), colors.WHITE, colors.WHITE))

            if not verbose:  # Si pas verbose, afficher tous les resultats maintenant
                for subdomain in final_subdomains:
                    print("{}{}{}".format(colors.GREEN, subdomain, colors.WHITE))

        # Sauvegarde des resultats
        if output_file:
            try:
                # Preparer les metadonnees
                metadata = {
                    'target_domain': clean_domain,
                    'enumeration_time': datetime.now().isoformat(),
                    'total_subdomains': len(final_subdomains),
                    'search_results': len(search_results),
                    'bruteforce_results': len(bruteforce_results),
                    'engines_used': global_metrics['engines_used'],
                    'tool_version': 'JARVIS Intelligence v1.0'
                }

                success = write_file_enhanced(output_file, final_subdomains, output_format, metadata)
                if success and not silent:
                    print("{}Results saved to: {}{}{}".format(colors.BLUE, colors.WHITE, output_file, colors.WHITE))

            except Exception as e:
                logger.error("Failed to save results", module="Main", error=str(e))
                if not silent:
                    print("{}Error saving results: {}{}".format(colors.RED, str(e), colors.WHITE))

        # Scanner de ports
        if port_list and final_subdomains:
            try:
                if not silent:
                    print("{}Starting port scan on {} subdomains{}".format(
                        colors.CYAN, len(final_subdomains), colors.WHITE))

                port_scanner = EnhancedPortScanner(
                    final_subdomains, port_list, max_threads=min(threads, 50)
                )
                port_results = port_scanner.run()

                # Sauvegarder les resultats de port si demande
                if output_file and port_results:
                    port_file = output_file.rsplit('.', 1)[0] + '_ports.' + output_format
                    port_data = []
                    for host, ports_found in port_results.items():
                        port_data.append("{}:{}".format(host, ','.join(map(str, ports_found))))

                    write_file_enhanced(port_file, port_data, output_format, {
                        'scan_type': 'port_scan',
                        'total_hosts': len(final_subdomains),
                        'hosts_with_open_ports': len(port_results)
                    })

            except Exception as e:
                logger.error("Port scan failed", module="Main", error=str(e))

        # Statistiques finales
        global_metrics['end_time'] = time.time()
        global_metrics['total_time'] = global_metrics['end_time'] - global_metrics['start_time']
        global_metrics['subdomains_found'] = len(final_subdomains)

        if statistics and not silent:
            print_statistics(global_metrics, engine_results)

        logger.info("Enumeration completed successfully", module="Main",
                   total_found=len(final_subdomains),
                   time_elapsed=global_metrics['total_time'])

        return final_subdomains

    except KeyboardInterrupt:
        if not silent:
            print("{}\\nEnumeration interrupted by user{}".format(colors.YELLOW, colors.WHITE))
        logger.warning("Enumeration interrupted by user", module="Main")
        return []

    except Exception as e:
        error_text = "{}Critical error in main execution: {}{}".format(colors.RED, str(e), colors.WHITE)
        if not silent:
            print(error_text)
        logger.critical("Main execution failed", module="Main", error=str(e))
        return []


def print_statistics(global_metrics: dict[str, object], engine_results: dict[str, dict[str, object]]) -> None:
    """Affiche les statistiques detaillees."""
    try:
        print("\\n{}{}=== DETAILED STATISTICS ==={}".format(colors.CYAN, colors.BOLD, colors.WHITE))

        # Statistiques globales
        print("{}Global Metrics:{}".format(colors.YELLOW, colors.WHITE))
        print("  \u2022 Total execution time: {:.2f} seconds".format(global_metrics['total_time']))
        print("  \u2022 Subdomains found: {}".format(global_metrics['subdomains_found']))
        print("  \u2022 Total HTTP requests: {}".format(global_metrics['total_requests']))
        print("  \u2022 Total errors: {}".format(global_metrics['total_errors']))

        if global_metrics['total_requests'] > 0:
            success_rate = ((global_metrics['total_requests'] - global_metrics['total_errors']) /
                          global_metrics['total_requests']) * 100
            print("  \u2022 Success rate: {:.1f}%".format(success_rate))

        # Statistiques par moteur
        if engine_results:
            print("\\n{}Engine Performance:{}".format(colors.YELLOW, colors.WHITE))
            for engine_name, results in engine_results.items():
                metrics = results['metrics']
                subdomains = results['subdomains']

                print("  {}{}:{}".format(colors.GREEN, engine_name.title(), colors.WHITE))
                print("    - Subdomains found: {}".format(len(subdomains)))
                print("    - Requests sent: {}".format(metrics.get('requests_sent', 0)))
                print("    - Success rate: {:.1f}%".format(metrics.get('success_rate', 0) * 100))
                print("    - Requests/second: {:.2f}".format(metrics.get('requests_per_second', 0)))

                if metrics.get('timeouts', 0) > 0:
                    print("    - Timeouts: {}".format(metrics['timeouts']))
                if metrics.get('rate_limited', 0) > 0:
                    print("    - Rate limited: {}".format(metrics['rate_limited']))

        print("{}{}================================\\n{}".format(colors.CYAN, colors.BOLD, colors.WHITE))

    except Exception as e:
        logger.error("Statistics display failed", module="Statistics", error=str(e))


def interactive_enhanced() -> list[str] | None:
    """Mode interactif ameliore avec gestion d'erreurs complete."""
    try:
        # Parser les arguments
        args = enhanced_parse_args()

        # Initialiser les globals avec les parametres
        initialize_globals(debug=args.debug, no_color=args.no_color)

        # Afficher le banner
        if not args.silent:
            jarvis_banner()

        # Gestionnaire de signal pour interruption propre
        def signal_handler(signum, frame):
            if not args.silent:
                print("\\n{}Received interrupt signal, cleaning up...{}".format(colors.YELLOW, colors.WHITE))
            logger.info("Received interrupt signal", module="Main", signal=signum)
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)

        # Validation des arguments supplementaire
        if args.threads < 1 or args.threads > 100:
            logger.warning("Thread count adjusted", module="Main",
                         original=args.threads, adjusted=max(1, min(args.threads, 100)))
            args.threads = max(1, min(args.threads, 100))

        if args.timeout < 5:
            logger.warning("Timeout adjusted to minimum", module="Main",
                         original=args.timeout, adjusted=5)
            args.timeout = 5

        # Traiter les presets d'engines
        if args.preset:
            engine_presets = {
                'fast': 'crt,dns',  # Rapide et efficace (gratuit)
                'complete': 'crt,dns,google,wayback,threatcrowd',  # Complet avec nouveaux moteurs
                'free': 'crt,dns,wayback,threatcrowd',  # Tous les moteurs gratuits
                'apis': 'crt,dns,wayback,threatcrowd,virustotal,securitytrails',  # Avec APIs
                'exhaustive': 'crt,dns,google,wayback,threatcrowd,virustotal,securitytrails'  # Tout
            }

            if args.preset in engine_presets:
                args.engines = engine_presets[args.preset]
                if not args.silent:
                    print("{}Using preset '{}': {}{}".format(
                        colors.CYAN, args.preset, args.engines, colors.WHITE))

        # Si aucun engine specifie, utiliser le preset 'free' par defaut
        if not args.engines and not args.preset:
            args.engines = 'crt,dns,wayback,threatcrowd'
            if not args.silent:
                print("{}Using default engines (free): {}{}".format(
                    colors.CYAN, args.engines, colors.WHITE))

        # Executer l'enumeration principale
        results = enhanced_main(
            domain=args.domain,
            threads=args.threads,
            output_file=args.output,
            output_format=args.format,
            ports=args.ports,
            silent=args.silent,
            verbose=args.verbose,
            enable_bruteforce=args.bruteforce,
            engines=args.engines,
            timeout=args.timeout,
            delay=args.delay,
            user_agent=args.user_agent,
            statistics=args.statistics,
            debug=args.debug,
            extract_emails=getattr(args, 'extract_emails', False),
            extract_owners=getattr(args, 'extract_owners', False),
            stats_file=getattr(args, 'stats_file', None),
            include_ips=getattr(args, 'include_ips', False),
            intelligence=getattr(args, 'intelligence', False),
            ai_export=getattr(args, 'ai_export', None)
        )

        # Resume final
        if not args.silent:
            if results:
                print("{}\\nEnumeration completed successfully with {} subdomains{}".format(
                    colors.GREEN, len(results), colors.WHITE))
            else:
                print("{}\\nNo subdomains found{}".format(colors.YELLOW, colors.WHITE))

        # Logs de metriques finales
        if logger:
            final_metrics = logger.get_metrics()
            logger.success("Session completed", module="Main",
                         subdomains_found=len(results),
                         total_logs=final_metrics.get('total_messages', 0),
                         errors=final_metrics.get('errors_count', 0))

        return results

    except SystemExit:
        # Exit normal, ne pas traiter comme une erreur
        return []
    except KeyboardInterrupt:
        if logger:
            logger.warning("Interactive session interrupted", module="Main")
        return []
    except Exception as e:
        error_text = "{}CRITICAL ERROR in interactive mode: {}{}".format(colors.RED, str(e), colors.WHITE)
        print(error_text)
        if logger:
            logger.critical("Interactive mode failed", module="Main", error=str(e))
        return []


if __name__ == "__main__":
    try:
        # Verifier la version Python
        if sys.version_info < (2, 7):
            print("Error: Python 2.7 or higher required")
            sys.exit(1)

        # Lancer le mode interactif ameliore
        interactive_enhanced()

    except Exception as e:
        print("FATAL ERROR: {}".format(str(e)))
        sys.exit(1)
