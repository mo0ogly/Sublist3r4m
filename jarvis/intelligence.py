"""Domain intelligence collection for JARVIS Intelligence."""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime


class DomainIntelligenceCollector:
    """
    Collecteur d'intelligence complet pour analyse de proprietaires par IA
    """

    def __init__(self, logger: logging.Logger | None = None) -> None:
        """Initialize the domain intelligence collector.

        Args:
            logger: Logger instance, or None to use the default module logger.
        """
        self.logger = logger or logging.getLogger(__name__)
        self.intelligence_data = {
            'target_domain': '',
            'collection_timestamp': datetime.now().isoformat(),
            'subdomains': {},
            'whois_data': {},
            'certificates': [],
            'dns_records': {},
            'network_info': {},
            'owner_analysis': {
                'detected_owners': [],
                'confidence_scores': {},
                'attribution_sources': {},
                'potential_conflicts': []
            },
            'security_context': {
                'ssl_issuers': [],
                'dns_providers': [],
                'hosting_providers': [],
                'email_domains': [],
                'suspicious_patterns': []
            }
        }

    def collect_subdomain_intelligence(self, subdomain):
        """Collecte toutes les informations d'un sous-domaine"""
        try:
            self.logger.info("Collecting intelligence", module="DomainIntel", subdomain=subdomain)

            subdomain_data = {
                'domain': subdomain,
                'discovered_at': datetime.now().isoformat(),
                'whois': {},
                'dns': {},
                'certificates': [],
                'network': {},
                'ownership_indicators': {}
            }

            # Collecte WHOIS
            whois_data = self._collect_whois(subdomain)
            if whois_data:
                subdomain_data['whois'] = whois_data
                self._extract_ownership_from_whois(subdomain, whois_data)

            # Collecte DNS
            dns_data = self._collect_dns_records(subdomain)
            if dns_data:
                subdomain_data['dns'] = dns_data
                self._analyze_dns_patterns(subdomain, dns_data)

            # Resolution IP et info reseau
            network_data = self._collect_network_info(subdomain)
            if network_data:
                subdomain_data['network'] = network_data
                self._analyze_hosting_patterns(subdomain, network_data)

            self.intelligence_data['subdomains'][subdomain] = subdomain_data

        except Exception as e:
            self.logger.error("Intelligence collection failed", module="DomainIntel",
                            subdomain=subdomain, error=str(e))

    def _collect_whois(self, domain):
        """Collecte les donnees WHOIS completes"""
        try:
            import whois

            w = whois.whois(domain)
            if not w:
                return None

            whois_data = {
                'registrar': getattr(w, 'registrar', None),
                'registrant': getattr(w, 'registrant', None),
                'admin': getattr(w, 'admin', None),
                'tech': getattr(w, 'tech', None),
                'emails': [],
                'organization': getattr(w, 'org', None),
                'country': getattr(w, 'country', None),
                'creation_date': str(getattr(w, 'creation_date', None)),
                'expiration_date': str(getattr(w, 'expiration_date', None)),
                'name_servers': getattr(w, 'name_servers', []),
                'status': getattr(w, 'status', [])
            }

            # Extraire tous les emails
            email_fields = ['emails', 'registrant_email', 'admin_email', 'tech_email']
            for field in email_fields:
                if hasattr(w, field):
                    emails = getattr(w, field)
                    if emails:
                        if isinstance(emails, list):
                            whois_data['emails'].extend(emails)
                        else:
                            whois_data['emails'].append(emails)

            # Nettoyer les emails
            whois_data['emails'] = list(set([str(e).lower() for e in whois_data['emails'] if e and '@' in str(e)]))

            return whois_data

        except ImportError:
            self.logger.warning("python-whois not available", module="DomainIntel")
            return None
        except Exception as e:
            self.logger.debug("WHOIS collection failed", module="DomainIntel", domain=domain, error=str(e))
            return None

    def _collect_dns_records(self, domain):
        """Collecte les enregistrements DNS"""
        try:
            import socket
            import subprocess

            dns_data = {
                'a_records': [],
                'aaaa_records': [],
                'mx_records': [],
                'ns_records': [],
                'txt_records': [],
                'cname_records': []
            }

            # A records (IPv4)
            try:
                ips = socket.gethostbyname_ex(domain)[2]
                dns_data['a_records'] = ips
            except Exception:
                pass

            # Utiliser dig si disponible pour plus d'infos
            try:
                # MX records
                result = subprocess.run(['dig', '+short', 'MX', domain],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    dns_data['mx_records'] = [line.strip() for line in result.stdout.split('\n') if line.strip()]

                # NS records
                result = subprocess.run(['dig', '+short', 'NS', domain],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    dns_data['ns_records'] = [line.strip() for line in result.stdout.split('\n') if line.strip()]

                # TXT records
                result = subprocess.run(['dig', '+short', 'TXT', domain],
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    dns_data['txt_records'] = [line.strip() for line in result.stdout.split('\n') if line.strip()]

            except Exception as e:
                self.logger.debug("dig command failed", module="DomainIntel", error=str(e))

            return dns_data

        except Exception as e:
            self.logger.debug("DNS collection failed", module="DomainIntel", domain=domain, error=str(e))
            return None

    def _collect_network_info(self, domain):
        """Collecte les informations reseau et geolocalisation"""
        try:
            import socket

            import requests

            network_data = {
                'ips': [],
                'geolocation': {},
                'asn': {},
                'hosting_provider': None,
                'cloud_provider': None
            }

            # Resoudre l'IP
            try:
                ip = socket.gethostbyname(domain)
                network_data['ips'].append(ip)

                # Geolocalisation via ipapi (gratuit)
                try:
                    response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
                    if response.status_code == 200:
                        geo_data = response.json()
                        network_data['geolocation'] = {
                            'country': geo_data.get('country'),
                            'region': geo_data.get('regionName'),
                            'city': geo_data.get('city'),
                            'isp': geo_data.get('isp'),
                            'org': geo_data.get('org'),
                            'as': geo_data.get('as')
                        }

                        # Detecter les fournisseurs cloud
                        org = geo_data.get('org', '').lower()
                        if 'amazon' in org or 'aws' in org:
                            network_data['cloud_provider'] = 'AWS'
                        elif 'google' in org or 'gcp' in org:
                            network_data['cloud_provider'] = 'Google Cloud'
                        elif 'microsoft' in org or 'azure' in org:
                            network_data['cloud_provider'] = 'Azure'
                        elif 'cloudflare' in org:
                            network_data['cloud_provider'] = 'Cloudflare'

                        network_data['hosting_provider'] = geo_data.get('org')

                except Exception as e:
                    self.logger.debug("Geolocation failed", module="DomainIntel", error=str(e))

            except Exception as e:
                self.logger.debug("IP resolution failed", module="DomainIntel", domain=domain, error=str(e))

            return network_data

        except Exception as e:
            self.logger.debug("Network info collection failed", module="DomainIntel", error=str(e))
            return None

    def _extract_ownership_from_whois(self, domain, whois_data):
        """Extrait les indicateurs de propriete depuis WHOIS"""
        try:
            # Ajouter aux donnees d'analyse de propriete
            for email in whois_data.get('emails', []):
                if email not in self.intelligence_data['owner_analysis']['detected_owners']:
                    self.intelligence_data['owner_analysis']['detected_owners'].append({
                        'type': 'email',
                        'value': email,
                        'source': f'whois:{domain}',
                        'confidence': 0.8
                    })

            if whois_data.get('organization'):
                org = whois_data.get('organization')
                self.intelligence_data['owner_analysis']['detected_owners'].append({
                    'type': 'organization',
                    'value': org,
                    'source': f'whois:{domain}',
                    'confidence': 0.9
                })

        except Exception as e:
            self.logger.debug("Ownership extraction failed", module="DomainIntel", error=str(e))

    def _analyze_dns_patterns(self, domain, dns_data):
        """Analyse les patterns DNS pour l'attribution"""
        try:
            # Analyser les serveurs de noms
            for ns in dns_data.get('ns_records', []):
                if 'cloudflare' in ns.lower():
                    self.intelligence_data['security_context']['dns_providers'].append('Cloudflare')
                elif 'godaddy' in ns.lower():
                    self.intelligence_data['security_context']['dns_providers'].append('GoDaddy')
                elif 'google' in ns.lower():
                    self.intelligence_data['security_context']['dns_providers'].append('Google')

            # Analyser les enregistrements TXT pour des patterns de propriete
            for txt in dns_data.get('txt_records', []):
                if 'google-site-verification' in txt:
                    self.intelligence_data['owner_analysis']['detected_owners'].append({
                        'type': 'google_verification',
                        'value': txt,
                        'source': f'dns:{domain}',
                        'confidence': 0.7
                    })
                elif 'facebook-domain-verification' in txt:
                    self.intelligence_data['owner_analysis']['detected_owners'].append({
                        'type': 'facebook_verification',
                        'value': txt,
                        'source': f'dns:{domain}',
                        'confidence': 0.7
                    })

        except Exception as e:
            self.logger.debug("DNS pattern analysis failed", module="DomainIntel", error=str(e))

    def _analyze_hosting_patterns(self, domain, network_data):
        """Analyse les patterns d'hebergement"""
        try:
            hosting_provider = network_data.get('hosting_provider')
            cloud_provider = network_data.get('cloud_provider')

            if hosting_provider:
                self.intelligence_data['security_context']['hosting_providers'].append(hosting_provider)

            if cloud_provider:
                self.intelligence_data['owner_analysis']['detected_owners'].append({
                    'type': 'cloud_provider',
                    'value': cloud_provider,
                    'source': f'network:{domain}',
                    'confidence': 0.6
                })

        except Exception as e:
            self.logger.debug("Hosting pattern analysis failed", module="DomainIntel", error=str(e))

    def add_certificate_data(self, cert_data):
        """Ajoute les donnees de certificats a l'analyse"""
        try:
            for cert in cert_data:
                cert_info = {
                    'common_name': cert.get('common_name'),
                    'issuer': cert.get('issuer_name'),
                    'subject': cert.get('subject'),
                    'not_before': cert.get('not_before'),
                    'not_after': cert.get('not_after')
                }

                self.intelligence_data['certificates'].append(cert_info)

                # Extraire les emetteurs SSL
                issuer = cert.get('issuer_name', '')
                if issuer:
                    self.intelligence_data['security_context']['ssl_issuers'].append(issuer)

                    # Patterns d'emetteurs connus
                    if 'Let\'s Encrypt' in issuer:
                        self.intelligence_data['owner_analysis']['detected_owners'].append({
                            'type': 'ssl_issuer',
                            'value': 'Let\'s Encrypt (Automated)',
                            'source': f'certificate:{cert.get("common_name")}',
                            'confidence': 0.5
                        })
                    elif 'DigiCert' in issuer:
                        self.intelligence_data['owner_analysis']['detected_owners'].append({
                            'type': 'ssl_issuer',
                            'value': 'DigiCert (Commercial)',
                            'source': f'certificate:{cert.get("common_name")}',
                            'confidence': 0.6
                        })

        except Exception as e:
            self.logger.debug("Certificate analysis failed", module="DomainIntel", error=str(e))

    def analyze_ownership_patterns(self):
        """Analyse finale pour detecter les patterns de propriete"""
        try:
            # Grouper par type d'indicateur
            owners_by_type = {}
            for owner in self.intelligence_data['owner_analysis']['detected_owners']:
                owner_type = owner['type']
                if owner_type not in owners_by_type:
                    owners_by_type[owner_type] = []
                owners_by_type[owner_type].append(owner)

            # Calculer les scores de confiance
            email_domains = set()
            for owner in owners_by_type.get('email', []):
                domain = owner['value'].split('@')[1] if '@' in owner['value'] else None
                if domain:
                    email_domains.add(domain)

            # Detecter les conflits potentiels
            if len(email_domains) > 3:
                self.intelligence_data['owner_analysis']['potential_conflicts'].append({
                    'type': 'multiple_email_domains',
                    'description': f'Multiple email domains detected: {list(email_domains)}',
                    'severity': 'medium'
                })

            # Analyser la coherence des organisations
            orgs = [o['value'] for o in owners_by_type.get('organization', [])]
            if len(set(orgs)) > 2:
                self.intelligence_data['owner_analysis']['potential_conflicts'].append({
                    'type': 'multiple_organizations',
                    'description': f'Multiple organizations detected: {orgs}',
                    'severity': 'high'
                })

            self.logger.info("Ownership analysis completed", module="DomainIntel",
                           owners_found=len(self.intelligence_data['owner_analysis']['detected_owners']),
                           conflicts=len(self.intelligence_data['owner_analysis']['potential_conflicts']))

        except Exception as e:
            self.logger.error("Ownership pattern analysis failed", module="DomainIntel", error=str(e))

    def export_for_ai_analysis(self, filename):
        """Exporte les donnees formatees pour l'analyse IA"""
        try:
            import json

            # Finaliser l'analyse
            self.analyze_ownership_patterns()

            # Structurer les donnees pour l'IA
            ai_data = {
                'metadata': {
                    'target_domain': self.intelligence_data['target_domain'],
                    'collection_timestamp': self.intelligence_data['collection_timestamp'],
                    'total_subdomains': len(self.intelligence_data['subdomains']),
                    'total_owners_detected': len(self.intelligence_data['owner_analysis']['detected_owners']),
                    'potential_conflicts': len(self.intelligence_data['owner_analysis']['potential_conflicts'])
                },
                'raw_intelligence': self.intelligence_data,
                'ai_analysis_prompts': {
                    'ownership_verification': (
                        "Analyze the collected data to verify domain "
                        "ownership attribution. Look for consistency "
                        "patterns in emails, organizations, registrars, "
                        "and technical contacts."
                    ),
                    'security_assessment': (
                        "Evaluate security posture based on SSL "
                        "certificates, DNS configuration, and "
                        "hosting patterns."
                    ),
                    'anomaly_detection': (
                        "Identify potential security threats, "
                        "suspicious patterns, or ownership "
                        "discrepancies."
                    ),
                }
            }

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(ai_data, f, indent=2, ensure_ascii=False)

            owner_analysis = self.intelligence_data['owner_analysis']
            total_ind = len(owner_analysis['detected_owners'])
            self.logger.info(
                "AI analysis data exported", module="DomainIntel",
                filename=filename, total_indicators=total_ind
            )

            return ai_data

        except Exception as e:
            self.logger.error("AI export failed", module="DomainIntel", error=str(e))
            return None


class EmailExtractor:
    """
    Extracteur d'emails depuis WHOIS et certificats
    """

    def __init__(self, logger: logging.Logger | None = None) -> None:
        """Initialize the email and organization extractor.

        Args:
            logger: Logger instance, or None to use the default module logger.
        """
        self.logger = logger or logging.getLogger(__name__)
        self.emails = set()
        self.organizations = set()

    def extract_from_whois(self, domain):
        """Extrait emails et organisations depuis WHOIS"""
        try:
            import whois

            self.logger.info("Querying WHOIS", module="EmailExtractor", domain=domain)

            w = whois.whois(domain)
            if w:
                # Extraire les emails
                emails = []
                if hasattr(w, 'emails') and w.emails:
                    if isinstance(w.emails, list):
                        emails.extend(w.emails)
                    else:
                        emails.append(w.emails)

                # Extraire depuis les champs texte
                for field in ['registrant_email', 'admin_email', 'tech_email']:
                    if hasattr(w, field) and getattr(w, field):
                        emails.append(getattr(w, field))

                # Nettoyer et valider les emails
                for email in emails:
                    if email and '@' in str(email):
                        clean_email = str(email).strip().lower()
                        if self._is_valid_email(clean_email):
                            self.emails.add(clean_email)

                # Extraire les organisations
                orgs = []
                for field in ['org', 'registrant', 'admin', 'tech']:
                    if hasattr(w, field) and getattr(w, field):
                        org = str(getattr(w, field)).strip()
                        if org and len(org) > 3:
                            orgs.append(org)

                for org in orgs:
                    self.organizations.add(org)

                self.logger.info("WHOIS extraction completed", module="EmailExtractor",
                               emails_found=len(self.emails), orgs_found=len(self.organizations))

        except ImportError:
            self.logger.warning("python-whois not available", module="EmailExtractor")
        except Exception as e:
            self.logger.error("WHOIS extraction failed", module="EmailExtractor", error=str(e))

    def extract_from_certificates(self, cert_data):
        """Extrait emails et organisations depuis les certificats"""
        try:
            if not cert_data:
                return

            for cert in cert_data:
                try:
                    # Extraire depuis issuer_name
                    issuer = cert.get('issuer_name', '')
                    if issuer:
                        emails = self._extract_emails_from_text(issuer)
                        self.emails.update(emails)

                        orgs = self._extract_organizations_from_text(issuer)
                        self.organizations.update(orgs)

                    # Extraire depuis subject
                    subject = cert.get('subject', '')
                    if subject:
                        emails = self._extract_emails_from_text(subject)
                        self.emails.update(emails)

                        orgs = self._extract_organizations_from_text(subject)
                        self.organizations.update(orgs)

                except Exception as e:
                    self.logger.debug("Certificate parsing error", module="EmailExtractor", error=str(e))
                    continue

            self.logger.info("Certificate extraction completed", module="EmailExtractor",
                           emails_found=len(self.emails), orgs_found=len(self.organizations))

        except Exception as e:
            self.logger.error("Certificate extraction failed", module="EmailExtractor", error=str(e))

    def _extract_emails_from_text(self, text):
        """Extrait les emails d'un texte avec regex"""
        emails = set()
        try:
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            matches = re.findall(email_pattern, text)
            for match in matches:
                if self._is_valid_email(match.lower()):
                    emails.add(match.lower())
        except Exception as e:
            self.logger.debug("Email regex extraction failed", module="EmailExtractor", error=str(e))
        return emails

    def _extract_organizations_from_text(self, text):
        """Extrait les organisations d'un texte"""
        orgs = set()
        try:
            # Pattern pour extraire O= (Organization)
            org_patterns = [
                r'O=([^,]+)',
                r'Organization:\s*([^\n]+)',
                r'Org:\s*([^\n]+)'
            ]

            for pattern in org_patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    org = match.strip()
                    if org and len(org) > 3 and not any(x in org.lower() for x in ['null', 'none', 'n/a']):
                        orgs.add(org)

        except Exception as e:
            self.logger.debug("Organization extraction failed", module="EmailExtractor", error=str(e))
        return orgs

    def _is_valid_email(self, email):
        """Valide un email"""
        try:
            pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            return bool(re.match(pattern, email)) and len(email) < 100
        except Exception:
            return False

    def get_results(self):
        """Retourne les resultats extraits"""
        return {
            'emails': list(self.emails),
            'organizations': list(self.organizations)
        }


class StatisticsCollector:
    """
    Collecteur de statistiques detaillees
    """

    def __init__(self, logger: logging.Logger | None = None) -> None:
        """Initialize the statistics collector for tracking enumeration metrics.

        Args:
            logger: Logger instance, or None to use the default module logger.
        """
        self.logger = logger or logging.getLogger(__name__)
        self.start_time = time.time()
        self.stats = {
            'domain': '',
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'total_time': 0,
            'engines_used': [],
            'engines_stats': {},
            'total_subdomains': 0,
            'unique_subdomains': 0,
            'subdomains_by_engine': {},
            'ips_resolved': 0,
            'emails_found': 0,
            'organizations_found': 0,
            'errors': [],
            'performance_metrics': {
                'requests_sent': 0,
                'requests_successful': 0,
                'requests_failed': 0,
                'avg_response_time': 0
            }
        }

    def set_domain(self, domain):
        """Definit le domaine cible"""
        self.stats['domain'] = domain

    def add_engine(self, engine_name):
        """Ajoute un moteur utilise"""
        if engine_name not in self.stats['engines_used']:
            self.stats['engines_used'].append(engine_name)

        if engine_name not in self.stats['engines_stats']:
            self.stats['engines_stats'][engine_name] = {
                'start_time': time.time(),
                'end_time': None,
                'duration': 0,
                'subdomains_found': 0,
                'requests_sent': 0,
                'requests_successful': 0,
                'requests_failed': 0,
                'errors': []
            }

    def update_engine_stats(self, engine_name, metrics):
        """Met a jour les statistiques d'un moteur"""
        if engine_name in self.stats['engines_stats']:
            engine_stats = self.stats['engines_stats'][engine_name]
            engine_stats['end_time'] = time.time()
            engine_stats['duration'] = engine_stats['end_time'] - engine_stats['start_time']

            if hasattr(metrics, 'get'):
                engine_stats['requests_sent'] = metrics.get('requests_sent', 0)
                engine_stats['requests_successful'] = metrics.get('requests_successful', 0)
                engine_stats['requests_failed'] = metrics.get('requests_failed', 0)

    def set_subdomains(self, subdomains, engine_results=None):
        """Definit les sous-domaines trouves"""
        self.stats['total_subdomains'] = len(subdomains)
        self.stats['unique_subdomains'] = len(set(subdomains))

        if engine_results:
            self.stats['subdomains_by_engine'] = engine_results

    def set_extraction_results(self, email_results):
        """Definit les resultats d'extraction"""
        if email_results:
            self.stats['emails_found'] = len(email_results.get('emails', []))
            self.stats['organizations_found'] = len(email_results.get('organizations', []))

    def add_error(self, error, engine=None):
        """Ajoute une erreur"""
        error_entry = {
            'timestamp': datetime.now().isoformat(),
            'error': str(error),
            'engine': engine
        }
        self.stats['errors'].append(error_entry)

    def finalize(self):
        """Finalise les statistiques"""
        self.stats['end_time'] = datetime.now().isoformat()
        self.stats['total_time'] = time.time() - self.start_time

        # Calculer les metriques de performance globales
        total_requests = sum(engine['requests_sent'] for engine in self.stats['engines_stats'].values())
        total_successful = sum(engine['requests_successful'] for engine in self.stats['engines_stats'].values())
        total_failed = sum(engine['requests_failed'] for engine in self.stats['engines_stats'].values())

        self.stats['performance_metrics'] = {
            'requests_sent': total_requests,
            'requests_successful': total_successful,
            'requests_failed': total_failed,
            'success_rate': (total_successful / total_requests * 100) if total_requests > 0 else 0,
            'avg_time_per_request': (self.stats['total_time'] / total_requests) if total_requests > 0 else 0
        }

    def export_to_file(self, filename):
        """Exporte les statistiques vers un fichier"""
        try:
            import json

            self.finalize()

            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.stats, f, indent=2, ensure_ascii=False)

            self.logger.info("Statistics exported", module="StatisticsCollector",
                           filename=filename, total_subdomains=self.stats['total_subdomains'])

        except Exception as e:
            self.logger.error("Statistics export failed", module="StatisticsCollector",
                            filename=filename, error=str(e))
