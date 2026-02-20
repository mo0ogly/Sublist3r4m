"""Enumerator implementations for JARVIS Intelligence."""
from __future__ import annotations

import json
import os
import queue
import re
import socket
import threading
import time
import urllib.request as urllib_request

from jarvis.base import REQUESTS_AVAILABLE, EnhancedEnumeratorBase, logger
from jarvis.config import config_manager

# Conditional import
if REQUESTS_AVAILABLE:
    import requests


class EnhancedGoogleEnum(EnhancedEnumeratorBase):
    """
    Enumerateur Google ameliore et securise.

    Note: L'utilisation de Google pour l'enumeration automatisee peut violer
    leurs conditions d'utilisation. Cet exemple est a des fins educatives.
    """

    def __init__(self, domain, **kwargs):
        """Initialize the enhanced Google search enumerator.

        Args:
            domain: Target domain to enumerate subdomains for.
            **kwargs: Additional keyword arguments passed to EnhancedEnumeratorBase.
        """
        try:
            base_url = "https://www.google.com/search?q=site:{domain}+-inurl:www&num=100&start={page_no}"
            super(EnhancedGoogleEnum, self).__init__(
                base_url, "Google", domain, **kwargs
            )
            self.MAX_PAGES = 5  # Limiter pour eviter d'etre bloque
            self.domain_pattern = re.compile(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', re.IGNORECASE)

        except Exception as e:
            logger.error("Google enumerator initialization failed", error=str(e))
            raise

    def generate_query(self):
        """Genere la requete de recherche."""
        try:
            return "site:{}".format(self.domain)
        except Exception as e:
            logger.error("Query generation failed", module=self.engine_name, error=str(e))
            return None

    def check_response_errors(self, resp):
        """Verifie les erreurs dans la reponse."""
        try:
            if not resp:
                return False

            # Verifier les indicateurs de blocage
            error_indicators = [
                "blocked", "captcha", "unusual traffic",
                "automated queries", "robot", "bot"
            ]

            resp_lower = resp.lower()
            for indicator in error_indicators:
                if indicator in resp_lower:
                    logger.warning("Possible blocking detected", module=self.engine_name,
                                 indicator=indicator)
                    return False

            return True

        except Exception as e:
            logger.error("Response error check failed", module=self.engine_name, error=str(e))
            return False

    def extract_domains(self, resp):
        """Extrait les domaines de la reponse."""
        try:
            if not resp:
                return

            # Utiliser regex pour extraire les domaines
            matches = self.domain_pattern.findall(resp)

            for match in matches:
                subdomain = match.strip().lower()

                # Validation supplementaire
                if (subdomain != self.domain and
                    subdomain.endswith('.' + self.domain) and
                    not any(char in subdomain for char in ['<', '>', '"', "'"])):

                    self.add_subdomain(subdomain)

        except Exception as e:
            logger.error("Domain extraction failed", module=self.engine_name, error=str(e))


class PlaywrightGoogleEnum(EnhancedEnumeratorBase):
    """
    Enumerateur Google utilisant Playwright pour contourner la detection de bot.
    """

    def __init__(self, domain, **kwargs):
        """Initialize the Playwright-based Google enumerator.

        Args:
            domain: Target domain to enumerate subdomains for.
            **kwargs: Additional keyword arguments passed to EnhancedEnumeratorBase.
        """
        try:
            base_url = "https://www.google.com/search?q=site:{domain}+-inurl:www&num=100&start={page_no}"
            super(PlaywrightGoogleEnum, self).__init__(
                base_url, "GooglePlaywright", domain, **kwargs
            )
            self.MAX_PAGES = 3
            self.domain_pattern = re.compile(r'([a-zA-Z0-9.-]+\.' + re.escape(self.domain) + r')', re.IGNORECASE)
            self.browser = None
            self.page = None

        except Exception as e:
            logger.error("Playwright Google enumerator initialization failed", error=str(e))
            raise

    def _init_browser(self):
        """Initialise le navigateur Playwright"""
        try:
            from playwright.sync_api import sync_playwright

            if not hasattr(self, 'playwright'):
                self.playwright = sync_playwright().start()

            if not self.browser:
                self.browser = self.playwright.chromium.launch(
                    headless=True,
                    args=[
                        '--no-sandbox',
                        '--disable-blink-features=AutomationControlled',
                        '--disable-web-security',
                        '--disable-features=VizDisplayCompositor'
                    ]
                )

                pw_ua = (
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                    'Chrome/120.0.0.0 Safari/537.36'
                )
                context = self.browser.new_context(
                    user_agent=pw_ua,
                    viewport={'width': 1920, 'height': 1080}
                )

                self.page = context.new_page()

                # Masquer les signes d'automatisation
                self.page.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => false,
                    });
                """)

            return True

        except ImportError:
            logger.error("Playwright not available", module=self.engine_name)
            return False
        except Exception as e:
            logger.error("Browser initialization failed", module=self.engine_name, error=str(e))
            return False

    def _cleanup_browser(self):
        """Nettoie les ressources du navigateur"""
        try:
            if self.page:
                self.page.close()
                self.page = None
            if self.browser:
                self.browser.close()
                self.browser = None
            if hasattr(self, 'playwright'):
                self.playwright.stop()
                delattr(self, 'playwright')
        except Exception as e:
            logger.warning("Browser cleanup failed", module=self.engine_name, error=str(e))

    def send_req(self, query, page_no=1, retries=3):
        """Envoi de requete via Playwright"""
        try:
            if not self._init_browser():
                return None

            # Construire l'URL
            start_idx = (page_no - 1) * 10
            url = (
                f"https://www.google.com/search"
                f"?q=site:{self.domain}+{query}"
                f"&num=100&start={start_idx}"
            )

            logger.info("Navigating to URL", module=self.engine_name, url=url[:100])

            # Naviguer vers la page
            response = self.page.goto(url, wait_until='networkidle', timeout=30000)

            if response and response.status == 200:
                # Attendre que la page soit chargee
                self.page.wait_for_selector('div#search', timeout=10000)

                # Obtenir le contenu HTML
                content = self.page.content()
                self.metrics['requests_successful'] += 1
                self.consecutive_failures = 0

                logger.info("Page loaded successfully", module=self.engine_name,
                          content_length=len(content), title=self.page.title())

                return content
            else:
                logger.warning("HTTP error", module=self.engine_name,
                             status_code=response.status if response else 'None')
                return None

        except Exception as e:
            logger.error("Playwright request failed", module=self.engine_name, error=str(e))
            self.metrics['requests_failed'] += 1
            self.consecutive_failures += 1
            return None

    def generate_query(self):
        """Genere la requete de recherche"""
        try:
            if self.subdomains:
                # Exclure les sous-domaines deja trouves
                excluded = ' -'.join([f'site:{sub}' for sub in list(self.subdomains)[:10]])
                return f"-www.{self.domain} -{excluded}"
            else:
                return f"-www.{self.domain}"
        except Exception as e:
            logger.error("Query generation failed", module=self.engine_name, error=str(e))
            return f"-www.{self.domain}"

    def check_response_errors(self, resp):
        """Verifie les erreurs dans la reponse"""
        try:
            if not resp:
                return False

            # Verifier les indicateurs de blocage
            error_indicators = [
                "unusual traffic", "captcha", "automated queries",
                "our systems have detected", "please try again"
            ]

            resp_lower = resp.lower()
            for indicator in error_indicators:
                if indicator in resp_lower:
                    logger.warning("Possible blocking detected",
                                 module=self.engine_name, indicator=indicator)
                    return False

            return True

        except Exception as e:
            logger.error("Response error check failed", module=self.engine_name, error=str(e))
            return False

    def extract_domains(self, resp):
        """Extrait les domaines de la reponse HTML Google"""
        try:
            if not resp:
                return

            # Parser avec BeautifulSoup si disponible, sinon regex
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp, 'html.parser')

                # Rechercher dans les liens de resultats
                for link in soup.find_all('a', href=True):
                    href = link.get('href', '')
                    if '/url?q=' in href:
                        # Extraire l'URL reelle
                        start = href.find('/url?q=') + 8
                        end = href.find('&', start)
                        if end == -1:
                            end = len(href)
                        url = href[start:end]

                        # Extraire le domaine
                        try:
                            from urllib.parse import urlparse
                            parsed = urlparse(url)
                            domain = parsed.netloc.lower()

                            if (domain.endswith('.' + self.domain) and
                                domain != self.domain and
                                domain not in self.subdomains):
                                self.add_subdomain(domain)
                        except Exception:
                            pass

            except ImportError:
                # Fallback regex si BeautifulSoup n'est pas disponible
                matches = self.domain_pattern.findall(resp)
                for match in matches:
                    subdomain = match.strip().lower()
                    if (subdomain != self.domain and
                        subdomain.endswith('.' + self.domain) and
                        subdomain not in self.subdomains):
                        self.add_subdomain(subdomain)

        except Exception as e:
            logger.error("Domain extraction failed", module=self.engine_name, error=str(e))

    def enumerate(self):
        """Methode d'enumeration avec Playwright"""
        try:
            logger.info("Starting Playwright enumeration", module=self.engine_name, domain=self.domain)

            for page in range(1, self.MAX_PAGES + 1):
                if not self.should_continue():
                    break

                query = self.generate_query()
                if not query:
                    break

                resp = self.send_req(query, page_no=page)
                if resp and self.check_response_errors(resp):
                    self.extract_domains(resp)

                    # Attendre entre les pages
                    if page < self.MAX_PAGES:
                        time.sleep(random.uniform(2, 4))
                else:
                    break

            result_list = list(self.subdomains)
            logger.info("Playwright enumeration completed", module=self.engine_name,
                       found=len(result_list))

            return result_list

        except Exception as e:
            logger.error("Playwright enumeration failed", module=self.engine_name, error=str(e))
            return list(self.subdomains)
        finally:
            self._cleanup_browser()


class CertificateTransparencyEnum(EnhancedEnumeratorBase):
    """
    Enumerateur utilisant Certificate Transparency Logs (crt.sh)
    Tres efficace car pas de detection de bot et donnees reelles
    """

    def __init__(self, domain, **kwargs):
        """Initialize the Certificate Transparency enumerator using crt.sh.

        Args:
            domain: Target domain to enumerate subdomains for.
            **kwargs: Additional keyword arguments passed to EnhancedEnumeratorBase.
        """
        try:
            base_url = "https://crt.sh/?q=%.{domain}&output=json"
            super(CertificateTransparencyEnum, self).__init__(
                base_url, "CertificateTransparency", domain, **kwargs
            )
            self.api_endpoints = [
                "https://crt.sh/?q=%.{domain}&output=json",
                "https://crt.sh/?q={domain}&output=json",
                "https://crt.sh/?q=%.%.{domain}&output=json"  # Pour les sous-domaines profonds
            ]

        except Exception as e:
            logger.error("Certificate Transparency enumerator initialization failed", error=str(e))
            raise

    def send_req(self, query, page_no=1, retries=3):
        """Envoi de requete vers l'API Certificate Transparency"""
        try:
            # Construire l'URL de l'API
            url = query.format(domain=self.domain)

            logger.info("Querying Certificate Transparency", module=self.engine_name, url=url)

            ct_ua = (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            )
            headers = {
                'User-Agent': ct_ua,
                'Accept': 'application/json',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive'
            }

            if self.session and REQUESTS_AVAILABLE:
                response = self.session.get(url, headers=headers, timeout=30)
                if response.status_code == 200:
                    self.metrics['requests_successful'] += 1
                    return response.json() if response.text.strip() else []
                else:
                    logger.warning("API error", module=self.engine_name, status_code=response.status_code)
                    return None
            else:
                # Fallback urllib
                req = urllib_request.Request(url, headers=headers)
                response = urllib_request.urlopen(req, timeout=30)
                data = response.read().decode('utf-8')
                return json.loads(data) if data.strip() else []

        except Exception as e:
            logger.error("Certificate Transparency request failed", module=self.engine_name, error=str(e))
            return None

    def extract_domains(self, cert_data):
        """Extrait les domaines des donnees de certificats"""
        try:
            if not cert_data:
                return

            found_count = 0
            for cert in cert_data:
                try:
                    # Extraire les noms du certificat
                    name_value = cert.get('name_value', '')
                    common_name = cert.get('common_name', '')

                    # Traiter les noms multiples (separes par \n)
                    names = []
                    if name_value:
                        names.extend([n.strip() for n in name_value.split('\n') if n.strip()])
                    if common_name:
                        names.append(common_name.strip())

                    for name in names:
                        # Nettoyer le nom
                        name = name.lower().strip()

                        # Supprimer les wildcards
                        if name.startswith('*.'):
                            name = name[2:]

                        # Verifier que c'est un sous-domaine valide
                        if (name.endswith('.' + self.domain) and
                            name != self.domain and
                            '.' in name and
                            not any(char in name for char in ['<', '>', '"', "'", ' ', '\t']) and
                            len(name.split('.')) >= 2):  # Au moins un sous-domaine

                            if self.add_subdomain(name):
                                found_count += 1

                                # Extraire des informations supplementaires du certificat
                                issuer = cert.get('issuer_name', '')
                                not_before = cert.get('not_before', '')
                                not_after = cert.get('not_after', '')

                                logger.debug("Certificate found", module=self.engine_name,
                                           subdomain=name, issuer=issuer[:50] if issuer else '',
                                           valid_from=not_before, valid_to=not_after)

                except Exception as e:
                    logger.debug("Certificate parsing error", module=self.engine_name, error=str(e))
                    continue

            if found_count > 0:
                logger.info("Certificates processed", module=self.engine_name,
                          total_certs=len(cert_data), domains_found=found_count)

        except Exception as e:
            logger.error("Certificate domain extraction failed", module=self.engine_name, error=str(e))

    def enumerate(self):
        """Enumeration via Certificate Transparency"""
        try:
            logger.info("Starting Certificate Transparency enumeration",
                       module=self.engine_name, domain=self.domain)

            # Requeter tous les endpoints
            for endpoint in self.api_endpoints:
                try:
                    logger.info("Querying endpoint", module=self.engine_name, endpoint=endpoint)

                    cert_data = self.send_req(endpoint)
                    if cert_data:
                        initial_count = len(self.subdomains)
                        self.extract_domains(cert_data)
                        new_count = len(self.subdomains) - initial_count

                        logger.info("Endpoint completed", module=self.engine_name,
                                  endpoint=endpoint.split('/')[-1],
                                  certificates=len(cert_data), new_domains=new_count)

                        # Attendre entre les requetes
                        time.sleep(1)
                    else:
                        logger.warning("No data from endpoint", module=self.engine_name, endpoint=endpoint)

                except Exception as e:
                    logger.error("Endpoint query failed", module=self.engine_name,
                               endpoint=endpoint, error=str(e))
                    continue

            result_list = list(self.subdomains)
            logger.info("Certificate Transparency enumeration completed",
                       module=self.engine_name, found=len(result_list))

            return result_list

        except Exception as e:
            logger.error("Certificate Transparency enumeration failed", module=self.engine_name, error=str(e))
            return list(self.subdomains)


class SecurityTrailsEnum(EnhancedEnumeratorBase):
    """
    Enumerateur utilisant l'API SecurityTrails
    Necessite une cle API mais tres complet
    """

    def __init__(self, domain, api_key=None, **kwargs):
        """Initialize the SecurityTrails API enumerator.

        Args:
            domain: Target domain to enumerate subdomains for.
            api_key: SecurityTrails API key, or None.
            **kwargs: Additional keyword arguments passed to EnhancedEnumeratorBase.
        """
        try:
            base_url = "https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            super(SecurityTrailsEnum, self).__init__(
                base_url, "SecurityTrails", domain, **kwargs
            )
            self.api_key = api_key or kwargs.get('securitytrails_api_key')

        except Exception as e:
            logger.error("SecurityTrails enumerator initialization failed", error=str(e))
            raise

    def send_req(self, query, page_no=1, retries=3):
        """Envoi de requete vers l'API SecurityTrails"""
        try:
            if not self.api_key:
                logger.warning("SecurityTrails API key not provided", module=self.engine_name)
                return None

            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"

            headers = {
                'APIKEY': self.api_key,
                'Content-Type': 'application/json',
                'User-Agent': 'JARVIS-Intelligence/2.1'
            }

            logger.info("Querying SecurityTrails API", module=self.engine_name)

            if self.session and REQUESTS_AVAILABLE:
                response = self.session.get(url, headers=headers, timeout=30)
                if response.status_code == 200:
                    self.metrics['requests_successful'] += 1
                    return response.json()
                elif response.status_code == 429:
                    logger.warning("SecurityTrails rate limit exceeded", module=self.engine_name)
                    return None
                elif response.status_code == 401:
                    logger.error("SecurityTrails API key invalid", module=self.engine_name)
                    return None
                else:
                    logger.warning("SecurityTrails API error", module=self.engine_name,
                                 status_code=response.status_code)
                    return None

        except Exception as e:
            logger.error("SecurityTrails request failed", module=self.engine_name, error=str(e))
            return None

    def extract_domains(self, api_data):
        """Extrait les domaines des donnees SecurityTrails"""
        try:
            if not api_data or 'subdomains' not in api_data:
                return

            subdomains = api_data.get('subdomains', [])
            found_count = 0

            for subdomain in subdomains:
                try:
                    # Construire le FQDN
                    full_domain = f"{subdomain}.{self.domain}".lower()

                    if self.add_subdomain(full_domain):
                        found_count += 1

                except Exception as e:
                    logger.debug("Subdomain processing error", module=self.engine_name, error=str(e))
                    continue

            logger.info("SecurityTrails data processed", module=self.engine_name,
                       total_subdomains=len(subdomains), domains_found=found_count)

        except Exception as e:
            logger.error("SecurityTrails domain extraction failed", module=self.engine_name, error=str(e))

    def enumerate(self):
        """Enumeration via SecurityTrails"""
        try:
            logger.info("Starting SecurityTrails enumeration", module=self.engine_name, domain=self.domain)

            if not self.api_key:
                logger.warning("SecurityTrails skipped - no API key", module=self.engine_name)
                return list(self.subdomains)

            api_data = self.send_req("")
            if api_data:
                self.extract_domains(api_data)

            result_list = list(self.subdomains)
            logger.info("SecurityTrails enumeration completed", module=self.engine_name, found=len(result_list))

            return result_list

        except Exception as e:
            logger.error("SecurityTrails enumeration failed", module=self.engine_name, error=str(e))
            return list(self.subdomains)


class VirusTotalEnum(EnhancedEnumeratorBase):
    """
    Enumerateur utilisant l'API VirusTotal
    Necessite une cle API gratuite
    """

    def __init__(self, domain, api_key=None, **kwargs):
        """Initialize the VirusTotal API enumerator.

        Args:
            domain: Target domain to enumerate subdomains for.
            api_key: VirusTotal API key, or None.
            **kwargs: Additional keyword arguments passed to EnhancedEnumeratorBase.
        """
        try:
            base_url = "https://www.virustotal.com/vtapi/v2/domain/report"
            super(VirusTotalEnum, self).__init__(
                base_url, "VirusTotal", domain, **kwargs
            )
            self.api_key = api_key or kwargs.get('virustotal_api_key')

        except Exception as e:
            logger.error("VirusTotal enumerator initialization failed", error=str(e))
            raise

    def send_req(self, query, page_no=1, retries=3):
        """Envoi de requete vers l'API VirusTotal"""
        try:
            if not self.api_key:
                logger.warning("VirusTotal API key not provided", module=self.engine_name)
                return None

            url = "https://www.virustotal.com/vtapi/v2/domain/report"
            params = {
                'apikey': self.api_key,
                'domain': self.domain
            }

            logger.info("Querying VirusTotal API", module=self.engine_name)

            if self.session and REQUESTS_AVAILABLE:
                response = self.session.get(url, params=params, timeout=30)
                if response.status_code == 200:
                    self.metrics['requests_successful'] += 1
                    return response.json()
                elif response.status_code == 204:
                    logger.info("VirusTotal quota exceeded", module=self.engine_name)
                    return None
                else:
                    logger.warning("VirusTotal API error", module=self.engine_name,
                                 status_code=response.status_code)
                    return None

        except Exception as e:
            logger.error("VirusTotal request failed", module=self.engine_name, error=str(e))
            return None

    def extract_domains(self, api_data):
        """Extrait les domaines des donnees VirusTotal"""
        try:
            if not api_data or api_data.get('response_code') != 1:
                return

            # Extraire les sous-domaines detectes
            subdomains = api_data.get('subdomains', [])
            found_count = 0

            for subdomain in subdomains:
                try:
                    subdomain = subdomain.lower().strip()

                    if (subdomain.endswith('.' + self.domain) and
                        subdomain != self.domain):

                        if self.add_subdomain(subdomain):
                            found_count += 1

                except Exception as e:
                    logger.debug("Subdomain processing error", module=self.engine_name, error=str(e))
                    continue

            logger.info("VirusTotal data processed", module=self.engine_name,
                       total_subdomains=len(subdomains), domains_found=found_count)

        except Exception as e:
            logger.error("VirusTotal domain extraction failed", module=self.engine_name, error=str(e))

    def enumerate(self):
        """Enumeration via VirusTotal"""
        try:
            logger.info("Starting VirusTotal enumeration", module=self.engine_name, domain=self.domain)

            if not self.api_key:
                logger.warning("VirusTotal skipped - no API key", module=self.engine_name)
                return list(self.subdomains)

            api_data = self.send_req("")
            if api_data:
                self.extract_domains(api_data)

            result_list = list(self.subdomains)
            logger.info("VirusTotal enumeration completed", module=self.engine_name, found=len(result_list))

            return result_list

        except Exception as e:
            logger.error("VirusTotal enumeration failed", module=self.engine_name, error=str(e))
            return list(self.subdomains)


class DNSBruteForceEnum(EnhancedEnumeratorBase):
    """
    Enumerateur DNS Brute Force intelligent avec wordlists optimisees
    """

    def __init__(self, domain, wordlist_file=None, **kwargs):
        """Initialize the DNS brute force enumerator.

        Args:
            domain: Target domain to enumerate subdomains for.
            wordlist_file: Path to a custom wordlist, or None for built-in defaults.
            **kwargs: Additional keyword arguments including dns_threads and dns_timeout.
        """
        try:
            base_url = ""  # Pas d'URL pour DNS brute force
            super(DNSBruteForceEnum, self).__init__(
                base_url, "DNSBruteForce", domain, **kwargs
            )

            # Wordlists par defaut (les plus communes)
            self.default_wordlist = [
                'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'app', 'web',
                'blog', 'shop', 'store', 'mobile', 'm', 'secure', 'vpn', 'remote',
                'staging', 'stage', 'prod', 'production', 'beta', 'alpha', 'demo',
                'support', 'help', 'docs', 'portal', 'login', 'auth', 'sso',
                'cloud', 'cdn', 'media', 'static', 'assets', 'img', 'images',
                'video', 'files', 'download', 'uploads', 'backup', 'old',
                'new', 'v2', 'v3', 'test1', 'test2', 'dev1', 'dev2',
                'smtp', 'pop', 'imap', 'webmail', 'email', 'mx', 'ns1', 'ns2',
                'dns', 'gateway', 'router', 'firewall', 'proxy', 'lb', 'www1',
                'www2', 'mail1', 'mail2', 'db', 'database', 'mysql', 'postgres',
                'redis', 'mongo', 'elastic', 'search', 'log', 'logs', 'monitor',
                'status', 'health', 'metrics', 'grafana', 'kibana', 'jenkins',
                'git', 'svn', 'repo', 'code', 'source', 'ci', 'cd', 'build',
                'deploy', 'release', 'artifactory', 'nexus', 'registry'
            ]

            self.wordlist_file = wordlist_file
            self.max_threads = kwargs.get('dns_threads', 50)
            self.timeout = kwargs.get('dns_timeout', 3)

        except Exception as e:
            logger.error("DNS BruteForce enumerator initialization failed", error=str(e))
            raise

    def _load_wordlist(self):
        """Charge la wordlist depuis un fichier ou utilise celle par defaut"""
        try:
            wordlist = []

            if self.wordlist_file and os.path.exists(self.wordlist_file):
                logger.info("Loading custom wordlist", module=self.engine_name, file=self.wordlist_file)
                with open(self.wordlist_file, 'r', encoding='utf-8') as f:
                    wordlist = [line.strip().lower() for line in f if line.strip() and not line.startswith('#')]
            else:
                logger.info("Using default wordlist", module=self.engine_name, size=len(self.default_wordlist))
                wordlist = self.default_wordlist.copy()

            # Nettoyer et valider la wordlist
            cleaned_wordlist = []
            for word in wordlist:
                if (word and
                    len(word) > 0 and
                    len(word) < 50 and
                    word.replace('-', '').replace('_', '').isalnum()):
                    cleaned_wordlist.append(word)

            logger.info("Wordlist loaded", module=self.engine_name,
                       total_words=len(wordlist), valid_words=len(cleaned_wordlist))

            return cleaned_wordlist

        except Exception as e:
            logger.error("Wordlist loading failed", module=self.engine_name, error=str(e))
            return self.default_wordlist

    def _resolve_subdomain(self, subdomain):
        """Resout un sous-domaine via DNS"""
        try:
            full_domain = f"{subdomain}.{self.domain}"

            # Essayer de resoudre le domaine
            try:
                result = socket.gethostbyname(full_domain)
                if result:
                    return full_domain, result
            except socket.gaierror:
                pass

            return None, None

        except Exception as e:
            logger.debug("DNS resolution error", module=self.engine_name,
                        subdomain=subdomain, error=str(e))
            return None, None

    def _worker(self, word_queue, results, progress_callback=None):
        """Worker thread pour le brute force DNS"""
        try:
            while True:
                try:
                    word = word_queue.get_nowait()
                except Exception:
                    break

                try:
                    subdomain, ip = self._resolve_subdomain(word)
                    if subdomain and ip:
                        with threading.Lock():
                            if self.add_subdomain(subdomain):
                                results.append((subdomain, ip))
                                logger.info("DNS resolved", module=self.engine_name,
                                          subdomain=subdomain, ip=ip)

                                if progress_callback:
                                    progress_callback(subdomain)

                    if progress_callback:
                        progress_callback(None)  # Signal de progression

                except Exception as e:
                    logger.debug("Worker error", module=self.engine_name,
                               word=word, error=str(e))
                finally:
                    word_queue.task_done()

        except Exception as e:
            logger.error("Worker thread failed", module=self.engine_name, error=str(e))

    def enumerate(self):
        """Enumeration par brute force DNS"""
        try:
            logger.info("Starting DNS BruteForce enumeration", module=self.engine_name, domain=self.domain)

            # Charger la wordlist
            wordlist = self._load_wordlist()
            if not wordlist:
                logger.warning("Empty wordlist", module=self.engine_name)
                return list(self.subdomains)

            # Preparer la queue et les resultats
            word_queue = queue.Queue()
            results = []

            # Ajouter tous les mots a la queue
            for word in wordlist:
                word_queue.put(word)

            total_words = len(wordlist)
            completed = 0
            found_count = 0

            def progress_callback(subdomain):
                nonlocal completed, found_count
                if subdomain:
                    found_count += 1
                    if not self.silent and self.verbose:
                        print(f"[DNS] Found: {subdomain}")
                else:
                    completed += 1
                    if completed % 50 == 0:
                        logger.info("DNS progress", module=self.engine_name,
                                  completed=completed, total=total_words, found=found_count)

            # Creer et demarrer les threads
            threads = []
            num_threads = min(self.max_threads, total_words, 100)

            logger.info("Starting DNS threads", module=self.engine_name,
                       threads=num_threads, wordlist_size=total_words)

            for i in range(num_threads):
                thread = threading.Thread(
                    target=self._worker,
                    args=(word_queue, results, progress_callback)
                )
                thread.daemon = True
                thread.start()
                threads.append(thread)

            # Attendre que tous les mots soient traites
            word_queue.join()

            # Attendre que tous les threads se terminent
            for thread in threads:
                thread.join(timeout=1)

            result_list = list(self.subdomains)
            logger.info("DNS BruteForce enumeration completed", module=self.engine_name,
                       tested=total_words, found=len(result_list))

            return result_list

        except Exception as e:
            logger.error("DNS BruteForce enumeration failed", module=self.engine_name, error=str(e))
            return list(self.subdomains)


class WaybackMachineEnum(object):
    """
    Enumerateur Wayback Machine pour decouvrir des sous-domaines historiques
    """

    def __init__(self, domain: str, **kwargs: object) -> None:
        """Initialize the Wayback Machine CDX API enumerator.

        Args:
            domain: Target domain to discover historical subdomains for.
            **kwargs: Additional keyword arguments including timeout.
        """
        try:
            self.domain = domain
            self.base_url = "https://web.archive.org/cdx/search/cdx"
            self.engine_name = "WaybackMachine"
            self.timeout = kwargs.get('timeout', 30)
            self.subdomains = set()

        except Exception as e:
            logger.error("Wayback Machine enumerator initialization failed", error=str(e))
            raise

    def send_req(self, url, params=None):
        """Requete specialisee pour l'API CDX de Wayback Machine"""
        try:
            if not REQUESTS_AVAILABLE:
                logger.error("requests module not available", module=self.engine_name)
                return None

            # Construction des parametres pour l'API CDX
            if not params:
                params = {
                    'url': f'*.{self.domain}',
                    'output': 'json',
                    'fl': 'original',
                    'collapse': 'urlkey',
                    'limit': 10000
                }

            logger.info("Querying Wayback Machine CDX API", module=self.engine_name, params=params)

            response = requests.get(
                url,
                params=params,
                timeout=config_manager.get_setting('timeout', 30),
                headers={
                    'User-Agent': config_manager.get_setting('user_agent',
                        'JARVIS Intelligence Scanner v1.0')
                }
            )

            if response.status_code == 200:
                return response.text
            else:
                logger.warning("Wayback Machine request failed",
                             module=self.engine_name, status_code=response.status_code)
                return None

        except Exception as e:
            logger.error("Wayback Machine request failed", module=self.engine_name, error=str(e))
            return None

    def enumerate(self):
        """Point d'entree principal pour l'enumeration"""
        return self.get_subdomains()

    def get_metrics(self):
        """Retourne les metriques de base"""
        return {
            'subdomains_found': len(self.subdomains),
            'requests_sent': 1,
            'errors': 0
        }

    def get_subdomains(self):
        """Enumere les sous-domaines via Wayback Machine"""
        try:
            subdomains = set()

            if not config_manager.is_service_enabled('wayback_machine'):
                logger.info("Wayback Machine disabled in config", module=self.engine_name)
                return []

            logger.info("Starting Wayback Machine enumeration", module=self.engine_name, domain=self.domain)

            # Requete a l'API CDX
            response_text = self.send_req(self.base_url)

            if response_text:
                try:
                    # Parser la reponse JSON
                    lines = response_text.strip().split('\n')
                    if lines and lines[0].startswith('['):
                        # Format JSON
                        data = json.loads(response_text)
                        if data and len(data) > 1:  # Skip header
                            for entry in data[1:]:
                                if entry and len(entry) > 0:
                                    url = entry[0]
                                    subdomain = self._extract_subdomain_from_url(url)
                                    if subdomain:
                                        subdomains.add(subdomain)
                    else:
                        # Format texte simple
                        for line in lines:
                            if line.strip():
                                subdomain = self._extract_subdomain_from_url(line.strip())
                                if subdomain:
                                    subdomains.add(subdomain)

                except json.JSONDecodeError:
                    # Traiter comme du texte simple
                    lines = response_text.strip().split('\n')
                    for line in lines:
                        if line.strip():
                            subdomain = self._extract_subdomain_from_url(line.strip())
                            if subdomain:
                                subdomains.add(subdomain)

                logger.info("Wayback Machine enumeration completed",
                           module=self.engine_name, found=len(subdomains))

                return list(subdomains)
            else:
                logger.warning("No data from Wayback Machine", module=self.engine_name)
                return []

        except Exception as e:
            logger.error("Wayback Machine enumeration failed", module=self.engine_name, error=str(e))
            return []

    def _extract_subdomain_from_url(self, url):
        """Extrait le sous-domaine d'une URL"""
        try:
            # Nettoyer l'URL
            url = url.strip()
            if url.startswith(('http://', 'https://')):
                url = url.split('://', 1)[1]

            # Extraire le domaine de l'URL
            domain_part = url.split('/')[0].split(':')[0]

            # Verifier si c'est un sous-domaine du domaine cible
            if domain_part.endswith(f'.{self.domain}') or domain_part == self.domain:
                return domain_part

            return None

        except Exception:
            return None


class ThreatCrowdEnum(object):
    """
    Enumerateur ThreatCrowd pour l'intelligence des menaces et decouverte de sous-domaines
    """

    def __init__(self, domain: str, **kwargs: object) -> None:
        """Initialize the ThreatCrowd threat intelligence enumerator.

        Args:
            domain: Target domain to enumerate subdomains for.
            **kwargs: Additional keyword arguments including timeout.
        """
        try:
            self.domain = domain
            self.base_url = "https://threatcrowd.org/searchApi/v2/domain/report/"
            self.engine_name = "ThreatCrowd"
            self.timeout = kwargs.get('timeout', 30)
            self.subdomains = set()

        except Exception as e:
            logger.error("ThreatCrowd enumerator initialization failed", error=str(e))
            raise

    def send_req(self, url):
        """Requete specialisee pour l'API ThreatCrowd"""
        try:
            if not REQUESTS_AVAILABLE:
                logger.error("requests module not available", module=self.engine_name)
                return None

            params = {'domain': self.domain}

            logger.info("Querying ThreatCrowd API", module=self.engine_name, domain=self.domain)

            response = requests.get(
                url,
                params=params,
                timeout=config_manager.get_setting('timeout', 30),
                headers={
                    'User-Agent': config_manager.get_setting('user_agent',
                        'JARVIS Intelligence Scanner v1.0')
                }
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.warning("ThreatCrowd request failed",
                             module=self.engine_name, status_code=response.status_code)
                return None

        except Exception as e:
            logger.error("ThreatCrowd request failed", module=self.engine_name, error=str(e))
            return None

    def enumerate(self):
        """Point d'entree principal pour l'enumeration"""
        return self.get_subdomains()

    def get_metrics(self):
        """Retourne les metriques de base"""
        return {
            'subdomains_found': len(self.subdomains),
            'requests_sent': 1,
            'errors': 0
        }

    def get_subdomains(self):
        """Enumere les sous-domaines via ThreatCrowd"""
        try:
            subdomains = set()

            if not config_manager.is_service_enabled('threatcrowd'):
                logger.info("ThreatCrowd disabled in config", module=self.engine_name)
                return []

            logger.info("Starting ThreatCrowd enumeration", module=self.engine_name, domain=self.domain)

            # Requete a l'API ThreatCrowd
            data = self.send_req(self.base_url)

            if data and data.get('response_code') == '1':
                # Extraire les sous-domaines de la reponse
                if 'subdomains' in data:
                    for subdomain in data['subdomains']:
                        if subdomain and self._is_valid_subdomain(subdomain):
                            subdomains.add(subdomain)

                # Extraire aussi des resolutions DNS
                if 'resolutions' in data:
                    for resolution in data['resolutions']:
                        if 'last_resolved' in resolution:
                            domain_name = resolution.get('last_resolved', '')
                            if domain_name and self._is_valid_subdomain(domain_name):
                                subdomains.add(domain_name)

                logger.info("ThreatCrowd enumeration completed",
                           module=self.engine_name, found=len(subdomains))

                return list(subdomains)
            else:
                logger.warning("No valid data from ThreatCrowd", module=self.engine_name,
                             response=data.get('response_code') if data else 'None')
                return []

        except Exception as e:
            logger.error("ThreatCrowd enumeration failed", module=self.engine_name, error=str(e))
            return []

    def _is_valid_subdomain(self, subdomain):
        """Valide si c'est un sous-domaine legitime du domaine cible"""
        try:
            return (subdomain and
                    isinstance(subdomain, str) and
                    (subdomain.endswith(f'.{self.domain}') or subdomain == self.domain) and
                    len(subdomain) > len(self.domain))
        except Exception:
            return False


# Need random for PlaywrightGoogleEnum.enumerate
import random  # noqa: E402
