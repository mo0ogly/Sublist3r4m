"""Enhanced enumerator base class for JARVIS Intelligence."""
from __future__ import annotations

import random
import socket
import time
import urllib.request as urllib_request
from datetime import datetime
from urllib.parse import quote

from jarvis.logger import colors

# External modules with fallback handling
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# These will be set by main module initialization
logger = None
security_validator = None


def set_globals(logger_instance, validator_instance):
    """Set the module-level globals from the main module."""
    global logger, security_validator
    logger = logger_instance
    security_validator = validator_instance


class EnhancedEnumeratorBase(object):
    """
    Classe de base amelioree pour tous les enumerateurs.

    Ameliorations:
    - Gestion d'erreurs robuste
    - Rate limiting intelligent
    - Retry avec backoff exponentiel
    - Metriques detaillees
    - User-Agent rotation
    - Timeout adaptatif
    """

    def __init__(
        self,
        base_url: str,
        engine_name: str,
        domain: str,
        subdomains: list[str] | None = None,
        silent: bool = False,
        verbose: bool = True,
        timeout: int = 25,
        delay: int = 0,
        user_agent: str | None = None,
    ) -> None:
        """Initialise l'enumerateur de base."""
        try:
            subdomains = subdomains or []
            self.domain = self._extract_domain(domain)
            self.original_domain = domain

            # Configuration de session
            if REQUESTS_AVAILABLE:
                self.session = requests.Session()
                self.session.verify = True  # Verification SSL par defaut
            else:
                self.session = None
                logger.warning("Requests not available, using urllib fallback", module=engine_name)

            self.subdomains = set()  # Utiliser un set pour eviter les doublons
            self.timeout = max(timeout, 5)  # Minimum 5 secondes
            self.base_url = base_url
            self.engine_name = engine_name
            self.silent = silent
            self.verbose = verbose
            self.delay = max(delay, 0)

            # User-Agent avec rotation
            default_ua = (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/91.0.4472.124 Safari/537.36'
            )
            self.user_agents = [
                user_agent if user_agent else default_ua,
                (
                    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                    'Chrome/91.0.4472.124 Safari/537.36'
                ),
                (
                    'Mozilla/5.0 (X11; Linux x86_64) '
                    'AppleWebKit/537.36 (KHTML, like Gecko) '
                    'Chrome/91.0.4472.124 Safari/537.36'
                ),
                (
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) '
                    'Gecko/20100101 Firefox/89.0'
                ),
            ]
            self.current_ua_index = 0

            # Headers avec rotation
            self.base_headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Cache-Control': 'max-age=0',
            }

            # Metriques
            self.metrics = {
                'requests_sent': 0,
                'requests_successful': 0,
                'requests_failed': 0,
                'subdomains_found': 0,
                'start_time': time.time(),
                'errors': [],
                'rate_limited': 0,
                'timeouts': 0
            }

            # Configuration rate limiting
            self.last_request_time = 0
            self.consecutive_failures = 0
            self.max_consecutive_failures = 5
            self.backoff_factor = 1.5
            self.current_delay = self.delay

            # Afficher le banner
            self.print_banner()

            logger.debug("Enumerator initialized", module=engine_name,
                        domain=self.domain, timeout=self.timeout)

        except Exception as e:
            logger.error("Enumerator initialization failed", module=engine_name, error=str(e))
            raise

    def _extract_domain(self, domain):
        """Extrait le domaine propre depuis une URL ou domaine."""
        try:
            import urllib.parse as urlparse

            if not domain:
                return ""

            # Valider avec le security validator
            is_valid, clean_domain, error_msg = security_validator.validate_domain(domain)
            if not is_valid:
                raise ValueError("Invalid domain: {}".format(error_msg))

            # Parser l'URL si necessaire
            if domain.startswith(('http://', 'https://')):
                parsed = urlparse.urlparse(domain)
                return parsed.netloc

            return clean_domain

        except Exception as e:
            logger.error("Domain extraction failed", module=self.engine_name,
                        domain=domain, error=str(e))
            raise

    def _get_headers(self):
        """Retourne les headers avec User-Agent en rotation."""
        try:
            headers = self.base_headers.copy()
            headers['User-Agent'] = self.user_agents[self.current_ua_index]

            # Rotation du User-Agent
            self.current_ua_index = (self.current_ua_index + 1) % len(self.user_agents)

            return headers

        except Exception as e:
            logger.error("Header generation failed", module=self.engine_name, error=str(e))
            return self.base_headers

    def _apply_rate_limiting(self):
        """Applique le rate limiting intelligent."""
        try:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time

            # Delai adaptatif base sur les echecs consecutifs
            required_delay = self.current_delay * (self.backoff_factor ** self.consecutive_failures)
            required_delay = min(required_delay, 10)  # Maximum 10 secondes

            if time_since_last < required_delay:
                sleep_time = required_delay - time_since_last
                if sleep_time > 0:
                    logger.debug("Rate limiting applied", module=self.engine_name,
                               sleep_time=sleep_time, consecutive_failures=self.consecutive_failures)
                    time.sleep(sleep_time)

            self.last_request_time = time.time()

        except Exception as e:
            logger.error("Rate limiting failed", module=self.engine_name, error=str(e))

    def print_(self, text):
        """Affichage avec gestion des erreurs."""
        try:
            if not self.silent:
                print(text)
        except Exception as e:
            logger.error("Print failed", module=self.engine_name, error=str(e))

    def print_banner(self):
        """Affiche le banner du moteur."""
        try:
            if not self.silent:
                banner_text = "{}[{}] Searching in {}{}".format(
                    colors.GREEN,
                    datetime.now().strftime("%H:%M:%S"),
                    self.engine_name,
                    colors.WHITE
                )
                self.print_(banner_text)
        except Exception as e:
            logger.error("Banner printing failed", module=self.engine_name, error=str(e))

    def send_req(self, query, page_no=1, retries=3):
        """
        Envoi de requete ameliore avec retry et gestion d'erreurs.

        Args:
            query: Requete a envoyer
            page_no: Numero de page
            retries: Nombre de tentatives

        Returns:
            Reponse ou None en cas d'echec
        """
        response = None
        last_error = None

        for attempt in range(retries + 1):
            try:
                # Appliquer le rate limiting
                self._apply_rate_limiting()

                # Construire l'URL
                url = self.base_url.format(domain=self.domain, query=quote(query), page_no=page_no)
                logger.debug("Sending request", module=self.engine_name,
                           url=url[:100], attempt=attempt + 1)

                # Incrementer le compteur de requetes
                self.metrics['requests_sent'] += 1

                # Envoyer la requete
                if self.session and REQUESTS_AVAILABLE:
                    response = self.session.get(
                        url,
                        headers=self._get_headers(),
                        timeout=self.timeout,
                        allow_redirects=True
                    )

                    # Verifier le code de statut
                    if response.status_code == 200:
                        self.metrics['requests_successful'] += 1
                        self.consecutive_failures = 0
                        return self.get_response(response)
                    elif response.status_code == 429:  # Too Many Requests
                        self.metrics['rate_limited'] += 1
                        self.consecutive_failures += 1
                        logger.warning("Rate limited by server", module=self.engine_name,
                                     status_code=response.status_code)
                        if attempt < retries:
                            time.sleep(2 ** attempt)  # Backoff exponentiel
                            continue
                    else:
                        logger.warning("HTTP error", module=self.engine_name,
                                     status_code=response.status_code, url=url[:50])
                else:
                    # Fallback urllib
                    req = urllib_request.Request(url, headers=self._get_headers())
                    response = urllib_request.urlopen(req, timeout=self.timeout)
                    self.metrics['requests_successful'] += 1
                    self.consecutive_failures = 0
                    return self.get_response(response)

            except requests.exceptions.Timeout if REQUESTS_AVAILABLE else socket.timeout:
                self.metrics['timeouts'] += 1
                last_error = "Request timeout"
                logger.warning("Request timeout", module=self.engine_name,
                             attempt=attempt + 1, timeout=self.timeout)

            except (
                requests.exceptions.ConnectionError
                if REQUESTS_AVAILABLE
                else (socket.error, urllib_request.URLError)
            ):
                last_error = "Connection error"
                logger.warning("Connection error", module=self.engine_name, attempt=attempt + 1)

            except Exception as e:
                last_error = str(e)
                logger.error("Request failed", module=self.engine_name,
                           attempt=attempt + 1, error=str(e))

            # Attendre avant la prochaine tentative
            if attempt < retries:
                wait_time = (2 ** attempt) + random.uniform(0, 1)
                time.sleep(wait_time)

        # Toutes les tentatives ont echoue
        self.metrics['requests_failed'] += 1
        self.consecutive_failures += 1
        self.metrics['errors'].append({
            'timestamp': datetime.now().isoformat(),
            'error': last_error,
            'query': query[:50] if query else 'None'
        })

        logger.error("All request attempts failed", module=self.engine_name,
                   retries=retries, last_error=last_error)

        return None

    def get_response(self, response):
        """Traite la reponse de la requete."""
        try:
            if response is None:
                return None

            # Pour requests
            if hasattr(response, 'text'):
                return response.text
            # Pour urllib
            elif hasattr(response, 'read'):
                content = response.read()
                if isinstance(content, bytes):
                    try:
                        return content.decode('utf-8')
                    except UnicodeDecodeError:
                        return content.decode('latin-1', errors='ignore')
                return content
            # Fallback
            else:
                return str(response)

        except Exception as e:
            logger.error("Response processing failed", module=self.engine_name, error=str(e))
            return None

    def add_subdomain(self, subdomain):
        """
        Ajoute un sous-domaine avec validation.

        Args:
            subdomain: Sous-domaine a ajouter

        Returns:
            bool: True si ajoute, False sinon
        """
        try:
            if not subdomain or not isinstance(subdomain, str):
                return False

            # Nettoyer le sous-domaine
            cleaned = subdomain.strip().lower()

            # Verifier que c'est un sous-domaine valide du domaine cible
            if not cleaned.endswith('.' + self.domain) and cleaned != self.domain:
                return False

            # Eviter les caracteres suspects
            if any(char in cleaned for char in ['*', '@', '<', '>', '[', ']']):
                return False

            # Verifier si c'est nouveau
            if cleaned in self.subdomains or cleaned == self.domain:
                return False

            # Ajouter a la liste
            self.subdomains.add(cleaned)
            self.metrics['subdomains_found'] += 1

            # Affichage verbose
            if self.verbose and not self.silent:
                result_text = "{}[{}]{} {}Found:{} {}{}".format(
                    colors.BLUE,
                    datetime.now().strftime("%H:%M:%S"),
                    colors.WHITE,
                    colors.GREEN,
                    colors.WHITE,
                    cleaned,
                    colors.WHITE
                )
                self.print_(result_text)

            logger.debug("Subdomain added", module=self.engine_name, subdomain=cleaned)
            return True

        except Exception as e:
            logger.error("Subdomain addition failed", module=self.engine_name,
                       subdomain=subdomain, error=str(e))
            return False

    def should_continue(self):
        """Determine si l'enumeration doit continuer."""
        try:
            # Arreter si trop d'echecs consecutifs
            if self.consecutive_failures >= self.max_consecutive_failures:
                logger.warning("Too many consecutive failures, stopping",
                             module=self.engine_name, failures=self.consecutive_failures)
                return False

            # Arreter si le taux d'echec est trop eleve
            total_requests = self.metrics['requests_sent']
            if total_requests > 10:
                failure_rate = self.metrics['requests_failed'] / total_requests
                if failure_rate > 0.8:  # Plus de 80% d'echecs
                    logger.warning("High failure rate, stopping",
                                 module=self.engine_name, failure_rate=failure_rate)
                    return False

            return True

        except Exception as e:
            logger.error("Continue check failed", module=self.engine_name, error=str(e))
            return False

    def get_metrics(self):
        """Retourne les metriques de l'enumerateur."""
        try:
            current_time = time.time()
            elapsed = current_time - self.metrics['start_time']

            metrics = self.metrics.copy()
            metrics['elapsed_time'] = elapsed
            metrics['requests_per_second'] = metrics['requests_sent'] / elapsed if elapsed > 0 else 0
            metrics['success_rate'] = (metrics['requests_successful'] / metrics['requests_sent']
                                     if metrics['requests_sent'] > 0 else 0)

            return metrics

        except Exception as e:
            logger.error("Metrics calculation failed", module=self.engine_name, error=str(e))
            return self.metrics

    # Methodes virtuelles a surcharger
    def extract_domains(self, resp):
        """A surcharger par les classes enfant."""
        raise NotImplementedError("extract_domains must be implemented by subclass")

    def check_response_errors(self, resp):
        """A surcharger par les classes enfant."""
        return resp is not None

    def generate_query(self):
        """A surcharger par les classes enfant."""
        raise NotImplementedError("generate_query must be implemented by subclass")

    def enumerate(self):
        """Methode d'enumeration de base."""
        try:
            logger.info("Starting enumeration", module=self.engine_name, domain=self.domain)

            # Logique d'enumeration basique - a surcharger par les classes enfant
            query = self.generate_query()
            if not query:
                logger.warning("No query generated", module=self.engine_name)
                return list(self.subdomains)

            resp = self.send_req(query)
            if resp and self.check_response_errors(resp):
                self.extract_domains(resp)

            result_list = list(self.subdomains)
            logger.info("Enumeration completed", module=self.engine_name,
                       found=len(result_list))

            return result_list

        except Exception as e:
            logger.error("Enumeration failed", module=self.engine_name, error=str(e))
            return list(self.subdomains)
