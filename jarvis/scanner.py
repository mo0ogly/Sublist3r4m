"""Enhanced port scanner for JARVIS Intelligence."""
from __future__ import annotations

import socket
import threading
from datetime import datetime

from jarvis.logger import ProgressBar, colors

# These will be set by main module initialization
logger = None


def set_globals(logger_instance):
    """Set the module-level globals from the main module."""
    global logger
    logger = logger_instance


class EnhancedPortScanner:
    """
    Scanner de ports ameliore avec threading et gestion d'erreurs.
    """

    def __init__(self, subdomains: list[str], ports: list[int | str], max_threads: int = 50, timeout: int = 3) -> None:
        """Initialise le scanner de ports."""
        try:
            self.subdomains = subdomains if subdomains else []
            self.ports = ports if ports else []
            self.max_threads = min(max_threads, 100)  # Limiter a 100 threads max
            self.timeout = max(timeout, 1)  # Minimum 1 seconde
            self.results = {}
            self.lock = threading.Lock()
            self.progress_bar = None

            # Validation des ports
            valid_ports = []
            for port in self.ports:
                if isinstance(port, int) and 1 <= port <= 65535:
                    valid_ports.append(port)
                elif isinstance(port, str) and port.isdigit():
                    port_int = int(port)
                    if 1 <= port_int <= 65535:
                        valid_ports.append(port_int)

            self.ports = valid_ports

            if not self.ports:
                logger.warning("No valid ports to scan", module="PortScanner")

            if not self.subdomains:
                logger.warning("No subdomains to scan", module="PortScanner")

            logger.info("Port scanner initialized", module="PortScanner",
                       subdomains=len(self.subdomains), ports=len(self.ports))

        except Exception as e:
            logger.error("Port scanner initialization failed", module="PortScanner", error=str(e))
            raise

    def scan_port(self, host, port):
        """
        Scanne un port specifique sur un hote.

        Args:
            host: Nom d'hote a scanner
            port: Port a scanner

        Returns:
            bool: True si le port est ouvert
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            result = sock.connect_ex((host, port))
            sock.close()

            return result == 0

        except socket.gaierror:
            # Erreur de resolution DNS
            logger.debug("DNS resolution failed", module="PortScanner", host=host)
            return False
        except Exception as e:
            logger.debug("Port scan failed", module="PortScanner", host=host, port=port, error=str(e))
            return False

    def scan_host(self, host):
        """
        Scanne tous les ports d'un hote.

        Args:
            host: Nom d'hote a scanner
        """
        try:
            open_ports = []

            for port in self.ports:
                if self.scan_port(host, port):
                    open_ports.append(port)

            # Stocker les resultats
            with self.lock:
                if open_ports:
                    self.results[host] = open_ports

                    # Affichage des resultats
                    ports_str = ', '.join(map(str, open_ports))
                    result_text = "{}{}[{}] {}Found open ports on {}: {}{}".format(
                        colors.GREEN,
                        colors.BOLD,
                        datetime.now().strftime("%H:%M:%S"),
                        colors.WHITE,
                        host,
                        colors.YELLOW,
                        ports_str,
                        )
                    print(result_text)

                    logger.info("Open ports found", module="PortScanner",
                               host=host, ports=open_ports)

                # Mettre a jour la barre de progression
                if self.progress_bar:
                    self.progress_bar.update(increment=1)

        except Exception as e:
            logger.error("Host scan failed", module="PortScanner", host=host, error=str(e))

    def run(self):
        """Execute le scan de ports avec threading."""
        try:
            if not self.subdomains or not self.ports:
                logger.warning("Nothing to scan", module="PortScanner")
                return self.results

            total_hosts = len(self.subdomains)
            logger.info("Starting port scan", module="PortScanner",
                       hosts=total_hosts, ports=len(self.ports), max_threads=self.max_threads)

            # Initialiser la barre de progression
            self.progress_bar = ProgressBar(
                total=total_hosts,
                prefix="{}Scanning ports{}".format(colors.CYAN, colors.WHITE),
                suffix="hosts completed"
            )

            # Creer le pool de threads
            threads = []
            semaphore = threading.Semaphore(self.max_threads)

            def worker(host):
                with semaphore:
                    self.scan_host(host)

            # Lancer les threads
            for host in self.subdomains:
                thread = threading.Thread(target=worker, args=(host,))
                threads.append(thread)
                thread.start()

            # Attendre que tous les threads se terminent
            for thread in threads:
                thread.join()

            # Finaliser la barre de progression
            self.progress_bar.finish()

            # Resume des resultats
            total_open_ports = sum(len(ports) for ports in self.results.values())
            logger.info("Port scan completed", module="PortScanner",
                       hosts_with_open_ports=len(self.results),
                       total_open_ports=total_open_ports)

            if not logger.silent:
                summary_text = "{}Port scan summary: {} hosts with open ports, {} total open ports{}".format(
                    colors.GREEN, len(self.results), total_open_ports, colors.WHITE
                )
                print(summary_text)

            return self.results

        except Exception as e:
            logger.error("Port scan execution failed", module="PortScanner", error=str(e))
            return self.results
