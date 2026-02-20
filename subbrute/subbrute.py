#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SubBrute v1.2 - A (very) fast subdomain enumeration tool

This tool performs subdomain enumeration using DNS queries with multiple
resolvers and processes to maximize speed and reliability.

Maintained by rook
Contributors: JordanMilne, KxCode, rc0r, memoryprint, ppaulojr
Refactored with class-based architecture and enhanced logging
"""

from __future__ import annotations

import ctypes
import json
import logging
import multiprocessing
import optparse
import os
import queue
import random
import re
import signal
import sys
import time
import uuid
from collections.abc import Generator
from logging.handlers import RotatingFileHandler

import dns.rdatatype
import dns.resolver

#Microsoft compatiablity
if sys.platform.startswith('win'):
    #Drop-in replacement,  subbrute + multiprocessing throws exceptions on windows.
    import threading
    multiprocessing.Process = threading.Thread

class NameServerVerifier(multiprocessing.Process):
    """
    DNS nameserver verification process.

    This class runs as a separate process to verify that nameservers are working
    correctly and can detect wildcard DNS records. It tests each nameserver
    before adding it to the queue for use by lookup processes.

    Attributes:
        target (str): The target domain to test
        record_type (str): DNS record type to query (A, AAAA, etc.)
        resolver_q (Queue): Queue to store verified nameservers
        resolver_list (list): List of nameservers to verify
        wildcards (dict): Shared dictionary of wildcard IP addresses
        time_to_die (bool): Flag to signal process termination
    """

    def __init__(
        self,
        target: str,
        record_type: str | None,
        resolver_q: multiprocessing.Queue,
        resolver_list: list[str],
        wildcards: dict[str, None],
    ) -> None:
        """
        Initialize the nameserver verification process.

        Args:
            target (str): Target domain name
            record_type (str): DNS record type to query
            resolver_q (Queue): Queue for verified nameservers
            resolver_list (list): List of nameservers to test
            wildcards (dict): Shared wildcard dictionary

        Raises:
            Exception: If process initialization fails
        """
        try:
            multiprocessing.Process.__init__(self, target=self.run)
            self.daemon = True
            signal_init()

            logger.debug("Initializing NameServerVerifier for target: {}".format(target))

            self.time_to_die = False
            self.resolver_q = resolver_q
            self.wildcards = wildcards

            # Set record type with validation
            self.record_type = "A"
            if record_type and record_type.upper() in ["A", "AAAA", "CNAME", "MX", "TXT", "SOA"]:
                self.record_type = record_type.upper()
                logger.debug("Using DNS record type: {}".format(self.record_type))
            else:
                logger.warning("Invalid record type '{}', defaulting to 'A'".format(record_type))

            self.resolver_list = resolver_list if resolver_list else []
            self.target = target.lower().strip() if target else ""

            if not self.target:
                raise ValueError("Target domain cannot be empty")

            # Most popular website for latency testing
            self.most_popular_website = "www.google.com"

            # Initialize DNS resolver
            resolver = dns.resolver.Resolver()

            # Backup resolvers in case primary list fails
            self.backup_resolver = resolver.nameservers + ['127.0.0.1', '8.8.8.8', '8.8.4.4']

            # Configure resolver timeouts (aggressive for speed)
            resolver.timeout = 1
            resolver.lifetime = 1

            # Test connection latency with Google's DNS
            try:
                logger.debug("Testing connection latency with Google DNS")
                resolver.nameservers = ['8.8.8.8']
                resolver.query(self.most_popular_website, self.record_type)
                logger.debug("Connection test successful")
            except Exception as e:
                logger.warning("Connection test failed: {}. Using default resolver.".format(e))
                resolver = dns.resolver.Resolver()

            self.resolver = resolver
            logger.info(
                "NameServerVerifier initialized with {} nameservers to test".format(
                    len(self.resolver_list)
                )
            )

        except Exception as e:
            logger.error("Failed to initialize NameServerVerifier: {}".format(e))
            raise

    def end(self):
        """
        Signal the process to terminate gracefully.

        Sets the time_to_die flag which is checked in various loops
        to allow for clean shutdown.
        """
        logger.debug("NameServerVerifier received termination signal")
        self.time_to_die = True

    def add_nameserver(self, nameserver):
        """
        Add a verified nameserver to the queue for use by lookup processes.

        This method attempts to add a nameserver to the queue with a timeout
        to prevent blocking. It will retry if the queue is full but respect
        the termination signal.

        Args:
            nameserver (str): IP address of the nameserver to add

        Returns:
            bool: True if nameserver was added successfully, False otherwise
        """
        if not nameserver or not nameserver.strip():
            logger.warning("Attempted to add empty nameserver")
            return False

        nameserver = nameserver.strip()
        keep_trying = True
        retry_count = 0
        max_retries = 3

        while not self.time_to_die and keep_trying and retry_count < max_retries:
            try:
                self.resolver_q.put(nameserver, timeout=1)
                logger.debug("Successfully added nameserver: {}".format(nameserver))
                return True
            except Exception as e:
                if isinstance(e, queue.Full):
                    retry_count += 1
                    logger.debug(
                        "Queue full, retrying to add nameserver {nameserver} "
                        "(attempt {retry_count})"
                    )
                    keep_trying = True
                else:
                    logger.error(
                        "Unexpected error adding nameserver {nameserver}: {e}"
                    )
                    return False

        if retry_count >= max_retries:
            logger.warning(
                "Failed to add nameserver {nameserver} after {max_retries} retries"
            )

        return False

    def verify(self, nameserver_list):
        """
        Verify a list of nameservers for reliability and wildcard detection.

        Tests each nameserver to ensure it responds correctly and can detect
        wildcard DNS records. Only verified nameservers are added to the queue.

        Args:
            nameserver_list (list): List of nameserver IP addresses to verify

        Returns:
            bool: True if at least one nameserver was successfully verified
        """
        if not nameserver_list:
            logger.warning("Empty nameserver list provided for verification")
            return False

        added_resolver = False
        total_servers = len(nameserver_list)
        processed_count = 0

        logger.info("Starting verification of {total_servers} nameservers")

        for server in nameserver_list:
            if self.time_to_die:
                logger.debug("Termination signal received, stopping nameserver verification")
                break

            processed_count += 1
            server = server.strip()

            if not server:
                logger.debug(
                    "Skipping empty nameserver entry ({processed_count}/{total_servers})"
                )
                continue

            logger.debug(
                "Testing nameserver {server} ({processed_count}/{total_servers})"
            )

            # Validate IP address format
            if not self._is_valid_ip(server):
                logger.warning("Invalid IP address format: {server}")
                continue

            self.resolver.nameservers = [server]

            try:
                # Test basic connectivity
                logger.debug("Testing basic connectivity for {server}")
                test_result = self.resolver.query(self.most_popular_website, "A")

                if test_result:
                    logger.debug("Basic connectivity test passed for {server}")

                    # Test wildcard detection capability
                    if self.find_wildcards(self.target):
                        logger.debug("Wildcard detection successful for {server}")

                        if self.add_nameserver(server):
                            added_resolver = True
                            logger.info(
                                "Successfully verified and added nameserver: {server}"
                            )
                        else:
                            logger.warning(
                                "Failed to add verified nameserver {server} to queue"
                            )
                    else:
                        logger.warning(
                            "Rejected nameserver {server}: wildcard detection failed"
                        )
                else:
                    logger.warning(
                        "Rejected nameserver {server}: no response to test query"
                    )

            except dns.resolver.NXDOMAIN:
                logger.debug("Nameserver {server} returned NXDOMAIN for test query")
            except dns.resolver.Timeout:
                logger.debug("Nameserver {server} timed out during testing")
            except Exception:
                logger.debug(
                    "Rejected nameserver {server}: unexpected error"
                )

        _success_rate = (
            (processed_count / total_servers * 100) if total_servers > 0 else 0
        )
        logger.info(
            "Nameserver verification completed: "
            "{_success_rate:.1f}% processed, "
            "{'success' if added_resolver else 'no valid nameservers found'}"
        )

        return added_resolver

    def _is_valid_ip(self, ip_str):
        """
        Validate IP address format.

        Args:
            ip_str (str): IP address string to validate

        Returns:
            bool: True if valid IPv4 address, False otherwise
        """
        import socket
        try:
            socket.inet_aton(ip_str)
            return True
        except socket.error:
            return False

    def run(self):
        """
        Main execution method for the nameserver verification process.

        This method runs in a separate process and performs the following:
        1. Shuffles the resolver list to distribute load
        2. Attempts to verify nameservers from the main list
        3. Falls back to backup resolvers if needed
        4. Signals completion by adding False to the queue
        """
        try:
            logger.info("Starting NameServerVerifier process")

            # Shuffle resolver list to distribute traffic load across different users
            if self.resolver_list:
                random.shuffle(self.resolver_list)
                logger.debug(
                    "Shuffled resolver list of {len(self.resolver_list)} nameservers"
                )

            # Attempt to verify nameservers from the main list
            verification_successful = False
            if self.resolver_list:
                verification_successful = self.verify(self.resolver_list)

            # Fallback to backup resolvers if primary verification failed
            if not verification_successful:
                logger.warning("Primary nameserver verification failed, trying backup resolvers")
                backup_success = self.verify(self.backup_resolver)

                if not backup_success:
                    logger.error("All nameserver verification attempts failed")
                else:
                    logger.info("Backup nameserver verification successful")
            else:
                logger.info("Primary nameserver verification successful")

            # Signal end of nameserver list by adding False to queue
            logger.debug("Signaling end of nameserver verification")
            try:
                self.resolver_q.put(False, timeout=5)
                logger.debug("Successfully signaled end of verification")
            except Exception:
                logger.error("Failed to signal end of verification: {e}")

        except Exception:
            logger.error("Critical error in NameServerVerifier process: {e}")
            # Ensure we still signal completion even on error
            try:
                self.resolver_q.put(False, timeout=1)
            except Exception:
                pass
        finally:
            logger.info("NameServerVerifier process completed")

    def find_wildcards(self, host):
        """
        Detect wildcard DNS records for the given host using the current nameserver.

        This method solves three common DNS problems:
        1) The target domain might have wildcard DNS records
        2) The target might use geolocation-aware DNS
        3) The DNS server might respond to non-existent records with advertisements

        Args:
            host (str): The target hostname to test for wildcards

        Returns:
            bool: True if nameserver is suitable (no spam DNS, wildcards detected properly),
                  False if nameserver should be rejected
        """
        if not host:
            logger.warning("Empty host provided for wildcard detection")
            return False

        logger.debug("Starting wildcard detection for host: {host}")

        # Test for spam DNS servers (case #3)
        # These servers respond to any domain with advertisements
        try:
            spam_test_domain = uuid.uuid4().hex + ".com"
            logger.debug("Testing for spam DNS with domain: {spam_test_domain}")
            wildtest = self.resolver.query(spam_test_domain, "A")

            if len(wildtest):
                logger.warning(
                    "Spam DNS detected for nameserver "
                    "{self.resolver.nameservers}: responds to random domains"
                )
                return False
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            # This is expected - random domains should not resolve
            logger.debug("Spam DNS test passed - random domain correctly returned NXDOMAIN")
        except Exception:
            logger.debug("Spam DNS test inconclusive: {type(e).__name__}: {e}")

        # Test for wildcard records with multiple attempts
        test_counter = 8
        wildcards_found = 0
        looking_for_wildcards = True

        logger.debug("Starting wildcard detection with {test_counter} test iterations")

        while looking_for_wildcards and test_counter >= 0:
            looking_for_wildcards = False
            test_counter -= 1

            try:
                # Generate random subdomain for testing
                random_subdomain = uuid.uuid4().hex
                testdomain = "{}.{}".format(random_subdomain, host)

                logger.debug("Testing wildcard with domain: {testdomain}")
                wildtest = self.resolver.query(testdomain, self.record_type)

                # Process wildcard responses
                if wildtest:
                    for record in wildtest:
                        record_str = str(record)

                        if record_str not in self.wildcards:
                            # New wildcard detected
                            self.wildcards[record_str] = None
                            wildcards_found += 1
                            logger.debug("New wildcard detected: {record_str}")

                            # Continue looking for more wildcards
                            looking_for_wildcards = True
                        else:
                            logger.debug("Known wildcard found: {record_str}")

            except dns.resolver.NXDOMAIN:
                # Expected behavior - random subdomain should not exist
                logger.debug("NXDOMAIN received for test domain (expected behavior)")
                return True

            except dns.name.EmptyLabel:
                logger.debug("Empty label error received (expected behavior)")
                return True

            except dns.resolver.Timeout:
                logger.debug("Timeout during wildcard test (iteration {8-test_counter})")
                # Don't immediately fail on timeout, try a few more times

            except Exception:
                logger.warning(
                    "Wildcard detection error for nameserver "
                    "{self.resolver.nameservers}: {type(e).__name__}: {e}"
                )
                return False

        # Evaluate results
        if test_counter < 0 and looking_for_wildcards:
            logger.warning("Too many wildcards found for {host}, nameserver may be unreliable")
            return False

        if wildcards_found > 0:
            logger.info(
                "Wildcard detection completed: "
                "{wildcards_found} wildcard records found for {host}"
            )
        else:
            logger.debug("No wildcard records found for {host}")

        return True

class DNSLookupWorker(multiprocessing.Process):
    """
    DNS lookup worker process for subdomain enumeration.

    This class runs as a separate process to perform DNS lookups on subdomains.
    It manages its own set of nameservers and handles various DNS record types
    while filtering out wildcard responses.

    Attributes:
        in_q (Queue): Input queue containing domains to lookup
        out_q (Queue): Output queue for successful DNS resolutions
        resolver_q (Queue): Queue containing verified nameservers
        domain (str): Base domain being enumerated
        wildcards (dict): Shared dictionary of wildcard IP addresses
        spider_blacklist (dict): Domains already processed to avoid duplicates
        required_nameservers (int): Minimum nameservers needed for optimal performance
    """

    def __init__(
        self,
        in_q: multiprocessing.Queue,
        out_q: multiprocessing.Queue,
        resolver_q: multiprocessing.Queue,
        domain: str,
        wildcards: dict[str, None],
        spider_blacklist: dict[str, None],
    ) -> None:
        """
        Initialize the DNS lookup worker process.

        Args:
            in_q (Queue): Input queue for lookup tasks
            out_q (Queue): Output queue for results
            resolver_q (Queue): Queue of verified nameservers
            domain (str): Target domain name
            wildcards (dict): Shared wildcard dictionary
            spider_blacklist (dict): Processed domains dictionary

        Raises:
            ValueError: If required parameters are missing
            Exception: If process initialization fails
        """
        try:
            multiprocessing.Process.__init__(self, target=self.run)
            signal_init()

            # Validate inputs
            if not domain or not domain.strip():
                raise ValueError("Domain cannot be empty")

            logger.debug("Initializing DNSLookupWorker for domain: {domain}")

            self.required_nameservers = 16  # Optimal number of nameservers per worker
            self.in_q = in_q
            self.out_q = out_q
            self.resolver_q = resolver_q
            self.domain = domain.lower().strip()
            self.wildcards = wildcards if wildcards is not None else {}
            self.spider_blacklist = spider_blacklist if spider_blacklist is not None else {}

            # Initialize DNS resolver with empty nameserver list
            self.resolver = dns.resolver.Resolver()
            self.resolver.nameservers = []  # Will be populated from resolver_q

            # Configure resolver timeouts for performance
            self.resolver.timeout = 2
            self.resolver.lifetime = 5

            logger.debug("DNSLookupWorker initialized successfully")

        except Exception:
            logger.error("Failed to initialize DNSLookupWorker: {e}")
            raise

    def get_nameserver(self):
        """
        Get a nameserver from the queue without blocking.

        Returns:
            list: List containing one nameserver IP, or empty list if none available
        """
        try:
            nameserver = self.resolver_q.get_nowait()
            if nameserver is False:
                # End marker detected, put it back for other processes
                self.resolver_q.put(False)
                logger.debug("End of nameserver queue detected")
                return []

            logger.debug("Retrieved nameserver from queue: {nameserver}")
            return [nameserver]

        except Exception:
            # Queue is empty or other error occurred
            logger.debug("No nameserver available from queue: {type(e).__name__}")
            return []

    def get_nameserver_blocking(self):
        """
        Get a nameserver from the queue with blocking.

        This method will wait until a nameserver becomes available or
        the end marker is reached.

        Returns:
            list: List containing one nameserver IP, or empty list if queue is exhausted
        """
        try:
            nameserver = self.resolver_q.get(timeout=10)  # 10 second timeout

            if nameserver is False:
                logger.debug("Nameserver queue is exhausted")
                # Put the end marker back for other processes
                self.resolver_q.put(False)
                return []

            logger.debug("Retrieved nameserver (blocking): {nameserver}")
            return [nameserver]

        except Exception:
            logger.warning(
                "Failed to get nameserver (blocking): {type(e).__name__}: {e}"
            )
            return []

    def check(self, host, record_type="A", retries=0):
        """Perform a DNS lookup for the given host and record type.

        Handles retries, timeouts, NXDOMAIN, and wildcard filtering.
        CNAME lookups will follow the chain up to 20 levels deep.

        Args:
            host: The hostname to resolve.
            record_type: DNS record type (e.g. "A", "CNAME", "AAAA").
            retries: Current retry count for timeout handling.

        Returns:
            DNS response records, a CNAME chain list, or False on failure.
        """
        trace("Checking:", host)
        cname_record = []
        retries = 0
        if len(self.resolver.nameservers) <= self.required_nameservers:
            #This process needs more nameservers,  lets see if we have one avaible
            self.resolver.nameservers += self.get_nameserver()
        #Ok we should be good to go.
        while True:
            try:
                #Query the nameserver, this is not simple...
                if not record_type or record_type == "A":
                    resp = self.resolver.query(host)
                    #Crawl the response
                    hosts = extract_hosts(str(resp.response), self.domain)
                    for h in hosts:
                        if h not in self.spider_blacklist:
                            self.spider_blacklist[h] = None
                            trace("Found host with spider:", h)
                            self.in_q.put((h, record_type, 0))
                    return resp
                if record_type == "CNAME":
                    #A max 20 lookups
                    for _x in range(20):
                        try:
                            resp = self.resolver.query(host, record_type)
                        except dns.resolver.NoAnswer:
                            resp = False
                        if resp and resp[0]:
                            host = str(resp[0]).rstrip(".")
                            cname_record.append(host)
                        else:
                            return cname_record
                else:
                    #All other records:
                    return self.resolver.query(host, record_type)

            except Exception as e:
                if type(e) is dns.resolver.NoNameservers:
                    #We should never be here.
                    #We must block,  another process should try this host.
                    #do we need a limit?
                    self.in_q.put((host, record_type, 0))
                    self.resolver.nameservers += self.get_nameserver_blocking()
                    return False
                elif type(e) is dns.resolver.NXDOMAIN:
                    #"Non-existent domain name."
                    return False
                elif type(e) is dns.resolver.NoAnswer:
                    #"The response did not contain an answer."
                    if retries >= 1:
                        trace("NoAnswer retry")
                        return False
                    retries += 1
                elif type(e) is dns.resolver.Timeout:
                    trace("lookup failure:", host, retries)
                    #Check if it is time to give up.
                    if retries >= 3:
                        if retries > 3:
                            #Sometimes 'internal use' subdomains will timeout
                            #for every request.
                            #As far as I'm concerned, the authorative name
                            #server has told us this domain exists,
                            #we just can't know the address value using
                            #this method.
                            return [
                                'Mutiple Query Timeout - '
                                'External address resolution was restricted'
                            ]
                        else:
                            #Maybe another process can take a crack at it.
                            self.in_q.put((host, record_type, retries + 1))
                        return False
                    retries += 1
                    #retry...
                elif type(e) is IndexError:
                    #Some old versions of dnspython throw this error,
                    #doesn't seem to affect the results,  and it was fixed
                    #in later versions.
                    pass
                elif type(e) is TypeError:
                    # We'll get here if the number procs > number of resolvers.
                    # This is an internal error do we need a limit?
                    self.in_q.put((host, record_type, 0))
                    return False
                elif type(e) is dns.rdatatype.UnknownRdatatype:
                    error("DNS record type not supported:", record_type)
                else:
                    trace("Problem processing host:", host)
                    #dnspython threw some strange exception...
                    raise e

    def run(self):
        """Main execution loop for the DNS lookup worker process.

        Pulls work items from the input queue, performs DNS lookups, filters
        wildcard responses, and pushes valid results to the output queue.
        """
        #This process needs one resolver before it can start looking.
        self.resolver.nameservers += self.get_ns_blocking()
        while True:
            found_addresses = []
            work = self.in_q.get()
            #Check if we have hit the end marker
            while not work:
                #Look for a re-queued lookup
                try:
                    work = self.in_q.get(blocking=False)
                    #if we took the end marker of the queue we need to put it back
                    if work:
                        self.in_q.put(False)
                except Exception:  # Queue.Empty
                    trace('End of work queue')
                    #There isn't an item behind the end marker
                    work = False
                    break
            #Is this the end all work that needs to be done?
            if not work:
                #Perpetuate the end marker for all threads to see
                self.in_q.put(False)
                #Notify the parent that we have died of natural causes
                self.out_q.put(False)
                break
            else:
                if len(work) == 3:
                    #keep track of how many times this lookup has timedout.
                    (hostname, record_type, timeout_retries) = work
                    response = self.check(hostname, record_type, timeout_retries)
                else:
                    (hostname, record_type) = work
                    response = self.check(hostname, record_type)
                sys.stdout.flush()
                trace(response)
                #self.wildcards is populated by the NameServerVerifier() process.
                #This variable doesn't need a mutex, because it has a queue.
                #A queue ensures nameserver cannot be used before its wildcard
                #entries are found.
                reject = False
                if response:
                    for a in response:
                        a = str(a)
                        if a in self.wildcards:
                            trace("resolved wildcard:", hostname)
                            reject = True
                            #reject this domain.
                            break
                        else:
                            found_addresses.append(a)
                    if not reject:
                        #This request is filled, send the results back
                        result = (hostname, record_type, found_addresses)
                        self.out_q.put(result)

class SubBrute:
    """
    Main SubBrute orchestrator class for subdomain enumeration.

    This class coordinates the subdomain enumeration process by managing:
    - DNS nameserver verification processes
    - Multiple DNS lookup worker processes
    - Input/output queues for distributed processing
    - Results collection and filtering

    Attributes:
        target (str): Target domain name
        record_type (str): DNS record type to query
        subdomains_file (str): Path to subdomains wordlist
        resolvers_file (str): Path to DNS resolvers list
        process_count (int): Number of worker processes
        debug (bool): Enable debug logging
    """

    def __init__(self, target: str, record_type: str | None = None, subdomains_file: str = "names.txt",
                 resolvers_file: str = "resolvers.txt", process_count: int = 16, debug: bool = True) -> None:
        """
        Initialize SubBrute instance.

        Args:
            target (str): Target domain name
            record_type (str): DNS record type (A, AAAA, CNAME, etc.)
            subdomains_file (str): Path to subdomains wordlist
            resolvers_file (str): Path to DNS resolvers list
            process_count (int): Number of worker processes
            debug (bool): Enable debug logging

        Raises:
            ValueError: If target domain is invalid
            FileNotFoundError: If required files don't exist
        """
        # Input validation
        if not target or not target.strip():
            raise ValueError("Target domain cannot be empty")

        self.target = target.lower().strip()
        self.record_type = record_type.upper() if record_type else "A"
        self.subdomains_file = subdomains_file
        self.resolvers_file = resolvers_file
        self.process_count = max(1, min(process_count, 64))  # Reasonable limits
        self.debug = debug

        # Update global logger debug setting
        global logger
        logger.debug_enabled = debug

        # Initialize statistics
        self.stats = {
            'subdomains_processed': 0,
            'successful_lookups': 0,
            'wildcard_filtered': 0,
            'nameservers_verified': 0,
            'start_time': None,
            'end_time': None
        }

        logger.info(
            "SubBrute initialized - Target: {}, Record Type: {}".format(
                self.target, self.record_type
            )
        )
        logger.debug(
            "Configuration: {} processes, Debug: {}".format(
                self.process_count, self.debug
            )
        )

    def load_wordlists(self):
        """
        Load subdomains and resolvers from files.

        Returns:
            tuple: (subdomains_list, resolvers_list)

        Raises:
            FileNotFoundError: If wordlist files don't exist
            ValueError: If files are empty
        """
        logger.debug(
            "Loading wordlists - Subdomains: {self.subdomains_file}, "
            "Resolvers: {self.resolvers_file}"
        )

        try:
            subdomains = check_open(self.subdomains_file)
            resolvers = check_open(self.resolvers_file)

            logger.info(
                "Loaded {len(subdomains)} subdomains and {len(resolvers)} resolvers"
            )

            # Validate resolver-to-process ratio
            if (len(resolvers) / 16) < self.process_count:
                logger.warning(
                    "Only {len(resolvers)/self.process_count:.1f} resolvers "
                    "per process. Consider adding more nameservers."
                )

            return subdomains, resolvers

        except Exception:
            logger.error("Failed to load wordlists: {e}")
            raise

    def run_enumeration(self):
        """
        Execute the complete subdomain enumeration process.

        Returns:
            generator: Yields (hostname, record_type, addresses) tuples
        """
        self.stats['start_time'] = time.time()
        logger.info("Starting subdomain enumeration for {}".format(self.target))

        try:
            # Load wordlists
            subdomains, resolvers = self.load_wordlists()

            # Setup shared data structures
            if os.name == 'nt':
                # Windows compatibility - use regular dicts
                wildcards = {}
                spider_blacklist = {}
                logger.debug("Using regular dictionaries (Windows compatibility)")
            else:
                # Unix systems - use managed shared dictionaries
                wildcards = multiprocessing.Manager().dict()
                spider_blacklist = multiprocessing.Manager().dict()
                logger.debug("Using multiprocessing managed dictionaries")

            # Create processing queues
            input_queue = multiprocessing.Queue()
            output_queue = multiprocessing.Queue()
            resolver_queue = multiprocessing.Queue(maxsize=2)

            logger.debug("Created processing queues")

            # Start nameserver verification process
            logger.info("Starting nameserver verification process")
            nameserver_verifier = NameServerVerifier(
                self.target, self.record_type, resolver_queue, resolvers, wildcards
            )
            nameserver_verifier.start()

            # Add target domain to processing queue
            input_queue.put((self.target, self.record_type))
            spider_blacklist[self.target] = None
            logger.debug(
                "Added target domain {self.target} to processing queue"
            )

            # Add subdomains to processing queue
            subdomain_count = 0
            for subdomain in subdomains:
                subdomain = str(subdomain).strip()
                if not subdomain:
                    continue

                # Handle CSV format (be forgiving)
                if "," in subdomain:
                    subdomain = subdomain.split(",")[0].strip()

                # Create full hostname
                if not subdomain.endswith(self.target):
                    hostname = "{}.{}".format(subdomain, self.target)
                else:
                    hostname = subdomain

                # Avoid duplicates
                if hostname not in spider_blacklist:
                    spider_blacklist[hostname] = None
                    input_queue.put((hostname, self.record_type))
                    subdomain_count += 1

            logger.info("Added {subdomain_count} subdomains to processing queue")

            # Add end marker to input queue
            input_queue.put(False)

            # Start DNS lookup worker processes
            logger.info(
                "Starting {self.process_count} DNS lookup worker processes"
            )
            workers = []
            for i in range(self.process_count):
                worker = DNSLookupWorker(
                    input_queue, output_queue, resolver_queue,
                    self.target, wildcards, spider_blacklist
                )
                worker.start()
                workers.append(worker)
                logger.debug(
                    "Started worker process {i+1}/{self.process_count}"
                )

            # Collect results
            active_workers = self.process_count
            results_count = 0

            logger.info("Starting result collection")

            while active_workers > 0:
                try:
                    result = output_queue.get(timeout=10)

                    if result is False:
                        # Worker finished
                        active_workers -= 1
                        logger.debug(
                            "Worker finished, {active_workers} remaining"
                        )
                        continue

                    # Process valid result
                    results_count += 1
                    self.stats['successful_lookups'] += 1

                    logger.debug("Result #{results_count}: {result[0]}")
                    yield result

                except Exception as e:
                    if "timeout" in str(e).lower():
                        logger.debug(
                            "Result collection timeout, checking worker status"
                        )
                        # Check if workers are still alive
                        alive_workers = sum(
                            1 for w in workers if w.is_alive()
                        )
                        if alive_workers == 0:
                            logger.info("All workers have finished")
                            break
                    else:
                        logger.error("Error collecting results: {e}")

            logger.info(
                "Result collection completed: "
                "{results_count} successful lookups"
            )

            # Cleanup
            logger.debug("Cleaning up processes")
            try:
                nameserver_verifier.end()
                nameserver_verifier.join(timeout=5)
                if nameserver_verifier.is_alive():
                    nameserver_verifier.terminate()
            except Exception:
                pass

            for worker in workers:
                try:
                    worker.join(timeout=2)
                    if worker.is_alive():
                        worker.terminate()
                except Exception:
                    pass

        except Exception:
            logger.error("Critical error during enumeration: {e}")
            raise

        finally:
            self.stats['end_time'] = time.time()
            self._log_final_stats()

    def _log_final_stats(self):
        """Log final enumeration statistics."""
        if self.stats['start_time'] and self.stats['end_time']:
            _duration = self.stats['end_time'] - self.stats['start_time']
            logger.info("Enumeration completed in {_duration:.2f} seconds")
            logger.info(
                "Statistics: {self.stats['successful_lookups']} successful lookups"
            )

#Extract relevant hosts
#The dot at the end of a domain signifies the root,
#and all TLDs are subs of the root.
host_match = re.compile(
    r"((?<=[\s])[a-zA-Z0-9_-]+\.(?:[a-zA-Z0-9_-]+\.?)+(?=[\s]))"
)
def extract_hosts(data: str, hostname: str) -> list[str]:
    """Extract hostnames from DNS response data that belong to the target domain.

    Args:
        data: Raw DNS response text to search.
        hostname: Target domain to filter results by.

    Returns:
        list: Matching hostnames found in the data.
    """
    #made a global to avoid re-compilation
    global host_match
    ret = []
    hosts = re.findall(host_match, data)
    for fh in hosts:
        host = fh.rstrip(".")
        #Is this host in scope?
        if host.endswith(hostname):
            ret.append(host)
    return ret

#Return a list of unique sub domains,  sorted by frequency.
#Only match domains that have 3 or more sections subdomain.domain.tld
domain_match = re.compile(
    r"([a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)+"
)
def extract_subdomains(file_name: str) -> list[str]:
    """Extract unique subdomains from a file, sorted by frequency.

    Parses a file for domain-like patterns with at least 3 segments, strips
    TLD and domain portions, and returns subdomain labels sorted by occurrence.

    Args:
        file_name: Path to the file to extract subdomains from.

    Returns:
        list: Subdomain labels sorted by frequency in descending order.
    """
    #Avoid re-compilation
    global domain_match
    subs = {}
    sub_file = open(file_name).read()
    f_all = re.findall(domain_match, sub_file)
    del sub_file
    for i in f_all:
        if i.find(".") >= 0:
            p = i.split(".")[0:-1]
            #gobble everything that might be a TLD
            while p and len(p[-1]) <= 3:
                p = p[0:-1]
            #remove the domain name
            p = p[0:-1]
            #do we have a subdomain.domain left?
            if len(p) >= 1:
                trace(str(p), " : ", i)
                for q in p:
                    if q:
                        #domain names can only be lower case.
                        q = q.lower()
                        if q in subs:
                            subs[q] += 1
                        else:
                            subs[q] = 1
    #Free some memory before the sort...
    del f_all
    #Sort by freq in desc order
    subs_sorted = sorted(subs.keys(), key=lambda x: subs[x], reverse=True)
    return subs_sorted

def print_target(
    target: str, record_type: str | None = None, subdomains: str = "names.txt",
    resolve_list: str = "resolvers.txt", process_count: int = 16,
    output: bool = False, json_output: bool = False, found_subdomains: list[str] | None = None,
    verbose: bool = False
) -> set[str]:
    """Enumerate subdomains for a target and return unique results.

    Wraps the ``run`` generator and collects results, filtering out
    previously found subdomains.

    Args:
        target: Target domain name to enumerate.
        record_type: DNS record type (e.g. "A", "CNAME"), or None.
        subdomains: Path to the subdomains wordlist file.
        resolve_list: Path to the DNS resolvers file.
        process_count: Number of worker processes to spawn.
        output: File handle for greppable output, or False.
        json_output: File handle for JSON output, or False.
        found_subdomains: Previously discovered subdomains to exclude.
        verbose: If True, print results to stdout.

    Returns:
        set: Unique subdomains discovered during enumeration.
    """
    if found_subdomains is None:
        found_subdomains = []
    subdomains_list = []
    _results_temp = []
    run(target, record_type, subdomains, resolve_list, process_count)
    for result in run(target, record_type, subdomains, resolve_list, process_count):
        (hostname, record_type, response) = result
        if not record_type:
            result = hostname
        else:
            result = "%s,%s" % (hostname, ",".join(response).strip(","))
        if result not in found_subdomains:
            if verbose:
                print(result)
            subdomains_list.append(result)

    return set(subdomains_list)

def run(
    target: str, record_type: str | None = None, subdomains: str = "names.txt",
    resolve_list: str = "resolvers.txt", process_count: int = 16
) -> Generator[tuple[str, str | None, list[str]], None, None]:
    """Run subdomain enumeration as a generator, yielding results as they arrive.

    Spawns nameserver verification and DNS lookup worker processes, feeds them
    a wordlist of subdomains, and yields (hostname, record_type, addresses)
    tuples for each successful resolution.

    Args:
        target: Target domain name.
        record_type: DNS record type, or None for default "A".
        subdomains: Path to the subdomains wordlist file.
        resolve_list: Path to the DNS resolvers file.
        process_count: Number of lookup worker processes.

    Yields:
        tuple: (hostname, record_type, addresses) for each resolved subdomain.
    """
    subdomains = check_open(subdomains)
    resolve_list = check_open(resolve_list)
    if (len(resolve_list) / 16) < process_count:
        sys.stderr.write(
            'Warning: Fewer than 16 resolvers per thread, '
            'consider adding more nameservers to resolvers.txt.\n'
        )
    if os.name == 'nt':
        wildcards = {}
        spider_blacklist = {}
    else:
        wildcards = multiprocessing.Manager().dict()
        spider_blacklist = multiprocessing.Manager().dict()
    in_q = multiprocessing.Queue()
    out_q = multiprocessing.Queue()
    #have a buffer of at most two new nameservers that lookup processes can draw from.
    resolve_q = multiprocessing.Queue(maxsize=2)

    #Make a source of fast nameservers avaiable for other processes.
    verify_nameservers_proc = NameServerVerifier(
        target, record_type, resolve_q, resolve_list, wildcards
    )
    verify_nameservers_proc.start()
    #The empty string
    in_q.put((target, record_type))
    spider_blacklist[target] = None
    #A list of subdomains is the input
    for s in subdomains:
        s = str(s).strip()
        if s:
            if "," in s:
                #SubBrute should be forgiving, a comma will never be in a url
                #but the user might try an use a CSV file as input.
                s = s.split(",")[0]
            if not s.endswith(target):
                hostname = "%s.%s" % (s, target)
            else:
                #A user might feed an output list as a subdomain list.
                hostname = s
            if hostname not in spider_blacklist:
                spider_blacklist[hostname] = None
                work = (hostname, record_type)
                in_q.put(work)
    #Terminate the queue
    in_q.put(False)
    for _i in range(process_count):
        worker = DNSLookupWorker(
            in_q, out_q, resolve_q, target, wildcards, spider_blacklist
        )
        worker.start()
    threads_remaining = process_count
    while True:
        try:
            #The output is valid hostnames
            result = out_q.get(True, 10)
            #we will get an empty exception before this runs.
            if not result:
                threads_remaining -= 1
            else:
                #run() is a generator, and yields results from the work queue
                yield result
        except Exception as e:
            #The cx_freeze version uses queue.Empty instead of Queue.Empty :(
            if isinstance(e, queue.Empty):
                pass
            else:
                raise e
        #make sure everyone is complete
        if threads_remaining <= 0:
            break
    trace("killing nameserver process")
    #We no longer require name servers.
    try:
        killproc(pid=verify_nameservers_proc.pid)
    except Exception:
        #Windows threading.tread
        verify_nameservers_proc.end()
    trace("End")

#exit handler for signals.  So ctrl+c will work.
#The 'multiprocessing' library each process is it's own process which
#side-steps the GIL
#If the user wants to exit prematurely,  each process must be killed.
def killproc(signum: int = 0, frame: int = 0, pid: int | bool = False) -> None:
    """Kill a process by PID. Used as a signal handler for clean shutdown.

    Args:
        signum: Signal number (unused, required by signal handler signature).
        frame: Stack frame (unused, required by signal handler signature).
        pid: Process ID to kill. If False, kills the current process.
    """
    if not pid:
        pid = os.getpid()
    if sys.platform.startswith('win'):
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(1, 0, pid)
            kernel32.TerminateProcess(handle, 0)
        except Exception:
            #Oh windows.
            pass
    else:
        os.kill(pid, 9)

class ColoredLogger:
    """
    Enhanced logger class with colored console output and file logging.
    Provides debug, info, warning, and error logging levels with proper formatting.
    """

    # Console color codes
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }

    def __init__(self, name: str = "SubBrute", log_file: str = "subbrute.log", debug: bool = True) -> None:
        """
        Initialize the colored logger.

        Args:
            name (str): Logger name
            log_file (str): Path to log file
            debug (bool): Enable debug mode
        """
        self.debug_enabled = debug
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)

        # Clear existing handlers
        self.logger.handlers.clear()

        # Create formatters
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        _console_formatter = logging.Formatter('%(levelname)s - %(message)s')

        # File handler with rotation
        try:
            file_handler = RotatingFileHandler(
                log_file, maxBytes=10*1024*1024, backupCount=5
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            print("Warning: Could not create log file {}: {}".format(log_file, e))

        # Console handler
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(logging.DEBUG if debug else logging.INFO)
        console_handler.setFormatter(_console_formatter)
        self.logger.addHandler(console_handler)

    def _log_with_color(self, level, message):
        """
        Log message with color formatting for console output.

        Args:
            level (str): Log level
            message (str): Message to log
        """
        color = self.COLORS.get(level, self.COLORS['RESET'])
        reset = self.COLORS['RESET']

        # Format message for console with colors
        colored_message = "{}{} - {}{}".format(color, level, message, reset)

        # Log to file without colors
        getattr(self.logger, level.lower())(message)

        # Print colored version to console manually to override formatter
        if level == 'DEBUG' and not self.debug_enabled:
            return

        sys.stderr.write(colored_message + "\n")

    def debug(self, *args):
        """Log debug message."""
        if self.debug_enabled:
            message = ' '.join(str(arg) for arg in args)
            self.logger.debug(message)

    def info(self, *args):
        """Log info message."""
        message = ' '.join(str(arg) for arg in args)
        self.logger.info(message)

    def warning(self, *args):
        """Log warning message."""
        message = ' '.join(str(arg) for arg in args)
        self.logger.warning(message)

    def error(self, *args):
        """Log error message."""
        message = ' '.join(str(arg) for arg in args)
        self.logger.error(message)

    def critical(self, *args):
        """Log critical message and exit."""
        message = ' '.join(str(arg) for arg in args)
        self.logger.critical(message)
        sys.exit(1)

# Global logger instance - set debug=False for Python 2 compatibility
logger = ColoredLogger(debug=False)

# Legacy functions for backward compatibility
def trace(*args: object, **kwargs: object) -> None:
    """Legacy trace function - now uses debug logging."""
    logger.debug(*args)

def error(*args: object, **kwargs: object) -> None:
    """Legacy error function - now uses critical logging."""
    logger.critical(*args)

def check_open(input_file: str) -> list[str]:
    """Open and read a file, returning its lines. Exits on failure.

    Args:
        input_file: Path to the file to read.

    Returns:
        list: Lines from the file.
    """
    ret = []
    #If we can't find a resolver from an input file, then we need to improvise.
    try:
        ret = open(input_file).readlines()
    except Exception:
        error("File not found:", input_file)
    if not len(ret):
        error("File is empty:", input_file)
    return ret

#Every 'multiprocessing' process needs a signal handler.
#All processes need to die, we don't want to leave zombies.
def signal_init() -> None:
    """Register signal handlers for clean process termination.

    Sets SIGINT, SIGTSTP, and SIGQUIT to call killproc, preventing zombie
    processes when the user interrupts execution.
    """
    #Escalate signal to prevent zombies.
    signal.signal(signal.SIGINT, killproc)
    try:
        signal.signal(signal.SIGTSTP, killproc)
        signal.signal(signal.SIGQUIT, killproc)
    except Exception:
        #Windows
        pass

if __name__ == "__main__":
    if getattr(sys, 'frozen', False):
        # cx_freeze windows:
        base_path = os.path.dirname(sys.executable)
        multiprocessing.freeze_support()
    else:
        #everything else:
        base_path = os.path.dirname(os.path.realpath(__file__))
    parser = optparse.OptionParser("usage: %prog [options] target")
    parser.add_option(
        "-s", "--subs", dest="subs",
        default=os.path.join(base_path, "names.txt"),
        type="string",
        help="(optional) list of subdomains,  default = 'names.txt'"
    )
    parser.add_option(
        "-r", "--resolvers", dest="resolvers",
        default=os.path.join(base_path, "resolvers.txt"),
        type="string",
        help=(
            "(optional) A list of DNS resolvers, if this list is empty "
            "it will OS's internal resolver default = 'resolvers.txt'"
        )
    )
    parser.add_option(
        "-t", "--targets_file", dest="targets", default="",
        type="string",
        help=(
            "(optional) A file containing a newline delimited "
            "list of domains to brute force."
        )
    )
    parser.add_option(
        "-o", "--output", dest="output", default=False,
        help="(optional) Output to file (Greppable Format)"
    )
    parser.add_option(
        "-j", "--json", dest="json", default=False,
        help="(optional) Output to file (JSON Format)"
    )
    parser.add_option(
        "-a", "-A", action='store_true', dest="ipv4", default=False,
        help="(optional) Print all IPv4 addresses for sub domains (default = off)."
    )
    parser.add_option(
        "--type", dest="type", default=False,
        type="string",
        help=(
            "(optional) Print all reponses for an arbitrary DNS "
            "record type (CNAME, AAAA, TXT, SOA, MX...)"
        )
    )
    parser.add_option(
        "-c", "--process_count", dest="process_count",
        default=16, type="int",
        help="(optional) Number of lookup theads to run. default = 16"
    )
    parser.add_option(
        "-", "--filter_subs", dest="filter", default="",
        type="string",
        help=(
            "(optional) A file containing unorganized domain names "
            "which will be filtered into a list of subdomains sorted "
            "by frequency.  This was used to build names.txt."
        )
    )
    parser.add_option(
        "-v", "--verbose", action='store_true', dest="verbose",
        default=False,
        help="(optional) Print debug information."
    )
    (options, args) = parser.parse_args()


    verbose = options.verbose

    if len(args) < 1 and options.filter == "" and options.targets == "":
        parser.error("You must provide a target. Use -h for help.")

    if options.filter != "":
        #cleanup this file and print it out
        for d in extract_subdomains(options.filter):
            print(d)
        sys.exit()

    if options.targets != "":
        targets = check_open(options.targets)  # the domains
    else:
        targets = args  # multiple arguments on the cli

    output = False
    if options.output:
        try:
            output = open(options.output, "w")
        except Exception:
            error("Failed writing to file:", options.output)

    json_output = False
    if options.json:
        try:
            json_output = open(options.json, "w")
        except Exception:
            error("Failed writing to file:", options.json)

    record_type = False
    if options.ipv4:
        record_type = "A"
    if options.type:
        record_type = str(options.type).upper()

    # Process each target domain
    for target in targets:
        target = target.strip()
        if not target:
            continue

        logger.info("Starting enumeration for target: {}".format(target))

        try:
            # Create SubBrute instance with enhanced configuration
            subbrute = SubBrute(
                target=target,
                record_type=record_type,
                subdomains_file=options.subs,
                resolvers_file=options.resolvers,
                process_count=options.process_count,
                debug=options.verbose
            )

            # Execute enumeration and process results
            result_count = 0
            for hostname, dns_record_type, addresses in subbrute.run_enumeration():
                result_count += 1

                # Format result
                if not dns_record_type:
                    formatted_result = hostname
                else:
                    formatted_result = "{},{}".format(
                        hostname, ','.join(addresses).strip(',')
                    )

                # Output to console
                print(formatted_result)

                # Output to file if specified
                if output:
                    try:
                        output.write(formatted_result + "\n")
                        output.flush()
                    except Exception:
                        logger.error("Error writing to output file: {e}")

                # Output to JSON file if specified
                if json_output:
                    try:
                        json_record = {
                            "hostname": hostname,
                            "record_type": dns_record_type,
                            "addresses": addresses,
                            "timestamp": time.time()
                        }
                        json_output.write(json.dumps(json_record) + "\n")
                        json_output.flush()
                    except Exception:
                        logger.error("Error writing JSON output: {e}")

            logger.info(
                "Enumeration completed for {target}: "
                "{result_count} results found"
            )

        except KeyboardInterrupt:
            logger.warning("Enumeration interrupted by user")
            break
        except Exception:
            logger.error("Error processing target {target}: {e}")
            continue

    # Close output files
    try:
        if output:
            output.close()
        if json_output:
            json_output.close()
    except Exception:
        logger.error("Error closing output files: {e}")

    logger.info("SubBrute execution completed")
