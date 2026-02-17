#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import itertools
import requests
import socket
import ssl
import argparse
import dns.resolver
import threading
import time
import re
import queue
import ipaddress
import api_keys
import urllib3
from time import sleep

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_banner = """\033[1;33;49m
 _____           _   _____                       _
/  __ \         | | /  __ \                     | |
| /  \/ ___ _ __| |_| /  \/_ __ _   _ _ __   ___| |__  _   _
| |    / _ \ '__| __| |   | '__| | | | '_ \ / __| '_ \| | | |
| \__/\  __/ |  | |_| \__/\ |  | |_| | | | | (__| | | | |_| |
 \____/\___|_|   \__|\____/_|   \__,_|_| |_|\___|_| |_|\__, |
                                                        __/ |
                                                       |___/
    \033[1;31;49mJust a silly recon tool...
    @_w_m__\033[0;37;49m
"""

_transparency_endpoint = "https://crt.sh/?q=%.{query}&output=json"
_censys_endpoint = "https://www.censys.io/api/v1"
_certdb_endpoint = "https://certdb.com/api?q={query}"
_certspotter_endpoint = "https://certspotter.com/api/v0/certs?domain={query}"
_vt_domainsearch_endpoint = "https://www.virustotal.com/vtapi/v2/domain/report"
_vt_ipsearch_endpoint = "https://www.virustotal.com/vtapi/v2/ip-address/report"
_riskiq_endpoint = "https://api.passivetotal.org"
_potential_hosts = []
_resolving_hosts = {}
_port = 443
_threads = 20
_delay = 3
_timeout = 3

_ssl_context = ssl.create_default_context()
_ssl_context.check_hostname = False

_requests_session = None


def get_requests_session():
    global _requests_session
    if _requests_session is None:
        _requests_session = requests.Session()
        _requests_session.verify = False
    return _requests_session


def strip_wildcard(hostname):
    return hostname[2:] if hostname.startswith("*.") else hostname


def is_valid_hostname(hostname):
    if len(hostname) > 253:
        return False
    if hostname.endswith("."):
        hostname = hostname[:-1]
    allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))


class CertThread(threading.Thread):
    def __init__(self, jobqueue, resultqueue):
        super().__init__()
        self.jobs = jobqueue
        self.results = resultqueue
        self.stop_received = False
        self.daemon = True

    def get_names(self, host, port):
        result = []
        try:
            sock = socket.socket(socket.AF_INET)
            sock.settimeout(1.0)
            conn = _ssl_context.wrap_socket(sock)
            conn.connect((host, port))
            cert = conn.getpeercert()
            conn.close()

            if "subject" in cert:
                for field in cert["subject"]:
                    if field[0][0] == "commonName":
                        name = strip_wildcard(field[0][1])
                        result.append(name)
                        print(f"[Found] {name}")

            if "subjectAltName" in cert:
                for field in cert["subjectAltName"]:
                    if field[0] == "DNS":
                        name = strip_wildcard(field[1])
                        result.append(name)
                        print(f"[Found] {name}")

        except (socket.gaierror, socket.timeout, ssl.SSLError,
                ConnectionResetError, ConnectionRefusedError, OSError):
            return None

        return result if result else None

    def stop(self):
        self.stop_received = True

    def run(self):
        while not self.stop_received:
            try:
                host = self.jobs.get_nowait()
                names = self.get_names(host, _port)
                if names:
                    self.results.put(names)
                self.jobs.task_done()
            except queue.Empty:
                sleep(0.1)
            except Exception as ex:
                print(f"Error processing {host}: {ex}")


class DnsThread(threading.Thread):
    def __init__(self, jobqueue, resultqueue):
        super().__init__()
        self.jobs = jobqueue
        self.results = resultqueue
        self.stop_received = False
        self.daemon = True

    def get_a_records(self, hostname):
        try:
            answers = dns.resolver.resolve(hostname, "A")
            return [answer.to_text() for answer in answers]
        except Exception:
            return None

    def stop(self):
        self.stop_received = True

    def run(self):
        while not self.stop_received:
            try:
                host = self.jobs.get_nowait()
                ips = self.get_a_records(host)
                if ips:
                    self.results.put({"host": host, "ips": ips})
                self.jobs.task_done()
            except queue.Empty:
                sleep(0.1)
            except Exception as ex:
                print(f"Error resolving {host}: {ex}")


def process_threaded_jobs(items, thread_class, num_threads):
    jobs = queue.Queue()
    results = queue.Queue()

    for item in items:
        jobs.put(item)

    threads = [thread_class(jobs, results) for _ in range(num_threads)]
    for thread in threads:
        thread.start()

    jobs.join()

    for thread in threads:
        thread.stop()
    for thread in threads:
        thread.join()

    return list(results.queue)


def get_names_from_ips(ip_range):
    print(f"Checking potential hostnames for netblock {ip_range}")
    ips = [str(ip) for ip in ipaddress.ip_network(ip_range)]

    results = process_threaded_jobs(ips, CertThread, _threads)
    results = list(itertools.chain.from_iterable(results))
    return list(set(results))


def get_censys_names(domain):
    print(f"[Censys.io] Checking [{domain}]")
    session = get_requests_session()
    page = 1
    query_template = '{{"query":"{}","page":{},"fields":["parsed.subject_dn", "ip"],"flatten":true}}'
    hosts = []

    try:
        while True:
            data = query_template.format(domain, page)
            res = session.post(
                f"{_censys_endpoint}/search/certificates",
                data=data,
                auth=(api_keys._censys_uid, api_keys._censys_secret),
                timeout=_timeout
            )

            if res.status_code != 200:
                response_data = res.json()
                print(f"Error occurred: {response_data.get('error', 'Unknown error')}")
                break

            response_data = res.json()
            results = response_data.get("results", [])

            for result in results:
                subject_dn = result.get("parsed.subject_dn", "")
                if "CN=" in subject_dn:
                    name = subject_dn.split("CN=")[1].lower().split(",")[0]
                    if is_valid_hostname(name) and not name.startswith("*") and f".{domain}" in name:
                        hosts.append(name)

            if len(results) < 100:
                break

            page += 1
            if page > 100:
                print("Can't go past page 100")
                break

    except Exception as ex:
        print(f"Censys error: {ex}")

    return list(set(hosts))


def get_transparency_names(domain):
    print(f"[crt.sh] Checking [{domain}]")
    session = get_requests_session()

    try:
        r = session.get(_transparency_endpoint.format(query=domain), timeout=_timeout)
        if r.status_code != 200:
            print(f"Results not found [{r.status_code}]")
            return []

        data = r.json()
        results = [
            item["name_value"].lower()
            for item in data
            if not item["name_value"].startswith("*")
        ]

        return sorted(set(results))
    except Exception as ex:
        print(f"crt.sh error: {ex}")
        return []


def get_passivetotal_names(domain):
    print(f"[passivetotal.org] Checking [{domain}]")
    session = get_requests_session()

    try:
        endpoint = f"{_riskiq_endpoint}/v2/enrichment/subdomains"
        auth = (api_keys._riskiq_user, api_keys._riskiq_key)
        data = {"query": domain}

        r = session.get(endpoint, auth=auth, json=data, timeout=_timeout)
        if r.status_code != 200:
            print("Results not found")
            return []

        result = r.json()
        if result.get("subdomains"):
            results = [f"{prefix}.{domain}" for prefix in result["subdomains"]]
            return sorted(set(results))
    except Exception as ex:
        print(f"PassiveTotal error: {ex}")

    return []


def get_domain_vt_names(domain):
    print(f"[virustotal.com] Checking [{domain}]")
    session = get_requests_session()

    try:
        params = {"apikey": api_keys._virustotal, "domain": domain}
        r = session.get(_vt_domainsearch_endpoint, params=params, timeout=_timeout)

        if r.status_code != 200:
            print("Results not found")
            return []

        data = r.json()
        if "subdomains" in data:
            results = [sub.strip().lower() for sub in data["subdomains"]]
            return sorted(set(results))
    except Exception as ex:
        print(f"VirusTotal error: {ex}")

    return []


def get_ip_vt_names(ip_range):
    print(f"[virustotal.com] Checking [{ip_range}]")
    session = get_requests_session()
    results = []

    for ip in ipaddress.ip_network(ip_range):
        print(f"Checking [{ip}]")
        try:
            params = {"apikey": api_keys._virustotal, "ip": str(ip)}
            r = session.get(_vt_ipsearch_endpoint, params=params, timeout=_timeout)

            if r.status_code != 200:
                print(f"Request failed with status {r.status_code}")
                break

            data = r.json()
            if data.get("response_code") == 1 and "resolutions" in data:
                for resolution in data["resolutions"]:
                    if "hostname" in resolution:
                        results.append(resolution["hostname"].strip().lower())

            sleep(15)
        except Exception as ex:
            print(f"Error checking {ip}: {ex}")

    return sorted(set(results))


def get_ip_reverse_lookup(ip_range):
    print(f"[PTR names] Checking [{ip_range}]")
    results = []

    for ip in ipaddress.ip_network(ip_range):
        try:
            name, _, _ = socket.gethostbyaddr(str(ip))
            results.append(name.strip().lower())
        except socket.herror:
            pass

    return sorted(set(results))


def get_certdb_names(domain):
    print(f"[CertDB] Checking [{domain}]")
    session = get_requests_session()

    try:
        r = session.get(_certdb_endpoint.format(query=domain), timeout=_timeout)
        if r.status_code != 200:
            print("Results not found")
            return []

        data = r.json()
        if not isinstance(data, list):
            data = [data]

        results = []
        for certs in data:
            if not isinstance(certs, dict):
                continue

            if "subject" in certs and "CN" in certs["subject"]:
                cn = strip_wildcard(certs["subject"]["CN"].lower())
                results.append(cn)

            if "extensions" in certs and "subjectAltName" in certs["extensions"]:
                altnames = certs["extensions"]["subjectAltName"].split(",")
                for altname in altnames:
                    if ":" in altname:
                        name = strip_wildcard(altname.split(":", 1)[1].lower())
                        results.append(name)

        return sorted(set(results))
    except Exception as ex:
        print(f"CertDB error: {ex}")
        return []


def get_certspotter_names(domain):
    print(f"[CertSpotter] Checking [{domain}]")
    session = get_requests_session()

    try:
        r = session.get(_certspotter_endpoint.format(query=domain), timeout=_timeout)
        if r.status_code != 200:
            print("Results not found")
            return []

        data = r.json()
        results = []
        for cert in data:
            if "dns_names" in cert:
                for name in cert["dns_names"]:
                    results.append(strip_wildcard(name))

        return sorted(set(results))
    except Exception as ex:
        print(f"CertSpotter error: {ex}")
        return []


if __name__ == "__main__":
    print(_banner)
    parser = argparse.ArgumentParser(description="SSL Certificate reconnaissance tool")
    parser.add_argument("-d", "--domain", type=str, help="Domain to check")
    parser.add_argument("-D", "--domains", type=str, help="File containing domains to check")
    parser.add_argument("-i", "--iprange", type=str, help="IP range to check certificates (e.g., 10.0.0.0/24)")
    parser.add_argument("-o", "--output", type=str, help="Results file")
    parser.add_argument("-f", "--format", type=str, choices=["csv", "json"], default="csv", help="Output format")
    parser.add_argument("-t", "--delay", type=int, default=3, help="Delay between querying online services")
    parser.add_argument("-T", "--threads", type=int, default=20, help="Number of concurrent threads")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port to connect to for SSL cert")
    parser.add_argument("-V", "--virustotal", action="store_true", help="Query VirusTotal for IP range (slow)")
    parser.add_argument("-O", "--request-timeout", type=int, default=10, help="HTTP timeout for API requests (seconds)")
    args = parser.parse_args()

    _port = args.port
    _threads = args.threads
    _delay = args.delay
    _timeout = args.request_timeout
    _domains = []

    if not args.domain and not args.domains and not args.iprange:
        parser.error("Requires either --domain, --domains, or --iprange")

    if args.domain:
        _domains.append(args.domain)

    if args.domains:
        try:
            with open(args.domains, "r", encoding="utf-8") as f:
                _domains.extend([line.strip() for line in f if len(line.strip()) > 3])
        except FileNotFoundError:
            print(f"Error: File '{args.domains}' not found")
            exit(1)
        except IOError as e:
            print(f"Error reading file: {e}")
            exit(1)

    if not _domains and not args.iprange:
        parser.error("No valid domains found")

    for domain in _domains:
        try:
            _potential_hosts.extend(get_transparency_names(domain))
        except Exception as ex:
            print(f"API [crt.sh] request failed: {ex}")

        try:
            _potential_hosts.extend(get_certdb_names(domain))
        except Exception as ex:
            print(f"API [CertDB] request failed: {ex}")

        try:
            _potential_hosts.extend(get_certspotter_names(domain))
        except Exception as ex:
            print(f"API [CertSpotter] request failed: {ex}")

        if api_keys._censys_uid and api_keys._censys_secret:
            try:
                _potential_hosts.extend(get_censys_names(domain))
            except Exception as ex:
                print(f"API [Censys.io] request failed: {ex}")

        if api_keys._virustotal:
            try:
                _potential_hosts.extend(get_domain_vt_names(domain))
            except Exception as ex:
                print(f"API [VirusTotal] request failed: {ex}")

        if api_keys._riskiq_user and api_keys._riskiq_key:
            try:
                _potential_hosts.extend(get_passivetotal_names(domain))
            except Exception as ex:
                print(f"API [PassiveTotal] request failed: {ex}")

        sleep(_delay)

    if args.iprange:
        _potential_hosts = get_names_from_ips(args.iprange)
        _potential_hosts.extend(get_ip_reverse_lookup(args.iprange))
        if api_keys._virustotal and args.virustotal:
            _potential_hosts.extend(get_ip_vt_names(args.iprange))

    _potential_hosts = list(set(_potential_hosts))
    print(f"Checking {len(_potential_hosts)} potential hostnames for DNS A records")

    results = process_threaded_jobs(_potential_hosts, DnsThread, _threads)
    for result in results:
        _resolving_hosts[result["host"]] = result["ips"]

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                if args.format == "csv":
                    for host, ips in _resolving_hosts.items():
                        f.write(f"{host},{','.join(ips)}\n")
                else:
                    json.dump(_resolving_hosts, f, indent=2)
            print(f"Results saved to {args.output}")
        except IOError as e:
            print(f"Error writing output file: {e}")

    print(f"\nFound [{len(_resolving_hosts)}] resolving hostnames")
    for host, ips in _resolving_hosts.items():
        print(f"[Resolving] {host} => [{', '.join(ips)}]")
    print()
