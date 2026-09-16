#!/usr/bin/env python3

"""
PYSCAN V6
Professional TCP Network Scanner

Features:
- Interactive menu
- TCP connect scanning
- Custom port ranges
- Common/top ports
- Multithreaded scanning
- Active service fingerprinting
- Banner detection
- HTTP/HTTPS detection on arbitrary ports
- TLS detection
- Product/version extraction
- Confidence scoring
- Safe vulnerability/configuration checks
- Structured vulnerability findings
- JSON / CSV / TXT reports
- Scan summary
- Vulnerability detail viewer

Author: PYSCAN Project
"""

import csv
import json
import os
import re
import socket
import ssl
import sys
import time

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ============================================================
# COLORS
# ============================================================

RESET = "\033[0m"
BOLD = "\033[1m"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
GRAY = "\033[90m"


def color(text, colour):
    return f"{colour}{text}{RESET}"


# ============================================================
# SERVICE DATABASE
# ============================================================

SERVICES = {
    20: "FTP-data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-trap",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IKE",
    514: "Syslog",
    587: "SMTP-submission",
    636: "LDAPS",
    873: "Rsync",
    902: "VMware",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    2376: "Docker-TLS",
    3000: "HTTP",
    3306: "MySQL",
    3389: "RDP",
    5000: "HTTP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    6443: "Kubernetes API",
    8000: "HTTP",
    8008: "HTTP",
    8080: "HTTP",
    8081: "HTTP",
    8443: "HTTPS",
    8888: "HTTP",
    9000: "HTTP",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 161, 389, 443, 445, 465, 587, 636, 873,
    993, 995, 1080, 1433, 1521, 2049, 2375, 2376,
    3000, 3306, 3389, 5000, 5432, 5900, 6379, 6443,
    8000, 8008, 8080, 8081, 8443, 8888, 9000,
    9200, 9300, 11211, 27017
]


# ============================================================
# APPLICATION DATA
# ============================================================

SCAN_DATA = {
    "target": "",
    "target_ip": "",
    "start_time": "",
    "end_time": "",
    "duration": 0,
    "ports": [],
    "services": [],
    "http": [],
    "tls": [],
    "vulnerabilities": [],
    "summary": {},
}


# ============================================================
# GENERAL HELPERS
# ============================================================

def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")


def banner():
    print(color(r"""
██████╗ ██╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝ ╚████╔╝ ███████╗██║     ███████║██╔██╗ ██║
██╔═══╝   ╚██╔╝  ╚════██║██║     ██╔══██║██║╚██╗██║
██║        ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝        ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝

             PYSCAN V6
      Network & Service Security Scanner
""", CYAN))


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return default


# ============================================================
# TARGET RESOLUTION
# ============================================================

def resolve_target(target):
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        return None


# ============================================================
# PORT PARSER
# ============================================================

def parse_ports(port_string):
    ports = set()

    try:
        parts = port_string.split(",")

        for part in parts:
            part = part.strip()

            if not part:
                continue

            if "-" in part:
                start, end = part.split("-", 1)

                start = int(start)
                end = int(end)

                if start > end:
                    start, end = end, start

                for port in range(start, end + 1):
                    if 1 <= port <= 65535:
                        ports.add(port)

            else:
                port = int(part)

                if 1 <= port <= 65535:
                    ports.add(port)

    except ValueError:
        return []

    return sorted(ports)


# ============================================================
# TCP PORT SCAN
# ============================================================

def scan_port(ip, port, timeout=1.0):
    start = time.perf_counter()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((ip, port))

        latency = round(
            (time.perf_counter() - start) * 1000,
            2
        )

        sock.close()

        if result == 0:
            return {
                "port": port,
                "state": "open",
                "service": SERVICES.get(port, "unknown"),
                "latency_ms": latency,
            }

        return {
            "port": port,
            "state": "closed",
            "service": SERVICES.get(port, "unknown"),
            "latency_ms": latency,
        }

    except socket.timeout:
        return {
            "port": port,
            "state": "filtered",
            "service": SERVICES.get(port, "unknown"),
            "latency_ms": None,
        }

    except Exception as e:
        return {
            "port": port,
            "state": "error",
            "service": SERVICES.get(port, "unknown"),
            "latency_ms": None,
            "error": str(e),
        }


def scan_ports(ip, ports, threads=50):
    results = []

    print(
        color(
            f"\n[*] Scanning {len(ports)} TCP ports...\n",
            BLUE
        )
    )

    with ThreadPoolExecutor(max_workers=threads) as executor:

        futures = [
            executor.submit(scan_port, ip, port)
            for port in ports
        ]

        completed = 0

        for future in as_completed(futures):
            completed += 1

            result = future.result()
            results.append(result)

            progress = int((completed / len(ports)) * 30)

            bar = (
                "[" +
                "#" * progress +
                "-" * (30 - progress) +
                "]"
            )

            print(
                f"\r{bar} "
                f"{completed}/{len(ports)}",
                end=""
            )

    print("\n")

    return sorted(results, key=lambda x: x["port"])


# ============================================================
# SOCKET HELPERS
# ============================================================

def create_socket(ip, port, timeout=2):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((ip, port))
    return sock


def receive_data(sock, size=4096):
    try:
        return sock.recv(size)
    except Exception:
        return b""


# ============================================================
# BANNER GRABBING
# ============================================================

def grab_initial_banner(ip, port, timeout=2):
    """
    Passive-ish banner collection.
    Does NOT send an HTTP request.
    """

    sock = None

    try:
        sock = create_socket(ip, port, timeout)

        data = receive_data(sock, 4096)

        if data:
            return data.decode(
                "utf-8",
                errors="replace"
            ).strip()

    except Exception:
        pass

    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass

    return ""


# ============================================================
# TLS DETECTION
# ============================================================

def detect_tls_service(ip, port, timeout=3):
    sock = None
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_CLIENT
    )

    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        raw = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        raw.settimeout(timeout)
        raw.connect((ip, port))

        sock = context.wrap_socket(
            raw,
            server_hostname=ip
        )

        cipher = sock.cipher()
        version = sock.version()

        cert = {}

        try:
            cert = sock.getpeercert()
        except Exception:
            pass

        return {
            "enabled": True,
            "version": version,
            "cipher": cipher[0] if cipher else None,
            "certificate": cert,
        }

    except Exception:
        return {
            "enabled": False
        }

    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


# ============================================================
# HTTP PROBE
# ============================================================

def http_probe(ip, port, use_tls=False, timeout=3):
    sock = None

    try:

        if use_tls:

            context = ssl.SSLContext(
                ssl.PROTOCOL_TLS_CLIENT
            )

            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            raw = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            raw.settimeout(timeout)
            raw.connect((ip, port))

            sock = context.wrap_socket(
                raw,
                server_hostname=ip
            )

        else:
            sock = create_socket(
                ip,
                port,
                timeout
            )

        request = (
            f"HEAD / HTTP/1.1\r\n"
            f"Host: {ip}\r\n"
            f"User-Agent: PYSCAN/6.0\r\n"
            f"Connection: close\r\n\r\n"
        )

        sock.sendall(
            request.encode()
        )

        response = sock.recv(8192)

        if not response:
            return None

        text = response.decode(
            "iso-8859-1",
            errors="replace"
        )

        first_line = text.splitlines()[0] \
            if text.splitlines() else ""

        headers = {}

        for line in text.splitlines()[1:]:
            if ":" in line:
                key, value = line.split(
                    ":",
                    1
                )

                headers[
                    key.strip().lower()
                ] = value.strip()

        return {
            "status": first_line,
            "headers": headers,
            "raw": text[:4000],
            "tls": use_tls,
        }

    except Exception:
        return None

    finally:
        try:
            if sock:
                sock.close()
        except Exception:
            pass


# ============================================================
# VERSION EXTRACTION
# ============================================================

def extract_version(text):
    if not text:
        return None

    patterns = [
        r"OpenSSH[_ /-]?([0-9][\w.\-p]*)",
        r"Apache[/ ]([0-9][\w.\-]*)",
        r"nginx[/ ]([0-9][\w.\-]*)",
        r"Microsoft-IIS[/ ]([0-9][\w.\-]*)",
        r"vsftpd[/ ]([0-9][\w.\-]*)",
        r"ProFTPD[/ ]([0-9][\w.\-]*)",
        r"Postfix[/ ]([0-9][\w.\-]*)",
        r"Exim[/ ]([0-9][\w.\-]*)",
        r"Redis[/ ]([0-9][\w.\-]*)",
        r"PostgreSQL[/ ]([0-9][\w.\-]*)",
        r"MySQL[/ ]([0-9][\w.\-]*)",
        r"Microsoft SQL Server[/ ]([0-9][\w.\-]*)",
        r"Werkzeug[/ ]([0-9][\w.\-]*)",
        r"gunicorn[/ ]([0-9][\w.\-]*)",
        r"Tomcat[/ ]([0-9][\w.\-]*)",
    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            text,
            re.IGNORECASE
        )

        if match:
            return match.group(1)

    return None


# ============================================================
# BANNER IDENTIFICATION
# ============================================================

def identify_banner(banner):
    if not banner:
        return None

    lower = banner.lower()

    fingerprints = [

        (
            "ssh",
            "SSH",
            "OpenSSH",
            r"openssh"
        ),

        (
            "ftp",
            "FTP",
            "FTP Server",
            r"ftp"
        ),

        (
            "vsftpd",
            "FTP",
            "vsftpd",
            r"vsftpd"
        ),

        (
            "proftpd",
            "FTP",
            "ProFTPD",
            r"proftpd"
        ),

        (
            "smtp",
            "SMTP",
            "SMTP Server",
            r"smtp|postfix|exim"
        ),

        (
            "redis",
            "Redis",
            "Redis",
            r"redis"
        ),

        (
            "mysql",
            "MySQL",
            "MySQL",
            r"mysql"
        ),

        (
            "postgres",
            "PostgreSQL",
            "PostgreSQL",
            r"postgres"
        ),

        (
            "mongodb",
            "MongoDB",
            "MongoDB",
            r"mongodb"
        ),

        (
            "elastic",
            "Elasticsearch",
            "Elasticsearch",
            r"elasticsearch"
        ),

        (
            "docker",
            "Docker",
            "Docker",
            r"docker"
        ),

        (
            "kubernetes",
            "Kubernetes",
            "Kubernetes API",
            r"kubernetes"
        ),

        (
            "telnet",
            "Telnet",
            "Telnet Server",
            r"telnet"
        ),
    ]

    for _, service, product, pattern in fingerprints:

        if re.search(
            pattern,
            lower,
            re.IGNORECASE
        ):

            return {
                "service": service,
                "product": product,
                "version": extract_version(banner),
                "method": "banner",
                "confidence": "HIGH",
            }

    return None


# ============================================================
# HTTP IDENTIFICATION
# ============================================================

def identify_http_service(http_data):
    if not http_data:
        return None

    headers = http_data.get(
        "headers",
        {}
    )

    server = headers.get(
        "server",
        ""
    )

    powered = headers.get(
        "x-powered-by",
        ""
    )

    combined = (
        server +
        " " +
        powered
    ).strip()

    product = "HTTP Server"

    if combined:
        product = combined

    version = extract_version(
        combined
    )

    return {
        "service": (
            "HTTPS"
            if http_data.get("tls")
            else "HTTP"
        ),
        "product": product,
        "version": version,
        "method": "HTTP-probe",
        "confidence": "HIGH",
        "headers": headers,
        "status": http_data.get(
            "status"
        ),
    }


# ============================================================
# GENERIC PROTOCOL PROBES
# ============================================================

def protocol_probe(ip, port, timeout=2):
    """
    Safe lightweight protocol probes.
    """

    # --------------------------------------------------------
    # SMTP
    # --------------------------------------------------------

    if port in [25, 465, 587]:

        try:
            sock = create_socket(
                ip,
                port,
                timeout
            )

            data = receive_data(
                sock,
                2048
            )

            sock.close()

            text = data.decode(
                "utf-8",
                errors="replace"
            )

            if text:
                return identify_banner(
                    text
                )

        except Exception:
            pass

    # --------------------------------------------------------
    # FTP
    # --------------------------------------------------------

    if port == 21:

        try:
            sock = create_socket(
                ip,
                port,
                timeout
            )

            data = receive_data(
                sock,
                2048
            )

            sock.close()

            text = data.decode(
                "utf-8",
                errors="replace"
            )

            if text:
                return identify_banner(
                    text
                )

        except Exception:
            pass

    # --------------------------------------------------------
    # Redis
    # --------------------------------------------------------

    if port == 6379:

        try:
            sock = create_socket(
                ip,
                port,
                timeout
            )

            sock.sendall(
                b"*1\r\n$4\r\nPING\r\n"
            )

            data = receive_data(
                sock,
                2048
            )

            sock.close()

            text = data.decode(
                "utf-8",
                errors="replace"
            )

            if text:

                return {
                    "service": "Redis",
                    "product": "Redis",
                    "version": extract_version(
                        text
                    ),
                    "method": "Redis-probe",
                    "confidence": "HIGH",
                }

        except Exception:
            pass

    return None


# ============================================================
# SERVICE FINGERPRINTING
# ============================================================

def service_fingerprint(ip, port):
    """
    Multi-stage service detection.

    Priority:

    1. TLS detection
    2. HTTP/HTTPS detection
    3. Protocol-specific probe
    4. Initial banner
    5. Static port mapping
    6. /etc/services database
    """

    result = {
        "port": port,
        "service": SERVICES.get(
            port,
            "unknown"
        ),
        "product": None,
        "version": None,
        "banner": None,
        "method": "port-map",
        "confidence": "LOW",
    }

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    tls_info = detect_tls_service(
        ip,
        port
    )

    if tls_info.get("enabled"):

        result["service"] = "HTTPS/TLS"
        result["product"] = "TLS service"
        result["method"] = "TLS-handshake"
        result["confidence"] = "HIGH"

        result["tls"] = tls_info

        http_data = http_probe(
            ip,
            port,
            use_tls=True
        )

        http_result = identify_http_service(
            http_data
        )

        if http_result:

            result.update({
                "service": http_result[
                    "service"
                ],
                "product": http_result[
                    "product"
                ],
                "version": http_result[
                    "version"
                ],
                "method": "HTTPS-probe",
                "confidence": "HIGH",
            })

            result["http"] = http_data

        return result

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    http_data = http_probe(
        ip,
        port,
        use_tls=False
    )

    http_result = identify_http_service(
        http_data
    )

    if http_result:

        result.update({
            "service": http_result[
                "service"
            ],
            "product": http_result[
                "product"
            ],
            "version": http_result[
                "version"
            ],
            "method": "HTTP-probe",
            "confidence": "HIGH",
        })

        result["http"] = http_data

        return result

    # --------------------------------------------------------
    # Protocol-specific probe
    # --------------------------------------------------------

    protocol_result = protocol_probe(
        ip,
        port
    )

    if protocol_result:

        result.update({
            "service": protocol_result.get(
                "service",
                result["service"]
            ),
            "product": protocol_result.get(
                "product"
            ),
            "version": protocol_result.get(
                "version"
            ),
            "method": protocol_result.get(
                "method",
                "protocol-probe"
            ),
            "confidence": protocol_result.get(
                "confidence",
                "MEDIUM"
            ),
        })

        return result

    # --------------------------------------------------------
    # Passive banner
    # --------------------------------------------------------

    banner_text = grab_initial_banner(
        ip,
        port
    )

    if banner_text:

        result["banner"] = banner_text[
            :1000
        ]

        identified = identify_banner(
            banner_text
        )

        if identified:

            result.update({
                "service": identified[
                    "service"
                ],
                "product": identified[
                    "product"
                ],
                "version": identified[
                    "version"
                ],
                "method": identified[
                    "method"
                ],
                "confidence": identified[
                    "confidence"
                ],
            })

        else:

            result["method"] = "banner"
            result["confidence"] = "MEDIUM"

    # --------------------------------------------------------
    # socket service database
    # --------------------------------------------------------

    if result["service"] == "unknown":

        try:
            service_name = socket.getservbyport(
                port,
                "tcp"
            )

            result["service"] = service_name
            result["method"] = "system-services"
            result["confidence"] = "LOW"

        except Exception:
            pass

    return result


def enrich_services(ip, ports):
    services = []

    open_ports = [
        item
        for item in ports
        if item["state"] == "open"
    ]

    print(
        color(
            "\n[*] Performing active service detection...\n",
            CYAN
        )
    )

    for index, item in enumerate(
        open_ports,
        start=1
    ):

        port = item["port"]

        print(
            f"\r[*] Fingerprinting "
            f"{port}/tcp "
            f"({index}/{len(open_ports)})",
            end=""
        )

        fingerprint = service_fingerprint(
            ip,
            port
        )

        services.append(
            fingerprint
        )

    print("\n")

    return services


# ============================================================
# SERVICE DISPLAY
# ============================================================

def display_services(services):

    print(
        color(
            "\nSERVICE & VERSION DETECTION",
            BOLD + CYAN
        )
    )

    print(
        color(
            "=" * 75,
            CYAN
        )
    )

    for item in services:

        port = item["port"]
        service = item.get(
            "service",
            "unknown"
        )

        product = item.get(
            "product"
        ) or "-"

        version = item.get(
            "version"
        ) or "-"

        confidence = item.get(
            "confidence",
            "LOW"
        )

        method = item.get(
            "method",
            "-"
        )

        if confidence == "HIGH":
            conf_color = GREEN
        elif confidence == "MEDIUM":
            conf_color = YELLOW
        else:
            conf_color = GRAY

        print(
            f"\n{color(str(port) + '/tcp', BOLD)}"
        )

        print(
            f"  Service     : "
            f"{color(service, CYAN)}"
        )

        print(
            f"  Product     : "
            f"{product}"
        )

        print(
            f"  Version     : "
            f"{version}"
        )

        print(
            f"  Confidence  : "
            f"{color(confidence, conf_color)}"
        )

        print(
            f"  Detection   : "
            f"{method}"
        )

        banner_text = item.get(
            "banner"
        )

        if banner_text:

            clean_banner = (
                banner_text
                .replace("\r", " ")
                .replace("\n", " ")
            )

            print(
                f"  Banner      : "
                f"{clean_banner[:150]}"
            )


# ============================================================
# HTTP SECURITY ANALYSIS
# ============================================================

def analyze_http(services):

    results = []

    for item in services:

        http_data = item.get(
            "http"
        )

        if not http_data:
            continue

        headers = http_data.get(
            "headers",
            {}
        )

        result = {
            "port": item["port"],
            "service": item["service"],
            "status": http_data.get(
                "status"
            ),
            "headers": headers,
        }

        results.append(result)

    return results


# ============================================================
# TLS ANALYSIS
# ============================================================

def analyze_tls(services):

    results = []

    for item in services:

        tls_data = item.get(
            "tls"
        )

        if not tls_data:
            continue

        results.append({
            "port": item["port"],
            "version": tls_data.get(
                "version"
            ),
            "cipher": tls_data.get(
                "cipher"
            ),
        })

    return results


# ============================================================
# VULNERABILITY STRUCTURE
# ============================================================

def make_finding(
    finding_id,
    title,
    severity,
    confidence,
    host,
    port,
    service,
    description,
    evidence,
    impact,
    recommendation,
    cwe=None,
    references=None
):

    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "host": host,
        "port": port,
        "service": service,
        "cwe": cwe,
        "description": description,
        "evidence": evidence,
        "impact": impact,
        "recommendation": recommendation,
        "references": references or [],
    }


# ============================================================
# SAFE VULNERABILITY CHECKS
# ============================================================

def vulnerability_scan(
    ip,
    services
):

    findings = []

    for item in services:

        port = item["port"]
        service = item.get(
            "service",
            ""
        )

        product = item.get(
            "product",
            ""
        ) or ""

        version = item.get(
            "version",
            ""
        ) or ""

        # ----------------------------------------------------
        # TELNET
        # ----------------------------------------------------

        if service.lower() == "telnet":

            findings.append(
                make_finding(
                    "PYSCAN-NET-001",
                    "Telnet Service Exposed",
                    "HIGH",
                    "HIGH",
                    ip,
                    port,
                    service,
                    "Telnet is an unencrypted remote administration protocol.",
                    f"TCP/{port} identified as Telnet.",
                    "Credentials and session data may be transmitted without encryption.",
                    "Disable Telnet and use SSH instead.",
                    "CWE-319"
                )
            )

        # ----------------------------------------------------
        # FTP
        # ----------------------------------------------------

        if service.upper() == "FTP":

            findings.append(
                make_finding(
                    "PYSCAN-NET-002",
                    "FTP Service Exposed",
                    "MEDIUM",
                    "HIGH",
                    ip,
                    port,
                    service,
                    "FTP commonly transmits authentication and data without transport encryption.",
                    f"TCP/{port} identified as FTP.",
                    "Network observers may be able to capture credentials or transferred data.",
                    "Prefer SFTP or FTPS where appropriate.",
                    "CWE-319"
                )
            )

        # ----------------------------------------------------
        # DOCKER API
        # ----------------------------------------------------

        if port == 2375:

            findings.append(
                make_finding(
                    "PYSCAN-CONFIG-001",
                    "Docker API Exposed Without TLS",
                    "CRITICAL",
                    "HIGH",
                    ip,
                    port,
                    service,
                    "TCP/2375 is commonly used for the Docker API without TLS.",
                    "Docker API port 2375 is reachable.",
                    "An exposed Docker daemon can provide extremely powerful control over containers and potentially the host.",
                    "Restrict access to trusted management networks and configure TLS.",
                    "CWE-284"
                )
            )

        # ----------------------------------------------------
        # REDIS
        # ----------------------------------------------------

        if service.lower() == "redis":

            findings.append(
                make_finding(
                    "PYSCAN-CONFIG-002",
                    "Redis Service Exposed",
                    "HIGH",
                    "HIGH",
                    ip,
                    port,
                    service,
                    "A Redis service was detected on the network.",
                    f"TCP/{port} identified as Redis.",
                    "An improperly protected Redis instance may expose sensitive data or administrative functionality.",
                    "Restrict Redis to trusted hosts and require authentication where appropriate.",
                    "CWE-306"
                )
            )

        # ----------------------------------------------------
        # MONGODB
        # ----------------------------------------------------

        if service.lower() == "mongodb":

            findings.append(
                make_finding(
                    "PYSCAN-CONFIG-003",
                    "MongoDB Service Exposed",
                    "HIGH",
                    "HIGH",
                    ip,
                    port,
                    service,
                    "A MongoDB service was detected.",
                    f"TCP/{port} identified as MongoDB.",
                    "An improperly protected database may expose application data.",
                    "Restrict database network access and enable authentication.",
                    "CWE-284"
                )
            )

        # ----------------------------------------------------
        # HTTP SECURITY HEADERS
        # ----------------------------------------------------

        http_data = item.get(
            "http"
        )

        if http_data:

            headers = http_data.get(
                "headers",
                {}
            )

            security_headers = {
                "x-content-type-options":
                    "X-Content-Type-Options",

                "x-frame-options":
                    "X-Frame-Options",

                "content-security-policy":
                    "Content-Security-Policy",

                "referrer-policy":
                    "Referrer-Policy",
            }

            missing = []

            for key, display in security_headers.items():

                if key not in headers:
                    missing.append(display)

            if missing:

                findings.append(
                    make_finding(
                        "PYSCAN-WEB-001",
                        "Missing HTTP Security Headers",
                        "LOW",
                        "MEDIUM",
                        ip,
                        port,
                        service,
                        "One or more recommended browser security headers were not observed.",
                        ", ".join(missing),
                        "Missing headers can reduce browser-side security protections.",
                        "Review and configure appropriate HTTP security headers.",
                        "CWE-693"
                    )
                )

            # ------------------------------------------------
            # SERVER HEADER DISCLOSURE
            # ------------------------------------------------

            server_header = headers.get(
                "server"
            )

            if server_header:

                findings.append(
                    make_finding(
                        "PYSCAN-WEB-002",
                        "Server Technology Disclosure",
                        "INFO",
                        "HIGH",
                        ip,
                        port,
                        service,
                        "The HTTP Server header reveals implementation information.",
                        f"Server: {server_header}",
                        "Technology information can assist reconnaissance.",
                        "Consider minimizing unnecessary server technology disclosure.",
                        "CWE-200"
                    )
                )

        # ----------------------------------------------------
        # OLD TLS
        # ----------------------------------------------------

        tls_data = item.get(
            "tls"
        )

        if tls_data:

            tls_version = tls_data.get(
                "version"
            )

            if tls_version in [
                "TLSv1",
                "TLSv1.1"
            ]:

                findings.append(
                    make_finding(
                        "PYSCAN-TLS-001",
                        "Obsolete TLS Version",
                        "MEDIUM",
                        "HIGH",
                        ip,
                        port,
                        service,
                        "The service accepted an obsolete TLS protocol version.",
                        f"Negotiated protocol: {tls_version}",
                        "Older TLS versions have weaker security properties and should generally be retired.",
                        "Disable obsolete TLS versions and require modern TLS.",
                        "CWE-326"
                    )
                )

    return findings


# ============================================================
# VULNERABILITY DISPLAY
# ============================================================

def severity_color(severity):

    mapping = {
        "CRITICAL": RED,
        "HIGH": RED,
        "MEDIUM": YELLOW,
        "LOW": CYAN,
        "INFO": GRAY,
    }

    return mapping.get(
        severity,
        WHITE
    )


def display_vulnerabilities(findings):

    print(
        color(
            "\nSECURITY FINDINGS",
            BOLD + MAGENTA
        )
    )

    print(
        color(
            "=" * 75,
            MAGENTA
        )
    )

    if not findings:

        print(
            color(
                "\n[+] No findings detected by the safe checks.\n",
                GREEN
            )
        )

        return

    for index, finding in enumerate(
        findings,
        start=1
    ):

        sev = finding["severity"]

        print(
            f"\n[{index}] "
            f"{color(sev, severity_color(sev))} "
            f"{finding['title']}"
        )

        print(
            f"    ID         : "
            f"{finding['id']}"
        )

        print(
            f"    Host       : "
            f"{finding['host']}"
        )

        print(
            f"    Port       : "
            f"{finding['port']}"
        )

        print(
            f"    Service    : "
            f"{finding['service']}"
        )

        print(
            f"    Confidence : "
            f"{finding['confidence']}"
        )


def vulnerability_details(findings):

    if not findings:
        print(
            color(
                "\nNo vulnerability findings available.\n",
                GREEN
            )
        )

        input(
            "Press ENTER to continue..."
        )

        return

    while True:

        display_vulnerabilities(
            findings
        )

        choice = input(
            "\nEnter finding number "
            "(0 to return): "
        ).strip()

        if choice == "0":
            return

        try:
            index = int(choice) - 1

            if not (
                0 <= index < len(findings)
            ):
                print(
                    color(
                        "Invalid selection.",
                        RED
                    )
                )
                continue

            finding = findings[index]

            clear_screen()

            print(
                color(
                    finding["title"],
                    BOLD + CYAN
                )
            )

            print(
                "=" * 75
            )

            fields = [
                ("ID", "id"),
                ("Severity", "severity"),
                ("Confidence", "confidence"),
                ("Host", "host"),
                ("Port", "port"),
                ("Service", "service"),
                ("CWE", "cwe"),
                ("Description", "description"),
                ("Evidence", "evidence"),
                ("Impact", "impact"),
                ("Recommendation", "recommendation"),
            ]

            for label, key in fields:

                value = finding.get(
                    key
                )

                if value:

                    print(
                        f"\n{color(label + ':', BOLD)}"
                    )

                    print(
                        f"{value}"
                    )

            references = finding.get(
                "references",
                []
            )

            if references:

                print(
                    "\nReferences:"
                )

                for ref in references:
                    print(
                        f"  - {ref}"
                    )

            print()

            input(
                "Press ENTER to return..."
            )

            clear_screen()

        except ValueError:

            print(
                color(
                    "Enter a valid number.",
                    RED
                )
            )


# ============================================================
# SUMMARY
# ============================================================

def generate_summary(
    ports,
    services,
    findings
):

    open_ports = [
        p for p in ports
        if p["state"] == "open"
    ]

    summary = {
        "total_ports_scanned": len(
            ports
        ),
        "open_ports": len(
            open_ports
        ),
        "services_detected": len(
            services
        ),
        "vulnerabilities": len(
            findings
        ),
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:

        severity = finding[
            "severity"
        ].lower()

        if severity in summary:
            summary[
                severity
            ] += 1

    return summary


def display_summary(summary):

    print(
        color(
            "\nSCAN SUMMARY",
            BOLD + CYAN
        )
    )

    print(
        "=" * 50
    )

    print(
        f"Ports scanned       : "
        f"{summary['total_ports_scanned']}"
    )

    print(
        f"Open ports          : "
        f"{summary['open_ports']}"
    )

    print(
        f"Services detected   : "
        f"{summary['services_detected']}"
    )

    print(
        f"Total findings      : "
        f"{summary['vulnerabilities']}"
    )

    print(
        f"Critical            : "
        f"{summary['critical']}"
    )

    print(
        f"High                : "
        f"{summary['high']}"
    )

    print(
        f"Medium              : "
        f"{summary['medium']}"
    )

    print(
        f"Low                 : "
        f"{summary['low']}"
    )

    print(
        f"Info                : "
        f"{summary['info']}"
    )


# ============================================================
# REPORT GENERATION
# ============================================================

def create_report(scan_data):

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    target_safe = (
        scan_data["target"]
        .replace("/", "_")
        .replace(":", "_")
    )

    folder = "pyscan_reports"

    os.makedirs(
        folder,
        exist_ok=True
    )

    base = os.path.join(
        folder,
        f"pyscan_{target_safe}_{timestamp}"
    )

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    json_file = base + ".json"

    with open(
        json_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            scan_data,
            file,
            indent=4,
            default=str
        )

    # --------------------------------------------------------
    # CSV
    # --------------------------------------------------------

    csv_file = base + ".csv"

    with open(
        csv_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "Port",
            "State",
            "Service",
            "Product",
            "Version",
            "Confidence",
            "Detection",
            "Latency"
        ])

        for port in scan_data[
            "ports"
        ]:

            service = next(
                (
                    x for x in scan_data[
                        "services"
                    ]
                    if x["port"] == port["port"]
                ),
                {}
            )

            writer.writerow([
                port["port"],
                port["state"],
                service.get(
                    "service",
                    port.get(
                        "service",
                        ""
                    )
                ),
                service.get(
                    "product",
                    ""
                ),
                service.get(
                    "version",
                    ""
                ),
                service.get(
                    "confidence",
                    ""
                ),
                service.get(
                    "method",
                    ""
                ),
                port.get(
                    "latency_ms",
                    ""
                ),
            ])

    # --------------------------------------------------------
    # TEXT
    # --------------------------------------------------------

    txt_file = base + ".txt"

    with open(
        txt_file,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "PYSCAN SECURITY SCAN REPORT\n"
        )

        file.write(
            "=" * 70 + "\n\n"
        )

        file.write(
            f"Target: "
            f"{scan_data['target']}\n"
        )

        file.write(
            f"IP: "
            f"{scan_data['target_ip']}\n"
        )

        file.write(
            f"Start: "
            f"{scan_data['start_time']}\n"
        )

        file.write(
            f"End: "
            f"{scan_data['end_time']}\n"
        )

        file.write(
            f"Duration: "
            f"{scan_data['duration']:.2f}s\n\n"
        )

        file.write(
            "OPEN PORTS\n"
        )

        file.write(
            "-" * 70 + "\n"
        )

        for port in scan_data[
            "ports"
        ]:

            if port["state"] != "open":
                continue

            file.write(
                f"{port['port']}/tcp "
                f"{port['state']} "
                f"{port.get('service', '')}\n"
            )

        file.write(
            "\nSERVICES\n"
        )

        file.write(
            "-" * 70 + "\n"
        )

        for service in scan_data[
            "services"
        ]:

            file.write(
                f"{service['port']}/tcp\n"
            )

            file.write(
                f"  Service: "
                f"{service.get('service')}\n"
            )

            file.write(
                f"  Product: "
                f"{service.get('product')}\n"
            )

            file.write(
                f"  Version: "
                f"{service.get('version')}\n"
            )

            file.write(
                f"  Confidence: "
                f"{service.get('confidence')}\n"
            )

            file.write(
                f"  Detection: "
                f"{service.get('method')}\n\n"
            )

        file.write(
            "SECURITY FINDINGS\n"
        )

        file.write(
            "-" * 70 + "\n"
        )

        for finding in scan_data[
            "vulnerabilities"
        ]:

            file.write(
                f"\n[{finding['severity']}] "
                f"{finding['title']}\n"
            )

            file.write(
                f"ID: {finding['id']}\n"
            )

            file.write(
                f"Port: {finding['port']}\n"
            )

            file.write(
                f"Description: "
                f"{finding['description']}\n"
            )

            file.write(
                f"Evidence: "
                f"{finding['evidence']}\n"
            )

            file.write(
                f"Impact: "
                f"{finding['impact']}\n"
            )

            file.write(
                f"Recommendation: "
                f"{finding['recommendation']}\n"
            )

    print(
        color(
            "\n[+] Reports created:",
            GREEN
        )
    )

    print(
        f"    JSON: {json_file}"
    )

    print(
        f"    CSV : {csv_file}"
    )

    print(
        f"    TXT : {txt_file}"
    )


# ============================================================
# PORT DISPLAY
# ============================================================

def display_ports(ports):

    print(
        color(
            "\nPORT RESULTS",
            BOLD + CYAN
        )
    )

    print(
        "=" * 75
    )

    for item in ports:

        if item["state"] == "open":

            print(
                f"{color(
                    str(item['port']) + '/tcp',
                    GREEN
                ):<20}"
                f"{item['state']:<12}"
                f"{item.get('service', 'unknown'):<20}"
                f"{item.get('latency_ms', '-')} ms"
            )


# ============================================================
# SCAN ENGINE
# ============================================================

def run_scan(
    target,
    ports,
    threads=50
):

    clear_screen()
    banner()

    ip = resolve_target(
        target
    )

    if not ip:

        print(
            color(
                "[!] Could not resolve target.",
                RED
            )
        )

        return

    print(
        f"Target : {target}"
    )

    print(
        f"IP     : {ip}"
    )

    print()

    start_time = time.time()

    SCAN_DATA.clear()

    SCAN_DATA.update({
        "target": target,
        "target_ip": ip,
        "start_time": now(),
        "end_time": "",
        "duration": 0,
        "ports": [],
        "services": [],
        "http": [],
        "tls": [],
        "vulnerabilities": [],
        "summary": {},
    })

    # --------------------------------------------------------
    # PORT SCAN
    # --------------------------------------------------------

    ports_result = scan_ports(
        ip,
        ports,
        threads
    )

    SCAN_DATA[
        "ports"
    ] = ports_result

    # --------------------------------------------------------
    # SERVICE DETECTION
    # --------------------------------------------------------

    services = enrich_services(
        ip,
        ports_result
    )

    SCAN_DATA[
        "services"
    ] = services

    display_ports(
        ports_result
    )

    display_services(
        services
    )

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    http_results = analyze_http(
        services
    )

    SCAN_DATA[
        "http"
    ] = http_results

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    tls_results = analyze_tls(
        services
    )

    SCAN_DATA[
        "tls"
    ] = tls_results

    # --------------------------------------------------------
    # VULNERABILITIES
    # --------------------------------------------------------

    findings = vulnerability_scan(
        ip,
        services
    )

    SCAN_DATA[
        "vulnerabilities"
    ] = findings

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    summary = generate_summary(
        ports_result,
        services,
        findings
    )

    SCAN_DATA[
        "summary"
    ] = summary

    SCAN_DATA[
        "duration"
    ] = time.time() - start_time

    SCAN_DATA[
        "end_time"
    ] = now()

    display_vulnerabilities(
        findings
    )

    display_summary(
        summary
    )

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    print()

    save = input(
        "Generate reports? [Y/n]: "
    ).strip().lower()

    if save != "n":

        create_report(
            SCAN_DATA
        )

    # --------------------------------------------------------
    # DETAILS
    # --------------------------------------------------------

    details = input(
        "\nView vulnerability details? [y/N]: "
    ).strip().lower()

    if details == "y":

        clear_screen()

        vulnerability_details(
            findings
        )


# ============================================================
# CUSTOM PORT INPUT
# ============================================================

def ask_ports():

    print(
        "\nExamples:"
    )

    print(
        "  22,80,443"
    )

    print(
        "  1-1000"
    )

    print(
        "  22,80,443,8000-9000"
    )

    while True:

        value = input(
            "\nPorts: "
        ).strip()

        ports = parse_ports(
            value
        )

        if ports:

            return ports

        print(
            color(
                "[!] Invalid port list.",
                RED
            )
        )


# ============================================================
# MAIN MENU
# ============================================================

def main_menu():

    while True:

        clear_screen()
        banner()

        print(
            color(
                "MAIN MENU",
                BOLD + WHITE
            )
        )

        print(
            "=" * 45
        )

        print(
            "1. Quick Port Scan"
        )

        print(
            "2. Top Ports + Service Detection"
        )

        print(
            "3. Full TCP Port Scan"
        )

        print(
            "4. Custom Port Scan"
        )

        print(
            "5. Comprehensive Security Scan"
        )

        print(
            "6. Exit"
        )

        print(
            "=" * 45
        )

        choice = input(
            "\nSelect option: "
        ).strip()

        if choice == "6":
            print(
                color(
                    "\nGoodbye!\n",
                    CYAN
                )
            )
            sys.exit(0)

        target = input(
            "\nTarget IP / hostname: "
        ).strip()

        if not target:
            continue

        # ----------------------------------------------------
        # QUICK
        # ----------------------------------------------------

        if choice == "1":

            ports = TOP_PORTS[:20]

            run_scan(
                target,
                ports,
                50
            )

        # ----------------------------------------------------
        # TOP PORTS
        # ----------------------------------------------------

        elif choice == "2":

            run_scan(
                target,
                TOP_PORTS,
                60
            )

        # ----------------------------------------------------
        # FULL
        # ----------------------------------------------------

        elif choice == "3":

            ports = list(
                range(1, 65536)
            )

            print(
                color(
                    "\n[!] Full TCP scan selected.",
                    YELLOW
                )
            )

            confirm = input(
                "Continue? [y/N]: "
            ).strip().lower()

            if confirm == "y":

                run_scan(
                    target,
                    ports,
                    100
                )

        # ----------------------------------------------------
        # CUSTOM
        # ----------------------------------------------------

        elif choice == "4":

            ports = ask_ports()

            run_scan(
                target,
                ports,
                50
            )

        # ----------------------------------------------------
        # COMPREHENSIVE
        # ----------------------------------------------------

        elif choice == "5":

            run_scan(
                target,
                TOP_PORTS,
                60
            )

        else:

            print(
                color(
                    "\nInvalid option.",
                    RED
                )
            )

        input(
            "\nPress ENTER to return to menu..."
        )


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    try:

        main_menu()

    except KeyboardInterrupt:

        print(
            color(
                "\n\n[!] Scan interrupted.",
                YELLOW
            )
        )

        sys.exit(0)

    except Exception as e:

        print(
            color(
                f"\n[!] Unexpected error: {e}",
                RED
            )
        )

        sys.exit(1)
