import nmap
import socket
from models import PortInfo, ScanResult

RISKY_PORTS = {
    21:   ("ftp",     "high"),    # FTP - στέλνει passwords unencrypted
    22:   ("ssh",     "medium"),  # SSH - ασφαλές αλλά brute-force target
    23:   ("telnet",  "high"),    # Telnet - όλα unencrypted
    25:   ("smtp",    "medium"),  # Email server - spam/relay abuse
    80:   ("http",    "low"),     # HTTP - unencrypted web
    443:  ("https",   "low"),     # HTTPS - κανονικό, ασφαλές
    3306: ("mysql",   "high"),    # Database - δεν πρέπει να είναι public
    5432: ("postgres","high"),    # Database - ίδιο
    6379: ("redis",   "high"),    # Redis - συχνά misconfigured
    8080: ("http-alt","low"),     # Dev server
}

def risk_asess(port: int, service: str) -> str:
    if port in RISKY_PORTS:
        return RISKY_PORTS[port][1]

    return "medium"


def port_score(risk: str) -> int:

    return {"low": 10, "medium": 25, "high": 40}.get(risk, 15)

def run_nmap_scan(target: str) -> ScanResult:
    try:
        socket.gethostbyname(target)

    except socket.gaierror:
        return ScanResult(target = target,
                          ip = "unknown",
                          is_up = False,
                          ports = [],
                          total_score = 0,
                          verdict = "unknown",
                          error = "Not Found")
    try:
        nm = nmap.PortScanner()

        nm.scan(hosts = target, arguments = "-F -sV -T4 --host-timeout 120s")

    except nmap.PortScannerError as e:
        return ScanResult(target = target,
                   ip = "Unknown",
                   is_up = False,
                   ports = [],
                   total_score = 0,
                   verdict = "unknown",
                   error = f"Scan failed: {str(e)}")

    hosts = nm.all_hosts()
    if not hosts:
        return ScanResult(target=target,
                          ip="unknown",
                          is_up=False,
                          ports=[],
                          total_score=0,
                          verdict="unknown",
                          error="Host unreachable or no results")

    actual_host = hosts[0]
    host = nm[actual_host]
    ip = host.get("addresses", {}).get("ipv4", actual_host)
    is_up = host.state() == "up"

    ports = []
    total_score = 0

    for port, data in host.get("tcp", {}).items():
        if data["state"] != "open":
            continue

        service = data.get("name", "unknown")
        risk = risk_assess(port, service)
        score = port_score(risk)
        total_score += score

        ports.append(PortInfo(port = port,
                              state = data["state"],
                              service = service,
                              risk = risk))

    if total_score < 20:

        verdict = "safe"

    elif 20 < total_score <= 50:

        verdict = "suspicious"

    else:

        verdict = "dangerous"

    return ScanResult(target = target,
                      ip = ip,
                      is_up = is_up,
                      ports = ports,
                      total_score = total_score,
                      verdict = verdict)
