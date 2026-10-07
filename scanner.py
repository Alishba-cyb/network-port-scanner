#!/usr/bin/env python3
"""
Network Port Scanner & Vulnerability Assessment Tool
----------------------------------------------------
A multi-threaded TCP connect scanner that:
  * resolves a hostname or IP address,
  * scans common (or user-defined) ports concurrently,
  * identifies the typical service on each open port,
  * attaches a basic risk note to commonly insecure services,
  * prints a terminal dashboard and saves a report to scan_results.txt.

LEGAL NOTICE: Only scan systems you own or have explicit written
permission to test. Unauthorized scanning may be illegal.
"""

import argparse
import socket
import sys
import threading
from datetime import datetime
from queue import Queue, Empty

# ----------------------------------------------------------------------
# Knowledge base: port -> (service name, risk level, assessment note)
# ----------------------------------------------------------------------
PORT_INFO = {
    21:   ("FTP",           "HIGH",   "Cleartext credentials; allow SFTP/FTPS only, disable anonymous login."),
    22:   ("SSH",           "LOW",    "Encrypted, but use key auth, disable root login, and patch regularly."),
    23:   ("Telnet",        "HIGH",   "Fully unencrypted remote access; replace with SSH."),
    25:   ("SMTP",          "MEDIUM", "Check for open relay and enforce TLS/authentication."),
    53:   ("DNS",           "MEDIUM", "Disable zone transfers and recursion for external hosts."),
    80:   ("HTTP",          "MEDIUM", "Unencrypted web traffic; redirect to HTTPS."),
    110:  ("POP3",          "HIGH",   "Cleartext mail retrieval; use POP3S (995)."),
    111:  ("RPCbind",       "MEDIUM", "Can leak RPC service info; restrict or disable."),
    135:  ("MS-RPC",        "HIGH",   "Frequently abused on Windows; block at the firewall."),
    139:  ("NetBIOS",       "HIGH",   "Legacy SMB/NetBIOS exposure; block externally."),
    143:  ("IMAP",          "MEDIUM", "Cleartext mail access; use IMAPS (993)."),
    443:  ("HTTPS",         "LOW",    "Encrypted web traffic; verify TLS version and certificate."),
    445:  ("SMB",           "HIGH",   "Targeted by ransomware/worms; never expose to the internet."),
    993:  ("IMAPS",         "LOW",    "Encrypted IMAP; verify TLS configuration."),
    995:  ("POP3S",         "LOW",    "Encrypted POP3; verify TLS configuration."),
    1433: ("MS-SQL",        "HIGH",   "Database exposed; restrict to trusted hosts only."),
    1723: ("PPTP VPN",      "MEDIUM", "Weak legacy VPN protocol; migrate to IPsec/WireGuard."),
    3306: ("MySQL",         "HIGH",   "Database exposed; bind to localhost or use a VPN."),
    3389: ("RDP",           "HIGH",   "Common brute-force/ransomware target; use VPN and MFA."),
    5432: ("PostgreSQL",    "HIGH",   "Database exposed; restrict access by IP."),
    5900: ("VNC",           "HIGH",   "Often weakly protected remote desktop; tunnel over SSH/VPN."),
    8080: ("HTTP-Alt",      "MEDIUM", "Often a proxy/admin panel; verify it is intended to be public."),
    8443: ("HTTPS-Alt",     "LOW",    "Alternate HTTPS; verify certificate and application."),
}

# Ports scanned when the user does not specify any
DEFAULT_PORTS = sorted(PORT_INFO.keys())

# Shared state used by all worker threads
results = []                    # list of dicts, one per open port
results_lock = threading.Lock() # prevents race conditions when appending


# ----------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------
def parse_ports(port_arg):
    """Convert a string like '22,80,100-200' into a sorted list of ints."""
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:                          # range, e.g. 1-1024
            start, end = part.split("-", 1)
            ports.update(range(int(start), int(end) + 1))
        elif part:                               # single port
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535.")
    return sorted(ports)


def grab_banner(sock, port):
    """Try to read a short service banner from an already-open socket."""
    try:
        sock.settimeout(1.0)
        if port in (80, 8080, 8443, 443):
            # Web servers stay silent until spoken to, so send a HEAD request
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(128).decode(errors="ignore").strip()
        return data.splitlines()[0][:60] if data else ""
    except (socket.timeout, OSError):
        return ""


def scan_port(ip, port, timeout):
    """Attempt a TCP connection; record the port if it is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        # connect_ex returns 0 on success instead of raising an exception
        if sock.connect_ex((ip, port)) == 0:
            service, risk, note = PORT_INFO.get(
                port, ("Unknown", "INFO", "Unrecognized service; verify it is expected.")
            )
            banner = grab_banner(sock, port)
            with results_lock:
                results.append({
                    "port": port, "service": service,
                    "risk": risk, "note": note, "banner": banner,
                })
    except OSError:
        pass  # network error on this port: treat as closed/filtered
    finally:
        sock.close()


def worker(queue, ip, timeout):
    """Thread target: keep pulling ports from the queue until it is empty."""
    while True:
        try:
            port = queue.get_nowait()
        except Empty:
            return
        scan_port(ip, port, timeout)
        queue.task_done()


def run_scan(ip, ports, thread_count, timeout):
    """Fill a queue with ports and let a pool of threads consume it."""
    queue = Queue()
    for p in ports:
        queue.put(p)

    threads = []
    for _ in range(min(thread_count, len(ports))):
        t = threading.Thread(target=worker, args=(queue, ip, timeout), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()


# ----------------------------------------------------------------------
# Output: terminal dashboard + report file
# ----------------------------------------------------------------------
def build_report(target, ip, start, end, total_ports):
    """Build the report as a list of text lines (used for screen and file)."""
    line = "=" * 92
    duration = (end - start).total_seconds()
    open_ports = sorted(results, key=lambda r: r["port"])

    out = [
        line,
        "  NETWORK PORT SCANNER & VULNERABILITY ASSESSMENT REPORT",
        line,
        f"  Target       : {target} ({ip})",
        f"  Scan started : {start:%Y-%m-%d %H:%M:%S}",
        f"  Scan ended   : {end:%Y-%m-%d %H:%M:%S}",
        f"  Duration     : {duration:.2f} seconds",
        f"  Ports scanned: {total_ports}   |   Open ports: {len(open_ports)}",
        line,
        f"  {'PORT':<8}{'STATE':<8}{'SERVICE':<14}{'RISK':<8}ASSESSMENT",
        "-" * 92,
    ]

    if not open_ports:
        out.append("  No open ports were found.")
    for r in open_ports:
        out.append(f"  {r['port']:<8}{'OPEN':<8}{r['service']:<14}{r['risk']:<8}{r['note']}")
        if r["banner"]:
            out.append(f"  {'':<8}{'':<8}banner: {r['banner']}")

    high = sum(1 for r in open_ports if r["risk"] == "HIGH")
    med = sum(1 for r in open_ports if r["risk"] == "MEDIUM")
    out += [
        line,
        f"  SUMMARY: {high} high-risk, {med} medium-risk service(s) detected.",
        "  Note: risk ratings are general guidance based on the service type,",
        "  not confirmed vulnerabilities. Verify findings manually.",
        line,
    ]
    return out


def save_report(lines, filename):
    """Write the report to disk."""
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ----------------------------------------------------------------------
# Main program
# ----------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Multi-threaded TCP port scanner with basic risk assessment.")
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument("-p", "--ports", default=None,
                        help="Ports, e.g. '22,80,443' or '1-1024' (default: common ports)")
    parser.add_argument("-t", "--threads", type=int, default=100,
                        help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Per-port timeout in seconds (default: 1.0)")
    parser.add_argument("-o", "--output", default="scan_results.txt",
                        help="Report filename (default: scan_results.txt)")
    args = parser.parse_args()

    # Validate the port list
    try:
        ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    except ValueError as err:
        sys.exit(f"[!] Invalid port specification: {err}")

    # Resolve hostname to an IPv4 address
    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        sys.exit(f"[!] Could not resolve host: {args.target}")

    print(f"\n[*] Scanning {args.target} ({ip}) - {len(ports)} ports, "
          f"{min(args.threads, len(ports))} threads...")
    print("[*] Only scan systems you are authorized to test.\n")

    start = datetime.now()
    try:
        run_scan(ip, ports, args.threads, args.timeout)
    except KeyboardInterrupt:
        sys.exit("\n[!] Scan interrupted by user.")
    end = datetime.now()

    report = build_report(args.target, ip, start, end, len(ports))
    print("\n".join(report))

    save_report(report, args.output)
    print(f"\n[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
