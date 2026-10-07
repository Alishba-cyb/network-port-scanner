# Network Port Scanner & Vulnerability Assessment Tool

A fast, multi-threaded TCP port scanner written in pure Python 3. It identifies open ports, maps them to their typical services, flags commonly insecure services with basic risk guidance, and saves a clean report automatically.

> **Disclaimer:** This tool is for educational use and authorized security testing only. Scan only systems you own or have explicit written permission to test. The author accepts no responsibility for misuse.

## Features

- **Multi-threaded scanning** using a thread pool and work queue for high speed
- **Common port coverage** (FTP, SSH, Telnet, HTTP, HTTPS, SMB, RDP, databases, and more) or fully custom ports and ranges
- **Service identification** (for example, Port 80 = HTTP)
- **Basic risk assessment** with HIGH / MEDIUM / LOW ratings and hardening advice
- **Banner grabbing** for extra service detail where available
- **Terminal dashboard** with a professional, readable layout
- **Automatic report** saved to `scan_results.txt`
- **Zero dependencies**: standard library only (`socket`, `threading`, `datetime`, `argparse`)

## Requirements

- Python 3.7 or newer

## Usage

```bash
# Clone the repository
git clone https://github.com/<your-username>/port-scanner.git
cd port-scanner

# Scan default common ports
python3 port_scanner.py scanme.nmap.org

# Scan specific ports
python3 port_scanner.py 192.168.1.1 -p 22,80,443,8080

# Scan a range with 200 threads and a custom report name
python3 port_scanner.py 192.168.1.1 -p 1-1024 -t 200 -o my_report.txt
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `target` | Hostname or IP address | required |
| `-p, --ports` | Ports (`22,80` or `1-1024`) | common ports |
| `-t, --threads` | Number of threads | 100 |
| `--timeout` | Per-port timeout (seconds) | 1.0 |
| `-o, --output` | Report filename | `scan_results.txt` |

## Example Output

```
  PORT    STATE   SERVICE       RISK    ASSESSMENT
--------------------------------------------------------------------------------------------
  22      OPEN    SSH           LOW     Encrypted, but use key auth, disable root login...
  80      OPEN    HTTP          MEDIUM  Unencrypted web traffic; redirect to HTTPS.
```

## How It Works

1. The target hostname is resolved to an IPv4 address.
2. All ports to scan are placed into a thread-safe queue.
3. Worker threads pull ports from the queue and attempt a TCP connection with `socket.connect_ex()`.
4. Open ports are matched against a built-in service and risk database.
5. Results are sorted, shown on screen, and written to a report file.

## Limitations

- TCP connect scan only (no UDP or stealth SYN scanning)
- IPv4 only
- Risk ratings are generic guidance by service type, not confirmed vulnerabilities. Always verify manually.

## Future Improvements

- UDP scanning and IPv6 support
- CVE lookup based on detected banners
- JSON / HTML report export

## License

MIT License. See `LICENSE` for details.
