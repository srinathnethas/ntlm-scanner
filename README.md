# NTLM Scanner

A multi-threaded Python tool that detects NTLM authentication across **HTTP, HTTPS, and SMB** services, parses the NTLM Type-2 challenge message to pull target/domain info, and flags hosts that look vulnerable to **NTLM relay attacks** (e.g. HTTP NTLM over plaintext, SMB signing not required).

Built for authorized internal network penetration testing and security auditing on Kali Linux.

## Features

- **Multi-service detection** — scans HTTP, HTTPS, and SMB (port 445) in one pass
- **CIDR support** — scan a single IP, a list of hosts, or an entire subnet (`10.0.0.0/24`)
- **Multi-threaded scanning** — configurable worker pool for fast scans of large ranges
- **NTLM challenge parsing** — decodes Type-2 messages to extract NetBIOS/DNS computer name, domain name, and negotiate flags
- **Relay risk heuristics** — flags NTLM-over-HTTP and SMB connections without signing enforced
- **Multi-format reporting** — export results to JSON, CSV, or a styled HTML report

## Installation

```bash
git clone https://github.com/srinathnethas/ntlm-scanner.git
cd ntlm-scanner
pip install -r requirements.txt
```

## Usage

Scan a single host across all services:
```bash
python3 ntlm_scanner.py 192.168.1.10
```

Scan a subnet, HTTP/HTTPS only, with a report:
```bash
python3 ntlm_scanner.py 192.168.1.0/24 --services http https --output report.html --format html
```

Scan a list of targets with more threads and a tighter timeout:
```bash
python3 ntlm_scanner.py 10.0.0.5 10.0.0.6 10.0.0.0/28 --threads 50 --timeout 2 --output results.json
```

### Options

| Flag | Description | Default |
|---|---|---|
| `targets` | Host(s), IP(s), or CIDR range(s) | required |
| `--services` | `http`, `https`, `smb` (one or more) | all three |
| `--http-port` / `--https-port` / `--smb-port` | Custom ports | 80 / 443 / 445 |
| `--threads` | Concurrent workers | 20 |
| `--timeout` | Per-probe timeout (seconds) | 3.0 |
| `--output` | Report file path | none (console only) |
| `--format` | `json`, `csv`, `html` | json |

## Sample output

```
[*] Scanning 254 host(s) across services: http, https, smb
  [1/254] 192.168.1.1     -> clean
  [2/254] 192.168.1.10    -> NTLM FOUND [RELAY RISK]
  [3/254] 192.168.1.15    -> NTLM FOUND
  ...
[*] Scan complete in 14.2s
[*] 12/254 hosts have NTLM authentication enabled
[*] 4 host(s) flagged as potential relay risk
```

## How it works

- **HTTP/HTTPS**: sends a request and checks the `WWW-Authenticate` header for `NTLM`. If present, sends a Type-1 Negotiate message and parses the returned Type-2 Challenge to extract target info. NTLM offered over plain HTTP (no TLS) is flagged as a relay risk since credentials/challenges can be intercepted and relayed.
- **SMB**: sends a raw SMB1 Negotiate Protocol Request and inspects the Security Mode byte in the response to determine whether message signing is enabled/required. SMB signing *not required* is flagged as a relay risk (the classic vector for SMB relay attacks like those used by Responder/ntlmrelayx).

## Disclaimer

This tool is intended for **authorized security testing and auditing only** — use it only against systems you own or have explicit written permission to test. Unauthorized scanning of networks you do not control may be illegal.

## License

MIT
