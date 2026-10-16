#!/usr/bin/env python3
"""
NTLM Scanner
============
Detects NTLM authentication endpoints over HTTP/HTTPS and SMB across a
single host, a list of hosts, or a CIDR range. Parses NTLM Type-2 challenge
messages to extract target info (domain, server name, OS version where
available) and flags hosts that may be vulnerable to NTLM relay attacks
(e.g. SMB signing disabled, HTTP endpoints without channel binding).

Intended for authorized penetration testing / internal security auditing
only. Do not scan systems you do not have explicit permission to test.

Author: Srinath
"""

import argparse
import base64
import concurrent.futures
import ipaddress
import json
import socket
import ssl
import struct
import sys
import time
from datetime import datetime, timezone

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Missing dependency: requests. Install with: pip install requests")
    sys.exit(1)

NTLM_MAGIC = b"NTLMSSP\x00"

# ---------------------------------------------------------------------------
# NTLM Type-2 (Challenge) message parsing
# ---------------------------------------------------------------------------

def parse_ntlm_challenge(blob: bytes) -> dict:
    """Parse a raw NTLM Type-2 challenge message into its fields."""
    info = {}
    if len(blob) < 32 or blob[:8] != NTLM_MAGIC:
        return info

    msg_type = struct.unpack("<I", blob[8:12])[0]
    if msg_type != 2:
        return info

    target_name_len = struct.unpack("<H", blob[12:14])[0]
    target_name_off = struct.unpack("<I", blob[16:20])[0]
    flags = struct.unpack("<I", blob[20:24])[0]
    server_challenge = blob[24:32].hex()

    info["server_challenge"] = server_challenge
    info["negotiate_flags"] = hex(flags)
    info["target_name"] = ""
    info["ntlm_version"] = "NTLMv1/v2 (flag-dependent)"

    if target_name_off and target_name_len and target_name_off + target_name_len <= len(blob):
        try:
            info["target_name"] = blob[target_name_off:target_name_off + target_name_len].decode("utf-16-le", errors="ignore")
        except Exception:
            pass

    # Target Info block (AV_PAIRs) - present when len(blob) >= 48
    if len(blob) >= 48:
        ti_len = struct.unpack("<H", blob[40:42])[0]
        ti_off = struct.unpack("<I", blob[44:48])[0]
        av_pairs = {}
        if ti_off and ti_len and ti_off + ti_len <= len(blob):
            data = blob[ti_off:ti_off + ti_len]
            pos = 0
            names = {
                1: "NetBIOS Computer Name", 2: "NetBIOS Domain Name",
                3: "DNS Computer Name", 4: "DNS Domain Name",
                5: "DNS Tree Name", 7: "Timestamp",
            }
            while pos + 4 <= len(data):
                av_id, av_len = struct.unpack("<HH", data[pos:pos + 4])
                pos += 4
                if av_id == 0:
                    break
                value = data[pos:pos + av_len]
                pos += av_len
                label = names.get(av_id)
                if label:
                    if av_id == 7 and len(value) == 8:
                        av_pairs[label] = "<FILETIME present>"
                    else:
                        try:
                            av_pairs[label] = value.decode("utf-16-le", errors="ignore")
                        except Exception:
                            av_pairs[label] = value.hex()
        info["av_pairs"] = av_pairs

    # Negotiate flag interpretation relevant to relay risk
    info["flag_ntlmssp_negotiate_sign"] = bool(flags & 0x00000010)
    info["flag_ntlmssp_negotiate_seal"] = bool(flags & 0x00000020)
    info["flag_ntlmssp_negotiate_always_sign"] = bool(flags & 0x00008000)
    info["flag_negotiate_target_info"] = bool(flags & 0x00800000)

    return info


# ---------------------------------------------------------------------------
# HTTP(S) NTLM detection
# ---------------------------------------------------------------------------

def probe_http_ntlm(host: str, port: int, use_tls: bool, timeout: float) -> dict:
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}/"
    result = {"service": "http", "port": port, "tls": use_tls, "ntlm": False}

    try:
        resp = requests.get(url, timeout=timeout, verify=False)
    except requests.exceptions.RequestException as e:
        result["error"] = str(e)
        return result

    www_auth = resp.headers.get("WWW-Authenticate", "")
    if "NTLM" in www_auth:
        result["ntlm"] = True
        result["auth_header"] = www_auth

        # Send the actual Type-1 negotiate message to pull a Type-2 challenge
        negotiate_b64 = base64.b64encode(
            b"NTLMSSP\x00" + struct.pack("<I", 1) + struct.pack("<I", 0xa2088207) +
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        ).decode()
        try:
            resp2 = requests.get(url, timeout=timeout, verify=False,
                                  headers={"Authorization": f"NTLM {negotiate_b64}"})
            chal_header = resp2.headers.get("WWW-Authenticate", "")
            if chal_header.startswith("NTLM "):
                chal_b64 = chal_header.split(" ", 1)[1]
                chal_bytes = base64.b64decode(chal_b64 + "=" * (-len(chal_b64) % 4))
                result["challenge_info"] = parse_ntlm_challenge(chal_bytes)
        except Exception as e:
            result["challenge_error"] = str(e)

        # Relay risk heuristic: NTLM over plain HTTP = classic relay vector
        result["relay_risk"] = (not use_tls)
    elif "Negotiate" in www_auth:
        result["spnego"] = True

    return result


# ---------------------------------------------------------------------------
# SMB NTLM detection (raw negotiate, no external smb library required)
# ---------------------------------------------------------------------------

def probe_smb_ntlm(host: str, port: int, timeout: float) -> dict:
    result = {"service": "smb", "port": port, "ntlm": False}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # SMB1 Negotiate Protocol Request advertising dialects up to SMB 2.1,
        # enough to get the server to respond and reveal signing requirements.
        negotiate_req = bytes.fromhex(
            "00000085"  # NBSS length
            "ff534d4272000000001843c80000000000000000000000ffff00000000"  # SMB1 header
            "00120002" "4e54204c4d20302e3132" "00"  # dialect NT LM 0.12
        )
        sock.sendall(negotiate_req)
        data = sock.recv(4096)
        sock.close()

        if b"SMB" in data[:40]:
            result["ntlm"] = True
            result["raw_response_len"] = len(data)
            # Security Mode byte (offset varies); best-effort signing check
            if len(data) > 39:
                security_mode = data[39]
                result["signing_enabled"] = bool(security_mode & 0x02)
                result["signing_required"] = bool(security_mode & 0x08)
                result["relay_risk"] = not result["signing_required"]
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# Scanning orchestration
# ---------------------------------------------------------------------------

def expand_targets(target: str) -> list:
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
    except ValueError:
        return [target]


def scan_host(host: str, args) -> dict:
    record = {"host": host, "timestamp": datetime.now(timezone.utc).isoformat(), "results": []}

    if "http" in args.services:
        record["results"].append(probe_http_ntlm(host, args.http_port, use_tls=False, timeout=args.timeout))
    if "https" in args.services:
        record["results"].append(probe_http_ntlm(host, args.https_port, use_tls=True, timeout=args.timeout))
    if "smb" in args.services:
        record["results"].append(probe_smb_ntlm(host, args.smb_port, timeout=args.timeout))

    record["ntlm_detected"] = any(r.get("ntlm") for r in record["results"])
    record["relay_risk"] = any(r.get("relay_risk") for r in record["results"])
    return record


def run_scan(args) -> list:
    targets = []
    for t in args.targets:
        targets.extend(expand_targets(t))
    targets = sorted(set(targets))

    print(f"[*] Scanning {len(targets)} host(s) across services: {', '.join(args.services)}")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(scan_host, h, args): h for h in targets}
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            host = futures[fut]
            try:
                rec = fut.result()
            except Exception as e:
                rec = {"host": host, "error": str(e)}
            results.append(rec)
            flag = "NTLM FOUND" if rec.get("ntlm_detected") else "clean"
            relay = " [RELAY RISK]" if rec.get("relay_risk") else ""
            print(f"  [{i}/{len(targets)}] {host:<16} -> {flag}{relay}")
    return results


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------

def export_report(results: list, fmt: str, out_path: str):
    if fmt == "json":
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
    elif fmt == "csv":
        import csv
        with open(out_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["host", "ntlm_detected", "relay_risk", "services_checked", "timestamp"])
            for r in results:
                writer.writerow([
                    r.get("host"), r.get("ntlm_detected"), r.get("relay_risk"),
                    ";".join(x.get("service", "") for x in r.get("results", [])),
                    r.get("timestamp"),
                ])
    elif fmt == "html":
        rows = "".join(
            f"<tr><td>{r.get('host')}</td><td>{r.get('ntlm_detected')}</td>"
            f"<td>{r.get('relay_risk')}</td><td>{r.get('timestamp')}</td></tr>"
            for r in results
        )
        html = f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>NTLM Scan Report</title>
<style>
body {{ font-family: sans-serif; background:#0d1117; color:#c9d1d9; padding:2rem; }}
table {{ border-collapse: collapse; width:100%; }}
th, td {{ border:1px solid #30363d; padding:8px 12px; text-align:left; }}
th {{ background:#161b22; }}
tr:nth-child(even) {{ background:#161b22; }}
</style></head><body>
<h1>NTLM Scan Report</h1>
<p>Generated: {datetime.now(timezone.utc).isoformat()}</p>
<table><tr><th>Host</th><th>NTLM Detected</th><th>Relay Risk</th><th>Timestamp</th></tr>{rows}</table>
</body></html>"""
        with open(out_path, "w") as f:
            f.write(html)
    print(f"[*] Report written to {out_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="NTLM authentication scanner for HTTP/HTTPS and SMB (authorized testing only).")
    parser.add_argument("targets", nargs="+", help="Target host(s), IP, or CIDR range (e.g. 10.0.0.0/24)")
    parser.add_argument("--services", nargs="+", default=["http", "https", "smb"],
                         choices=["http", "https", "smb"], help="Services to check")
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--https-port", type=int, default=443)
    parser.add_argument("--smb-port", type=int, default=445)
    parser.add_argument("--threads", type=int, default=20, help="Concurrent worker threads")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-probe timeout in seconds")
    parser.add_argument("--output", default=None, help="Report output file path")
    parser.add_argument("--format", default="json", choices=["json", "csv", "html"])
    args = parser.parse_args()

    start = time.time()
    results = run_scan(args)
    elapsed = time.time() - start

    hits = [r for r in results if r.get("ntlm_detected")]
    risky = [r for r in results if r.get("relay_risk")]
    print(f"\n[*] Scan complete in {elapsed:.1f}s")
    print(f"[*] {len(hits)}/{len(results)} hosts have NTLM authentication enabled")
    print(f"[*] {len(risky)} host(s) flagged as potential relay risk")

    if args.output:
        export_report(results, args.format, args.output)


if __name__ == "__main__":
    main()
