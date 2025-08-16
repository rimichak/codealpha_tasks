#!/usr/bin/env python3
"""
suricata_blocker.py
Watches Suricata's /var/log/suricata/eve.json for alerts and blocks offending IPs with iptables.
Simple, educational script. Use with caution in production.
"""

import json
import time
import os
import subprocess
from collections import defaultdict

EVE_FILE = "/var/log/suricata/eve.json"
BLOCK_THRESHOLD = 3         # number of alerts from an IP before blocking
BLOCK_DURATION = 3600       # seconds to keep IP blocked (simple TTL in-memory)

blocked = {}                # ip -> unblock_time
counters = defaultdict(int)

def iptables_block(ip):
    # Add a DROP rule (idempotent check)
    # you might prefer ipset for performance in production
    try:
        subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # rule exists
        return True
    except subprocess.CalledProcessError:
        # rule didn't exist; add it
        subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"], check=True)
        return True

def iptables_unblock(ip):
    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    except subprocess.CalledProcessError:
        pass

def follow(file):
    file.seek(0, os.SEEK_END)
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

def main():
    if not os.path.exists(EVE_FILE):
        print(f"eve file not found: {EVE_FILE}")
        return

    with open(EVE_FILE, "r", encoding="utf-8") as f:
        loglines = follow(f)
        for raw in loglines:
            try:
                o = json.loads(raw)
            except Exception:
                continue

            # handle only alert events
            if o.get("event_type") != "alert":
                continue

            src = o.get("src_ip")
            if not src:
                continue

            # Simple heuristic: focus on high severity alerts
            severity = o.get("alert", {}).get("severity", 1)
            sig = o.get("alert", {}).get("signature", "unknown")
            # increase counters on severity >= 3 (adjust as needed)
            if severity >= 3:
                counters[src] += 1
                print(f"[+] Alert from {src}: {sig} (severity {severity}) count={counters[src]}")
            else:
                # optionally still count low severity events
                counters[src] += 1

            # If threshold exceeded and not already blocked, block
            if counters[src] >= BLOCK_THRESHOLD and src not in blocked:
                print(f"[!] Blocking {src} (count {counters[src]})")
                if iptables_block(src):
                    blocked[src] = time.time() + BLOCK_DURATION

            # periodic cleanup of expired blocks
            now = time.time()
            expired = [ip for ip, until in blocked.items() if until <= now]
            for ip in expired:
                print(f"[!] Unblocking {ip}")
                iptables_unblock(ip)
                del blocked[ip]
                counters[ip] = 0

if __name__ == "__main__":
    main()
