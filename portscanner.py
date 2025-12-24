#!/usr/bin/env python3

import socket
import time
import sys
from concurrent.futures import ThreadPoolExecutor

# -----------------------------
# Configuration
# -----------------------------
DEFAULT_TIMEOUT = 0.6
MAX_CONFIDENCE = 100
THREADS = 100
BANNER_GRAB = True

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# -----------------------------
# Utility Functions
# -----------------------------

def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print("[!] Failed to resolve target")
        sys.exit(1)

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"

# -----------------------------
# Core Scan Function
# -----------------------------

def tcp_connect_scan(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(DEFAULT_TIMEOUT)

    start_time = time.time()
    result = sock.connect_ex((ip, port))
    elapsed = time.time() - start_time

    banner = None
    if result == 0 and BANNER_GRAB:
        try:
            sock.sendall(b"\r\n")
            banner = sock.recv(1024).decode(errors="ignore").strip()
        except:
            pass

    sock.close()
    return port, result, elapsed, banner

# -----------------------------
# Confidence Engine
# -----------------------------

def calculate_confidence(result, response_time):
    confidence = 0

    if result == 0:
        confidence += 60
    elif result == 111:
        confidence += 10

    if response_time < 0.2:
        confidence += 25
    elif response_time < 0.5:
        confidence += 15

    return min(confidence, MAX_CONFIDENCE)

# -----------------------------
# Result Formatter
# -----------------------------

def interpret_result(port, result, response_time, banner):
    service = get_service_name(port)
    confidence = calculate_confidence(result, response_time)

    if result == 0:
        state = f"{GREEN}OPEN{RESET}"
    elif result == 111:
        state = f"{RED}CLOSED{RESET}"
    else:
        state = f"{YELLOW}FILTERED{RESET}"

    print(f"[{state}] {port}/tcp ({service}) — {confidence}%")

    if banner:
        print(f"      Banner: {CYAN}{banner}{RESET}")

    return result == 0

# -----------------------------
# Scan Controller
# -----------------------------

def scan_target(target, start_port, end_port):
    ip = resolve_target(target)

    print(f"\n[*] SentinelScan v2.0")
    print(f"[*] Target: {target} ({ip})")
    print(f"[*] Ports: {start_port}-{end_port}")
    print(f"[*] Threads: {THREADS}\n")

    open_ports = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [
            executor.submit(tcp_connect_scan, ip, port)
            for port in range(start_port, end_port + 1)
        ]

        for future in futures:
            port, result, response_time, banner = future.result()
            if interpret_result(port, result, response_time, banner):
                open_ports.append(port)

    # -----------------------------
    # Summary
    # -----------------------------
    print("\n" + "-" * 40)
    print("[*] Scan Summary")
    print(f"[*] Open ports: {len(open_ports)}")

    if open_ports:
        print("[*] Ports:", ", ".join(map(str, open_ports)))
    print("-" * 40)

# -----------------------------
# Entry Point
# -----------------------------

def main():
    print("=== SentinelScan | Ethical Port Scanner ===")
    print("Authorized use only.\n")

    target = input("Target IP / Hostname: ").strip()
    start_port = int(input("Start port: "))
    end_port = int(input("End port: "))

    scan_target(target, start_port, end_port)

if __name__ == "__main__":
    main()
