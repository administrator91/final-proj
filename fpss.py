#!/usr/bin/env python3
# fps.py - Final Professional Version (Clean, Full Output)
# Developed by: Rajarshi Sarkar
# Website: rajarshisarkar.com

import socket
import sys
import time
import queue
import threading
import subprocess
import os
import re
import argparse
import requests
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

# -------------------------------------------------------------
# Utility Functions
# -------------------------------------------------------------
def is_nmap_available():
    try:
        subprocess.run(["nmap", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def parse_nmap_sV_output(nmap_stdout):
    svc_map = {}
    for line in nmap_stdout.splitlines():
        if re.match(r"^\d+\/(tcp|udp)\s+", line):
            parts = re.split(r"\s+", line, maxsplit=4)
            try:
                port = int(parts[0].split("/")[0])
                svc = parts[2] if len(parts) > 2 else ""
                ver = " ".join(parts[3:]) if len(parts) > 3 else ""
                svc_map[port] = (svc, ver)
            except:
                continue
    return svc_map

def os_by_ttl(host):
    param = "-c" if sys.platform != "win32" else "-n"
    try:
        out = subprocess.run(["ping", param, "1", host], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"[Tt][Tt][Ll]=\s*(\d+)|ttl=(\d+)", out)
        if not m:
            return "Unknown"
        ttl = int(m.group(1) or m.group(2))
        if ttl >= 128:
            return "Windows (likely)"
        elif 64 <= ttl < 128:
            return "Linux/Unix (likely)"
        else:
            return "Unknown"
    except:
        return "Unknown"

def clean_nmap_output(text):
    """Keep nearly full nmap output but remove warnings, 'Starting Nmap', and 'Nmap done' lines."""
    if not text:
        return ""
    lines = text.splitlines()
    cleaned = []
    skip_patterns = [
        re.compile(r"^Starting Nmap", re.I),
        re.compile(r"^Nmap done:", re.I),
        re.compile(r"^Warning:", re.I),
        re.compile(r"^Service detection performed", re.I),
        re.compile(r"^Please report any incorrect results", re.I),
    ]
    for ln in lines:
        if not any(pat.search(ln) for pat in skip_patterns):
            cleaned.append(ln.rstrip())
    while cleaned and cleaned[0].strip() == "":
        cleaned.pop(0)
    while cleaned and cleaned[-1].strip() == "":
        cleaned.pop()
    return "\n".join(cleaned)

def clean_nmap_stderr(stderr_text):
    """Remove script.db and other known warning lines."""
    if not stderr_text:
        return ""
    lines = stderr_text.splitlines()
    filtered = []
    skip_patterns = [
        re.compile(r"script\.db", re.I),
        re.compile(r"NMAPDIR", re.I),
        re.compile(r"Nmap done", re.I),
        re.compile(r"Warning", re.I),
    ]
    for ln in lines:
        if not any(pat.search(ln) for pat in skip_patterns):
            filtered.append(ln)
    return "\n".join(filtered)

# -------------------------------------------------------------
# Arguments
# -------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="FPS - Personal Fast Scanner by Rajarshi Sarkar (rajarshisarkar.com)",
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument("target", help="Target hostname or IP")
parser.add_argument("--start", type=int, default=1, help="Start port (default 1)")
parser.add_argument("--end", type=int, default=1024, help="End port (default 1024)")
parser.add_argument("--threads", type=int, default=100, help="Number of threads (default 100)")
parser.add_argument("--service-version", action="store_true", help="Run nmap -sV for service/version detection")
parser.add_argument("--script", action="append",
                    help="Run script(s) from ./scripts (comma-separated). Example: --script ftp-anon:21,ssh-hostkey:22")
parser.add_argument("--save", help="Save output to file (e.g., result.txt)")
parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode (only console, not saved)")
args = parser.parse_args()

# -------------------------------------------------------------
# Setup
# -------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, "scripts")

try:
    target_ip = socket.gethostbyname(args.target)
except:
    print(Fore.RED + "[!] Could not resolve host.")
    sys.exit(1)

start_port = max(1, args.start)
end_port = min(65535, args.end)
threads_count = max(1, args.threads)
total_ports = end_port - start_port + 1

q = queue.Queue()
open_ports = []
completed = 0
done_event = threading.Event()
lock = threading.Lock()

def get_banner(p, s, host):
    if p == 80:
        try:
            r = requests.get("http://" + host, timeout=2)
            return r.headers.get("Server", "HTTP")
        except:
            return "HTTP"
    try:
        s.settimeout(2)
        data = s.recv(1024)
        return data.decode(errors="ignore").strip() or "No banner"
    except:
        return "No banner"

def worker(verbose=False):
    global completed
    while True:
        try:
            port = q.get_nowait()
        except queue.Empty:
            return
        try:
            s = socket.socket()
            s.settimeout(1.5)
            res = s.connect_ex((target_ip, port))
            if res == 0:
                banner = get_banner(port, s, args.target)
                with lock:
                    open_ports.append((port, banner))
                if verbose:
                    print(Fore.GREEN + f"[+] {port}/tcp open")
            elif verbose:
                print(Fore.WHITE + f"[-] {port}/tcp closed")
            s.close()
        except:
            pass
        with lock:
            completed += 1
        q.task_done()

def progress():
    while not done_event.is_set():
        try:
            line = sys.stdin.readline()
            if line == "":
                break
            with lock:
                per = (completed / total_ports) * 100
            print(Fore.MAGENTA + f"[Progress] {completed}/{total_ports} ports ({per:.1f}%)")
        except:
            break

for p in range(start_port, end_port + 1):
    q.put(p)

threads = []
for _ in range(threads_count):
    t = threading.Thread(target=worker, args=(args.verbose,))
    t.daemon = True
    t.start()
    threads.append(t)

progress_thread = threading.Thread(target=progress, daemon=True)
progress_thread.start()

scan_start = time.time()
q.join()
done_event.set()
duration = time.time() - scan_start
open_ports.sort(key=lambda x: x[0])

# -------------------------------------------------------------
# OS Detection
# -------------------------------------------------------------
os_guess = os_by_ttl(args.target)

# -------------------------------------------------------------
# Service/Version detection
# -------------------------------------------------------------
nmap_env = os.environ.copy()
nmap_env["NMAPDIR"] = SCRIPTS_DIR
service_map = {}
if args.service_version and open_ports and is_nmap_available():
    ports_str = ",".join(str(p) for p, _ in open_ports)
    out = subprocess.run(["nmap", "-sV", "-p", ports_str, target_ip],
                         capture_output=True, text=True, env=nmap_env)
    service_map = parse_nmap_sV_output(out.stdout)

# -------------------------------------------------------------
# Script Runner
# -------------------------------------------------------------
script_jobs = []
if args.script:
    for s_arg in args.script:
        for tok in s_arg.split(","):
            tok = tok.strip()
            if not tok:
                continue
            if ":" in tok:
                name, ports = tok.split(":", 1)
                ports = [int(x) for x in ports.split(",") if x.isdigit()]
            else:
                name, ports = tok, []
            script_jobs.append((name.strip().replace(".nse", ""), ports))

script_results = {}
if script_jobs:
    for name, ports in script_jobs:
        p1 = os.path.join(SCRIPTS_DIR, f"{name}.nse")
        p2 = os.path.join(SCRIPTS_DIR, name, f"{name}.nse")
        script_file = p1 if os.path.isfile(p1) else (p2 if os.path.isfile(p2) else None)
        if not script_file:
            script_results[name] = {"status": "not-found", "out": ""}
            continue
        run_ports = ports if ports else [p for p, _ in open_ports]
        if not run_ports:
            script_results[name] = {"status": "no-open-ports", "out": ""}
            continue
        cmd = ["nmap", "-Pn", "-p", ",".join(map(str, run_ports)), "--script", script_file, target_ip]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=nmap_env)
        out_clean = clean_nmap_output(proc.stdout)
        err_clean = clean_nmap_stderr(proc.stderr)
        combined = out_clean
        if err_clean:
            combined += "\n" + err_clean
        script_results[name] = {"status": "ok", "out": combined.strip()}

# -------------------------------------------------------------
# Final Report Build
# -------------------------------------------------------------
report = []
report.append("="*72)
report.append("Personal Fast Scanner - Final Year Project (Rajarshi Sarkar)".center(72))
report.append("Website: rajarshisarkar.com".center(72))
report.append("="*72)
report.append(f"Target: {args.target} ({target_ip})")
report.append(f"Ports: {start_port}-{end_port} | Threads: {threads_count}")
report.append(f"Scan Duration: {duration:.2f}s\n")

report.append("PORTS\n-----")
if open_ports:
    for p, _ in open_ports:
        if p in service_map:
            svc, ver = service_map[p]
            report.append(f"{p}/tcp open {svc} {ver}")
        else:
            banner = next((b for pp, b in open_ports if pp == p), "")
            report.append(f"{p}/tcp open {banner}")
else:
    report.append("No open ports found.")
report.append("")

report.append("OS GUESS\n--------")
report.append(os_guess + "\n")

report.append("SCRIPTS RESULTS\n---------------")
if script_results:
    for name, res in script_results.items():
        report.append(f"Script: {name} -> {res['status']}")
        if res["out"]:
            for ln in res["out"].splitlines():
                report.append("  " + ln)
else:
    report.append("No scripts run.\n")

report.append("="*72)
report.append(f"Scan completed in {duration:.2f} seconds")
report.append(f"Generated: {time.ctime()}")
report.append("="*72)
final_report = "\n".join(report)

# -------------------------------------------------------------
# Console Output (One-Time)
# -------------------------------------------------------------
print("\n" + Fore.GREEN + "="*72)
print(Fore.CYAN + f"Target: {args.target} ({target_ip})")
print(Fore.GREEN + "="*72)
print(Fore.YELLOW + "PORTS\n-----")
for p, _ in open_ports:
    if p in service_map:
        svc, ver = service_map[p]
        print(Fore.WHITE + f"{p}/tcp open {svc} {ver}")
    else:
        banner = next((b for pp, b in open_ports if pp == p), "")
        print(Fore.WHITE + f"{p}/tcp open {banner}")

print("\n" + Fore.YELLOW + "OS GUESS\n--------")
print(Fore.WHITE + os_guess)

print("\n" + Fore.YELLOW + "SCRIPTS RESULTS\n---------------")
if script_results:
    for name, res in script_results.items():
        print(Fore.CYAN + f"Script: {name} -> {res['status']}")
        if res["out"]:
            for ln in res["out"].splitlines():
                print(Fore.WHITE + "  " + ln)
else:
    print(Fore.WHITE + "No scripts run.")

print("\n" + Fore.MAGENTA + f"Scan completed in {duration:.2f} seconds")
print(Fore.GREEN + "="*72)

# -------------------------------------------------------------
# Save Report
# -------------------------------------------------------------
if args.save:
    outfile = args.save if args.save.endswith(".txt") else args.save + ".txt"
else:
    outfile = "scan_report.txt"

try:
    with open(outfile, "w", encoding="utf-8") as f:
        f.write(final_report)
    print(Fore.GREEN + f"[+] Report saved as {outfile}")
except Exception as e:
    print(Fore.RED + f"[!] Error saving report: {e}")

print(Fore.CYAN + "Done. Use responsibly. (Scan only authorized targets.)")
