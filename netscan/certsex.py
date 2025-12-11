import sys
import ssl
import socket
import threading
import masscan
import OpenSSL.crypto
import subprocess
import os
import argparse
import shutil

try:
    import queue
except ImportError:
    import Queue as queue

def notice(msg):
    print(f"\033[1;34m[INFO]\033[0m {msg}")

def warn(msg):
    print(f"\033[1;33m[WARN]\033[0m {msg}")

def err(msg):
    print(f"\033[1;31m[ERROR]\033[0m {msg}")

def success(msg):
    print(f"\033[1;32m[SUCCESS]\033[0m {msg}")


parser = argparse.ArgumentParser(description="Hybrid Masscan + SSL + HTTPX Scanner")
parser.add_argument('-f', '--file', required=True, help="Input file containing ASNs or CIDRs")
parser.add_argument('-o', '--output', required=True, help="Final output file path")

args = parser.parse_args()

FINAL_OUTPUT_FILE = args.output
OUTPUT_DIR = os.path.dirname(FINAL_OUTPUT_FILE)
if OUTPUT_DIR and not os.path.exists(OUTPUT_DIR):
    notice(f"Creating output directory: {OUTPUT_DIR}")
    os.makedirs(OUTPUT_DIR)
elif not OUTPUT_DIR:
    OUTPUT_DIR = "."

TARGETS_FILE = os.path.join(OUTPUT_DIR, "initial.targets")
DOMAINS_FILE = os.path.join(OUTPUT_DIR, "live.host")

q = queue.Queue()
subs_ssl = []
found_domains = []
lock = threading.Lock()

def resolve_targets():
#    notice(f"Reading input from {args.file}...")
    
    if not os.path.exists(args.file):
        err(f"File not found: {args.file}")
        sys.exit(1)

    with open(args.file, 'r') as infile, open(TARGETS_FILE, 'w') as outfile:
        for line in infile:
            line = line.strip()
            if not line:
                continue

            if line.upper().startswith("AS") and line[2].isdigit():
                resolve_asn(line, outfile)
            else:
                outfile.write(line + "\n")
                
#    success(f"Targets prepared in {TARGETS_FILE}")

def resolve_asn(asn, outfile):
    if not shutil.which("asnmap"):
        err("asnmap not found. Please install it to resolve ASNs.")
        sys.exit(1)
        
 #   notice(f"Resolving {asn}...")
    try:
        cmd = ["asnmap", "-a", asn, "-silent"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout.strip():
            outfile.write(result.stdout)
            if not result.stdout.endswith('\n'):
                outfile.write('\n')
        else:
            warn(f"No CIDRs found for {asn}")
    except Exception as e:
        err(f"Failed to resolve {asn}: {e}")

def run_masscan():
 #   notice(f"Starting Masscan on {TARGETS_FILE}...")
    try:
        mas = masscan.PortScanner()
        mas.scan(arguments=f'-iL {TARGETS_FILE} -p443 --rate 5000 --wait 0 --open')
        
        for host in mas.all_hosts:
            subs_ssl.append(host)
            
 #       success(f"Masscan complete. Found {len(subs_ssl)} hosts with port 443.")
        
    except Exception as e:
        err(f'Masscan Error: {e}')
        if len(subs_ssl) == 0:
            warn("No ports found open. Exiting this run.")
            sys.exit(1)

def process_cert_subs(ip):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        cert_pem = ssl.get_server_certificate((str(ip), 443), timeout=5)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
        
        subject = x509.get_subject()
        cn = subject.CN
        
        if cn:
            clean_cn = cn.replace('*.', '')
            with lock:
                if clean_cn not in found_domains:
                    found_domains.append(clean_cn)
                    success(f"{ip} -> {clean_cn}")
            
    except Exception:
        pass

def process_queue():
    while not q.empty():
        current_ip = q.get()
        process_cert_subs(current_ip)
        q.task_done()

if __name__ == "__main__":

    resolve_targets()

    run_masscan()
    
    if len(subs_ssl) > 0:
        for i in subs_ssl:
            q.put(str(i).strip())
    else:
        warn('No live hosts found.')
        sys.exit(1)

 #   notice("Extracting certificates using 50 threads...")
    threads = []
    for i in range(50):
        t = threading.Thread(target=process_queue)
        t.daemon = True 
        t.start()
        threads.append(t)
    q.join()

    if len(found_domains) > 0:
        notice(f"Saved {len(found_domains)} domains: {DOMAINS_FILE}")
        
        with open(DOMAINS_FILE, 'a') as f:
            for domain in found_domains:
                f.write(f"{domain}\n")

        notice("Live assets verification with HTTPX...")
        
        httpx_cmd = [
            "httpx",
            "-l", DOMAINS_FILE,
            "-silent",
            "-random-agent",
            "-timeout", "10",
            "-H", "X-Forwarded-For: 127.0.0.1",
            "-H", "Referrer: 127.0.0.1",
            "-H", "X-Forward-For: 127.0.0.1",
            "-H", "X-Forwarded-Host: 127.0.0.1",
            "-status-code",
            "-content-length",
            "-title",
            "-tech-detect",
            "-cdn",
            "-server",
            "-method",
            "-follow-redirects",
            "-cname",
            "-asn",
            "-jarm"
        ]

        try:
            result = subprocess.run(httpx_cmd, capture_output=True, text=True, check=True)
            
            with open(FINAL_OUTPUT_FILE, 'a') as f:
                f.write(result.stdout)
                
            success(f"Httpx scan results saved: {FINAL_OUTPUT_FILE}")
            
        except FileNotFoundError:
            err("Error: 'httpx' not found in PATH.")
        except subprocess.CalledProcessError:
            err("HTTPX encountered an error.")
    else:
        warn("No domains extracted for SSL certificate.")
