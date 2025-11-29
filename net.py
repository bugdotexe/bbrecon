import sys
import ssl
import socket
import threading
import masscan
import OpenSSL.crypto
import xml.etree.ElementTree as ET
import subprocess
import os
import argparse
import shutil

# Handle Python 2/3 queue import
try:
    import queue
except ImportError:
    import Queue as queue

# ==========================================
# SETUP & ARGUMENT PARSING
# ==========================================

parser = argparse.ArgumentParser(description="Hybrid Masscan + SSL + HTTPX Scanner")
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-cidr', help="Target IP Range (e.g., 192.168.1.0/24)")
group.add_argument('-asn', help="Target ASN (e.g., AS12345)")
parser.add_argument('-o', '--output', required=True, help="Output folder name")

args = parser.parse_args()

# Create Output Directory
if not os.path.exists(args.output):
    print(f"[*] Creating output directory: {args.output}")
    os.makedirs(args.output)

# Define File Paths
TARGETS_FILE = os.path.join(args.output, "targets.txt")
DOMAINS_FILE = os.path.join(args.output, "found_domains.txt")
HTTPX_FILE = os.path.join(args.output, "httpx_results.json")

# Global Variables
q = queue.Queue()
subs_ssl = []
found_domains = []
lock = threading.Lock()

# ==========================================
# STEP 1: RESOLVE TARGETS
# ==========================================

def resolve_targets():
    print("[*] Resolving targets...")
    
    if args.cidr:
        # If CIDR, just write it to the targets file
        with open(TARGETS_FILE, 'w') as f:
            f.write(args.cidr)
        print(f"[+] Target set to CIDR: {args.cidr}")

    elif args.asn:
        # If ASN, check for asnmap and resolve
        if not shutil.which("asnmap"):
            print("[!] Error: 'asnmap' is not installed or not in PATH.")
            print("[!] Run: go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest")
            sys.exit(1)
        
        print(f"[*] resolving {args.asn} using asnmap...")
        try:
            # Run asnmap -> mapcidr logic
            # We assume mapcidr is not strictly necessary if asnmap returns CIDRs, 
            # but masscan handles CIDRs fine.
            cmd = ["asnmap", "-a", args.asn, "-silent"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            if not result.stdout.strip():
                print("[!] No CIDRs found for this ASN.")
                sys.exit(1)

            with open(TARGETS_FILE, 'w') as f:
                f.write(result.stdout)
            
            count = len(result.stdout.strip().split('\n'))
            print(f"[+] Resolved {args.asn} to {count} CIDRs.")
            
        except subprocess.CalledProcessError as e:
            print(f"[!] ASN resolution failed: {e}")
            sys.exit(1)

# ==========================================
# STEP 2: MASSCAN
# ==========================================

def run_masscan():
    print(f"[*] Starting Masscan on targets in {TARGETS_FILE}...")
    try:
        mas = masscan.PortScanner()
        # We use -iL to read the targets file created in Step 1
        # --rate 5000 as per your preference
        mas.scan(arguments=f'-iL {TARGETS_FILE} -p443 --rate 5000 --wait 0 --open')
        
        for host in mas.all_hosts:
            subs_ssl.append(host)
            
        print(f"[*] Masscan complete. Found {len(subs_ssl)} hosts with port 443.")
        
    except (ET.ParseError, masscan.masscan.NetworkConnectionError) as e:
        print(f'[!] Masscan Error: {e}')
        # If masscan fails (e.g., sudo required), we shouldn't continue
        if len(subs_ssl) == 0:
            sys.exit(1)

# ==========================================
# STEP 3: SSL EXTRACTION
# ==========================================

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
                # Deduplication logic
                if clean_cn not in found_domains:
                    found_domains.append(clean_cn)
                    print(f"[+] {ip} -> {clean_cn}")
            
    except (ssl.SSLError, socket.error, OpenSSL.crypto.Error, socket.timeout):
        pass
    except Exception:
        pass

def process_queue():
    while not q.empty():
        current_ip = q.get()
        process_cert_subs(current_ip)
        q.task_done()

# ==========================================
# MAIN EXECUTION FLOW
# ==========================================

if __name__ == "__main__":
    # 1. Resolve Targets
    resolve_targets()

    # 2. Run Masscan
    run_masscan()

    # 3. Queue Logic
    if len(subs_ssl) > 0:
        for i in subs_ssl:
            q.put(str(i).strip())
    else:
        print('[-] No live hosts found to extract certificates from. Exiting.')
        sys.exit(1)

    # 4. Threading
    print(f"[*] Extracting certificates using 50 threads...")
    threads = []
    for i in range(50):
        t = threading.Thread(target=process_queue)
        t.daemon = True 
        t.start()
        threads.append(t)
    q.join()

    # 5. Save & HTTPX
    if len(found_domains) > 0:
        print(f"\n[*] Saving {len(found_domains)} domains to {DOMAINS_FILE}...")
        
        with open(DOMAINS_FILE, 'w') as f:
            for domain in found_domains:
                f.write(f"{domain}\n")

        print("[*] Starting HTTPX...")
        httpx_cmd = [
            "httpx",
            "-l", DOMAINS_FILE,
            "-sc", "-title", "-tech-detect", "-jarm", "-location",
            "-random-agent",
            "-silent",
            "-json",
            "-o", HTTPX_FILE
        ]
        
        try:
            subprocess.run(httpx_cmd, check=True)
            print(f"[*] Done! Results saved to {args.output}/")
        except FileNotFoundError:
            print("[!] Error: 'httpx' not found in PATH.")
        except subprocess.CalledProcessError:
            print("[!] HTTPX encountered an error.")
    else:
        print("[-] No domains extracted.")
