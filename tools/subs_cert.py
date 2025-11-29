import sys
import ssl
import socket  # <--- This was missing
import threading
import masscan
import OpenSSL.crypto
import xml.etree.ElementTree as ET

# Handle Python 2/3 queue import
try:
    import queue
except ImportError:
    import Queue as queue

q = queue.Queue()
subs_ssl = []

# 1. Input Handling
try:
    ip_range = sys.argv[1]
except IndexError:
    print('Usage: python subs_cert.py <IPRANGE>')
    sys.exit(1)

# 2. Masscan Execution
print(f"[*] Scanning {ip_range} on port 443...")
try:
    mas = masscan.PortScanner()
    mas.scan(ip_range, ports='443')
    for host in mas.all_hosts:
        subs_ssl.append(host)
    print(f"[*] Found {len(subs_ssl)} hosts with port 443 open.")
except (ET.ParseError, masscan.masscan.NetworkConnectionError) as e:
    print(f'[!] Error scanning IP range: {e}')
    pass

# 3. Certificate Processing Function
def process_cert_subs(ip):
    try:
        # Create a context that doesn't verify the certificate (we just want to read it)
        # and allows older protocols if possible.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Fetch certificate
        cert_pem = ssl.get_server_certificate((str(ip), 443), timeout=5)
        
        # Load into pyOpenSSL
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_pem)
        
        # Extract Common Name (CN)
        subject = x509.get_subject()
        cn = subject.CN
        
        if cn:
            # Print format: IP -> Domain
            print(f"{ip} -> {cn}")
            
    except (ssl.SSLError, socket.error, OpenSSL.crypto.Error, socket.timeout):
        # Gracefully skip handshake failures, timeouts, and connection resets
        pass
    except Exception as e:
        # Catch generic errors so threads don't die
        pass

# 4. Queue Worker
def process_queue():
    while not q.empty():
        current_ip = q.get()
        process_cert_subs(current_ip)
        q.task_done()

# 5. Populate Queue
if len(subs_ssl) > 0:
    for i in subs_ssl:
        q.put(str(i).strip())
else:
    print('[-] No hosts found. Exiting.')
    sys.exit(1)

# 6. Start Threads
print(f"[*] Starting thread pool to extract certificates...")
for i in range(50):
    t = threading.Thread(target=process_queue)
    t.daemon = True 
    t.start()

q.join()
