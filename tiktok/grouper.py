import sys
from collections import defaultdict

targets = defaultdict(list)

try:
    with open("tiktok/masscan.grep", "r") as f:
        for line in f:
            if "Host:" in line and "Ports:" in line:
                parts = line.split()
                ip = parts[1]
                # Extract port (e.g., 80/open/tcp) -> 80
                try:
                    port_str = line.split("Ports: ")[1].split("/")[0]
                    targets[ip].append(port_str)
                except:
                    continue
except FileNotFoundError:
    sys.exit(0)

for ip, ports in targets.items():
    # Deduplicate ports just in case
    unique_ports = list(set(ports))
    print(f"{ip} -p {','.join(unique_ports)}")
