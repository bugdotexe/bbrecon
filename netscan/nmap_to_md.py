import xml.etree.ElementTree as ET
import sys
import os

def parse_nmap_to_md(xml_file):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        return f"Error parsing XML: {e}"

    output_lines = []
    
    for host in root.findall('host'):
        # 1. Get IP and Hostname
        address = host.find("address[@addrtype='ipv4']")
        ip = address.get('addr') if address is not None else "Unknown IP"
        
        hostnames = host.find('hostnames')
        hostname = "N/A"
        if hostnames is not None:
            hn = hostnames.find('hostname')
            if hn is not None:
                hostname = hn.get('name')

        # 2. Header
        output_lines.append(f"# Target: {ip} ({hostname})")
        output_lines.append(f"**Scan Date:** {root.find('runstats/finished').get('timestr', 'N/A')}\n")

        # 3. Ports Table
        output_lines.append("## Open Ports")
        output_lines.append("| Port | Protocol | State | Service | Version |")
        output_lines.append("| :--- | :--- | :--- | :--- | :--- |")

        ports = host.find('ports')
        open_ports_found = False

        if ports is not None:
            for port in ports.findall('port'):
                state = port.find('state').get('state')
                if state == 'open':
                    open_ports_found = True
                    portid = port.get('portid')
                    protocol = port.get('protocol')
                    
                    service = port.find('service')
                    service_name = service.get('name') if service is not None else "unknown"
                    version = service.get('version') if service is not None else ""
                    product = service.get('product') if service is not None else ""
                    full_version = f"{product} {version}".strip()

                    output_lines.append(f"| {portid} | {protocol} | {state} | {service_name} | {full_version} |")

        if not open_ports_found:
            output_lines.append("| - | - | - | - | - |")
            output_lines.append("\n*No open ports found.*")

        output_lines.append("\n---")

    return "\n".join(output_lines)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 nmap_to_md.py <nmap_output.xml>")
        sys.exit(1)
    
    xml_path = sys.argv[1]
    print(parse_nmap_to_md(xml_path))
