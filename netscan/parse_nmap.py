import xml.etree.ElementTree as ET
import sys

# Loop through all XML files provided as arguments
for filename in sys.argv[1:]:
    try:
        tree = ET.parse(filename)
        root = tree.getroot()
        for host in root.findall('host'):
            # Get the IPv4 address
            address = host.find("address[@addrtype='ipv4']")
            if address is None:
                continue
            ip = address.get('addr')

            # Iterate through all ports
            for port in host.findall(".//port"):
                state = port.find("state")
                # Only grab open ports
                if state is not None and state.get("state") == "open":
                    portid = port.get("portid")
                    print(f"{ip}:{portid}")
    except Exception:
        # Skip files that can't be parsed
        pass
