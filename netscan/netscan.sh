#!/bin/bash

RED="\e[31m"
RESET="\e[0m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"

notice()  { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()    { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()     { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }
success() { printf '\e[1;32m[SUCCESS]\e[0m %s\n' "$*"; }
debug()   { printf '\e[1;36m[DEBUG]\e[0m %s\n' "$*"; }

function usage() {
    echo -e "${YELLOW}Usage: ./$0 [FLAGS]${RESET}"
    echo -e "Flags:"
    echo -e "  -asn  <AS1234>    Scan a single ASN"
    echo -e "  -cidr <IP/CIDR>   Scan a single IP or CIDR"
    echo -e "  -l    <file>      File containing list of CIDRs, IPs, or ASNs"
    echo -e "  -o    <output_dir> Specify output directory (default: ./output)"
    echo -e "  -h                Show this help message"
    exit 1
}

BASE_DIR="./output"
INPUT_CIDRS=""
INPUT_ASNS=""

if [[ $# -eq 0 ]]; then
    usage
fi

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -asn)
            if [ -n "$2" ]; then
                INPUT_ASNS+="$2 "
                shift
            else
                err "-asn requires an argument (e.g., AS1234)"
                exit 1
            fi
            ;;        
        -o)
            if [ -n "$2" ]; then
                BASE_DIR="$2"
                shift
            else
                err "-o requires an argument (output directory)"
                exit 1
            fi
            ;;
        -cidr) 
            if [ -n "$2" ]; then
                INPUT_CIDRS+="$2"$'\n'
                shift
            else
                err "-cidr requires an argument (CIDR or IP)"
                exit 1
            fi
            ;;
        -l|--list)
            if [ -f "$2" ]; then
                while IFS= read -r line || [[ -n "$line" ]]; do
                    [[ -z "$line" || "$line" =~ ^# ]] && continue
                    
                    if [[ "$line" =~ ^AS[0-9]+ ]]; then
                        INPUT_ASNS+="$line "
                    else
                        INPUT_CIDRS+="$line"$'\n'
                    fi
                done < "$2"
                shift
            else
                err "File not found: $2"
                exit 1
            fi
            ;;
        -h|--help)
            usage
            ;;
        *)
            err "Unknown parameter: $1"
            usage
            ;;
    esac
    shift
done

TARGETS_FILE="$BASE_DIR/initial.targets"
LIVE_HOSTS="$BASE_DIR/live.host"
WEB_HOSTS="$BASE_DIR/web.host"

if [ ! -d "$BASE_DIR" ]; then
    notice "Creating directory: $BASE_DIR"
    mkdir -p "$BASE_DIR"
fi

mkdir -p "$BASE_DIR/reports"
mkdir -p "$BASE_DIR/nmap"
mkdir -p "$BASE_DIR/nuclei"

touch "$TARGETS_FILE"

if [ -n "$INPUT_CIDRS" ]; then
    echo "$INPUT_CIDRS" | sed '/^$/d' | anew -q "$TARGETS_FILE"
fi

for asn in $INPUT_ASNS; do
    notice "Mapping ASN: $asn" 
    if command -v asnmap &> /dev/null; then
        asnmap -a "$asn" -silent | anew -q "$TARGETS_FILE"
    else
        err "asnmap not found! Skipping ASN resolution."
    fi
done

if [ ! -s "$TARGETS_FILE" ]; then
    err "No targets gathered. Exiting."
    exit 1
fi

COUNT_TARGETS=$(wc -l < "$TARGETS_FILE")
success "Total targets loaded: $COUNT_TARGETS"
debug "Output Directory: $BASE_DIR"

notice "Detecting Live Hosts: $TARGETS_FILE"

notice "Performing PTR lookups to filter live hosts."
mapcidr -silent -si -skip-base -skip-broadcast -cl "$TARGETS_FILE" | dnsx -ptr -resp-only -silent | anew "$LIVE_HOSTS"

notice "Performing ICMP Ping Sweep to find live hosts."
nmap -sn -iL "$TARGETS_FILE" -oG - | awk '/Up$/{print $2}' | anew "$LIVE_HOSTS"

notice "Performing SSL certificate checks to filter live hosts."

if [ -f "/home/bugdotexe/bbrecon/netscan/certsex.py" ]; then
    python3 /home/bugdotexe/bbrecon/netscan/certsex.py -f "$TARGETS_FILE" -o "$LIVE_HOSTS"
else
    warn "certsex.py not found, skipping SSL extraction."
fi

LIVE_COUNT=$(wc -l < "$LIVE_HOSTS")
success "Found ${LIVE_COUNT} live hosts."

if [ "$LIVE_COUNT" -eq 0 ]; then
    err "No live hosts found. Exiting."
    exit 1
fi

cat ${LIVE_HOSTS} | httpx -silent -random-agent -H "X-Forwarded-For: 127.0.0.1" -H "Referrer: 127.0.0.1" -H "X-Forward-For: 127.0.0.1" -H "X-Forwarded-Host: 127.0.0.1" -timeout 10 -status-code -content-length -title -tech-detect -cdn -server -method -follow-redirects -cname -asn -jarm -sr -srd "$BASE_DIR" -o "$BASE_DIR/httpx.probe"

notice "Scanning Ports & Generating Reports"

if [ ! -f "/home/bugdotexe/bbrecon/netscan/nmap_to_md.py" ]; then
    err "nmap_to_md file not found."
    exit 1
fi

cat "$LIVE_HOSTS" | xargs -P 10 -I {} sh -c '
    IP="{}"
    BASE="'$BASE_DIR'"
    XML_OUT="$BASE/nmap/scan_$IP.xml"
    MD_OUT="$BASE/reports/$IP.md"
    
    printf "\e[1;36m[DEBUG]\e[0m Scanning Ports: %s\n" "$IP"
    nmap -sV --open --top-ports 1000 --version-intensity 0 -Pn -oX "$XML_OUT" "$IP" > /dev/null 2>&1
    python3 /home/bugdotexe/bbrecon/netscan/nmap_to_md.py "$XML_OUT" > "$MD_OUT"
    
    if grep -q "http" "$XML_OUT"; then
        echo "$IP" >> "'$WEB_HOSTS'.tmp.$IP"
    fi
'
cat "$WEB_HOSTS".tmp.* 2>/dev/null | sort -u > "$WEB_HOSTS"
rm "$WEB_HOSTS".tmp.* 2>/dev/null

success "Port scanning and report generation completed."

notice "Scanning Web Services with Nuclei"

if [ -s "$WEB_HOSTS" ]; then
    COUNT=$(wc -l < "$WEB_HOSTS")
    notice "Found ${COUNT} web services to scan."
    
    # Run Nuclei
    nuclei -l "$WEB_HOSTS" \
           -s critical,high,medium,low \
           -o "$BASE_DIR/nuclei/nuclei_summary.txt" \
           -silent
    
    success "Nuclei scan completed."

    SUMMARY_FILE="$BASE_DIR/nuclei/nuclei_summary.txt"

    if [ ! -s "$SUMMARY_FILE" ]; then
        warn "Nuclei summary file is empty. No vulnerabilities found or write error."
    else
        debug "Parsing Nuclei results from: $SUMMARY_FILE"
        
        while read -r ip; do
            # 1. Clean the IP (remove whitespace/newlines)
            ip=$(echo "$ip" | tr -d '\r' | xargs)
            
            # Skip empty lines
            [ -z "$ip" ] && continue

            TMP_FILE="$BASE_DIR/nuclei/tmp_$ip.txt"
            REPORT_FILE="$BASE_DIR/reports/$ip.md"

            # 2. Grep using Fixed String (-F) to handle dots correctly
            # We grep for the IP followed by a colon OR the end of the line/space to match ports
            grep -F "$ip" "$SUMMARY_FILE" > "$TMP_FILE"
            
            if [ -s "$TMP_FILE" ]; then
                FINDINGS_COUNT=$(wc -l < "$TMP_FILE")
                debug "Updating Report for $ip: Found $FINDINGS_COUNT Nuclei findings."
                
                # Check if report exists, if not, create header
                if [ ! -f "$REPORT_FILE" ]; then
                    echo "# Report for $ip" > "$REPORT_FILE"
                fi

                echo -e "\n## Vulnerabilities (Nuclei)" >> "$REPORT_FILE"
                echo '```text' >> "$REPORT_FILE"
                cat "$TMP_FILE" >> "$REPORT_FILE"
                echo '```' >> "$REPORT_FILE"
            fi
            rm "$TMP_FILE" 2>/dev/null
        done < "$WEB_HOSTS"
    fi
else
    warn "No web services found to scan with Nuclei."
fi

success "Scanning Completed. Reports saved to $BASE_DIR/reports"
