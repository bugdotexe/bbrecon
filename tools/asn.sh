#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }
success() { printf '\e[1;32m[SUCCESS]\e[0m %s\n' "$*"; }
debug()   { printf '\e[1;36m[DEBUG]\e[0m %s\n' "$*"; }

TARGET=$1
OUTPUT=$2

if [ -z "$TARGET" ] || [ -z "$OUTPUT" ]; then
    err "Usage: ./net.sh <ASN_OR_FILE> <OUTPUT>"
    exit 1
fi

mkdir -p "$OUTPUT" 2>/dev/null

scan_asn() {
    local ASN=$1
    local TGT=$2
    
    notice "Scanning ASN: $ASN for target: $TGT" | notify -silent
    asnmap -a "$ASN" -silent | \
    mapcidr -silent -si -skip-base -skip-broadcast | anew -q "$OUTPUT/asn.ips"
}

if [ -f "$TARGET" ]; then
    notice "Input detected as File. Processing ASNs from file."
    while IFS= read -r line; do
        CURRENT_ASN=$(echo "$line" | xargs)
        if [[ ! -z "$CURRENT_ASN" ]]; then
            scan_asn "$CURRENT_ASN" "$OUTPUT"
        fi
    done < "$TARGET"
else
    notice "Input detected as ASN. Processing single ASN."
    scan_asn "$TARGET" "$OUTPUT"
fi

IP_COUNT=$(wc -l < "$OUTPUT/asn.ips")
success "ASN to IP resolution complete. Found $IP_COUNT unique IPs." | notify -silent
notice "Starting Port Scan on resolved IPs using RustScan."

PORTS_FILE="$OUTPUT/open.ports"
HTTPX_FILE="$OUTPUT/httpx.results"
 
cat "$OUTPUT/asn.ips" | xargs -I {} -P 1 sh -c '
    rustscan -a {} -r 1-65535 --ulimit 5000 -g --no-config 2>/dev/null | \
    grep "Open" | \
    awk -F"->" "{print \$2}" | \
    tr -d "[]" | \
    tr "," "\n" | \
    awk -v ip={} "{print ip\":\"\$1}" 
' | anew "$PORTS_FILE"

PORT_COUNT=$(wc -l < "$PORTS_FILE")
success "Port Scan Complete. Found $PORT_COUNT active ports" | notify -silent

success "Starting HTTPX Service Discovery..."

httpx -l "$PORTS_FILE" \
    -sc -title -tech-detect -location -server -jarm \
    -random-agent \
    -silent \
    -o "$HTTPX_FILE" \
    -json

success "Scan Finished! Saved Results: $HTTPX_FILE" | notify -silent
