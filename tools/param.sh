#!/bin/bash

# --- Configuration ---
WORDLIST="/home/bugdotexe/bbrecon/tools/wordlist/params.txt"
TEMP_PARAMS=".param.tmp"
TEMP_ARJUN=".arjun.tmp"
TEMP_X8=".x8.tmp"

# RATE LIMIT SETTINGS
THREADS=25
DELAY=50

# --- Colors & Helpers ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

notice()  { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()    { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()     { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }
success() { printf '\e[1;32m[SUCCESS]\e[0m %s\n' "$*"; }
debug()   { printf '\e[1;36m[DEBUG]\e[0m %s\n' "$*"; }

usage() {
    debug "Usage: $0 -d https://target.com -o params.txt"
    echo -e "Examples:"
    echo -e "  $0 -d https://hackerone.com -o paramaters.txt"
    echo -e "  $0 -f live_subdomains.txt -o paramaters.txt"
    exit 1
}

# --- Argument Parsing ---
while getopts "d:f:o:" opt; do
  case $opt in
    d) TARGET_DOMAIN="$OPTARG" ;;
    f) TARGET_FILE="$OPTARG" ;;
    o) OUTPUT_FILE="$OPTARG" ;;
    *) usage ;;
  esac
done

if [[ -z "$OUTPUT_FILE" ]]; then
    err "You must specify an output file with -o"
    usage
fi

if [[ -z "$TARGET_DOMAIN" && -z "$TARGET_FILE" ]]; then
    err "You must specify either a domain (-d) or a file (-f)"
    usage
fi

# Cleanup temp files
rm -f "$TEMP_PARAMS" "$TEMP_ARJUN" "$TEMP_X8"

success "Starting Hybrid Parameter Discovery [Arjun + x8]"
success "Configuration: Threads=$THREADS | Delay=${DELAY}ms"

# --- Main Scan Function ---
scan_target() {
    local url=$1
    echo -e "${BLUE}[+] Scanning: $url${NC}"

    # 1. RUN ARJUN (Logic & HTML Parsing)
    # We use --stable because you had rate limit issues in your logs
    if command -v arjun &> /dev/null; then
        debug "Running Arjun..."
        arjun -u "$url" -oT "$TEMP_ARJUN" --stable -t 10 > /dev/null 2>&1
        
        # Format Arjun output to ensure it's saved nicely
        if [[ -s "$TEMP_ARJUN" ]]; then
            # Arjun often outputs just the query string or param list. 
            # We treat whatever is in the file as valid and append it.
            cat "$TEMP_ARJUN" >> "$TEMP_PARAMS"
            # Add a newline just in case
            echo "" >> "$TEMP_PARAMS"
        fi
        rm -f "$TEMP_ARJUN"
    else
        warn "Arjun not found, skipping."
    fi

    # 2. RUN X8 (Brute Force)
    if command -v x8 &> /dev/null; then
        debug "Running x8..."
        # -O url: Forces output to look like a URL
        x8 -u "$url" \
           -w "$WORDLIST" \
           -O url \
           -c "$THREADS" \
           -d "$DELAY" \
           --follow-redirects \
           --disable-colors \
           -o "$TEMP_X8" 
           
        if [[ -s "$TEMP_X8" ]]; then
           cat "$TEMP_X8" >> "$TEMP_PARAMS"
        fi
        rm -f "$TEMP_X8"
    else
        err "x8 not found! Skipping."
    fi
}

# --- Execution Loop ---
if [[ -n "$TARGET_DOMAIN" ]]; then
    scan_target "$TARGET_DOMAIN"
elif [[ -n "$TARGET_FILE" ]]; then
    if [[ ! -f "$TARGET_FILE" ]]; then
        err "File $TARGET_FILE not found."
        exit 1
    fi
    
    COUNT=$(wc -l < "$TARGET_FILE")
    debug "Loading $COUNT hosts from $TARGET_FILE"
    
    while IFS= read -r host || [ -n "$host" ]; do
        [[ -z "$host" ]] && continue
        scan_target "$host"
    done < "$TARGET_FILE"
fi

# --- Finalize ---
if [[ ! -s "$TEMP_PARAMS" ]]; then
    warn "No parameters found on any target."
    rm -f "$TEMP_PARAMS"
    exit 0
fi

# Sort and Unique to remove duplicates between tools
sort -u "$TEMP_PARAMS" > "$OUTPUT_FILE"
rm -f "$TEMP_PARAMS"

TOTAL_PARAMS=$(wc -l < "$OUTPUT_FILE")
success "Found $TOTAL_PARAMS URLs with hidden parameters."
debug "Saved to: $OUTPUT_FILE"
