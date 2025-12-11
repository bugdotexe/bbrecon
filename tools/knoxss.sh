#!/bin/bash

# =========================================================
#  KNOXNL Automator for bugdotexe
#  Focus: API Efficiency, WAF Evasion, and Clear Logging
# =========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' 

echo -e "${BLUE}"
echo "    __ __                     _   __   __"
echo "   / //_/__  ____  _  __     / | / /  / /"
echo "  / ,< / _ \/ __ \| |/_/____/  |/ /  / / "
echo " / /| / / / / /_/ />  </___/ /|  /  / /___"
echo "/_/ |/_/ /_/\____/_/|_|   /_/ |_/  /_____/"
echo -e "${NC}"
echo -e "${YELLOW}[*] Automator initiated for Bug Bounty Hunting...${NC}"


if [ -z "$1" ]; then
    echo -e "${RED}[!] Error: No input file provided.${NC}"
    echo -e "Usage: ./run_knoxnl.sh <urls_file.txt>"
    exit 1
fi

INPUT_FILE="$1"
KEY=$2
OUTPUT_FILE="knoxnl_results.txt"
TODO_FILE="${INPUT_FILE}.todo"

if [ ! -f "$INPUT_FILE" ]; then
    echo -e "${RED}[!] Error: File '$INPUT_FILE' not found.${NC}"
    exit 1
fi

echo -e "${BLUE}[+] Target List: ${INPUT_FILE}${NC}"
echo -e "${BLUE}[+] Output File: ${OUTPUT_FILE}${NC}"
echo -e "${YELLOW}[*] Configuration: 5 Threads | Skip Blocked (3) | Auto-Pause on API Limit${NC}"
echo "-------------------------------------------------------"

# =========================================================
# RUN COMMAND EXPLANATION
# -i  : Input file
# -o  : Output file for hits
# -s  : Success only (Cleaner terminal output)
# -p 5: 5 Parallel processes (Balance between speed and not killing the API)
# -pur: Pause Until Reset (CRITICAL: Waits if you hit the daily API cap instead of dying)
# -sb 3: Skip Blocked (If a domain gives 3x 403s, stop scanning it to save credits)
# -t 60: Timeout set to 60s (Don't hang forever on dead links)
# =========================================================

knoxnl -i "$INPUT_FILE" \
       -o "$OUTPUT_FILE" \
       -s \
       -p 5 \
       -pur \
       -sb 3 \
       -t 60 \
      -X BOTH \
      -A $KEY

echo "-------------------------------------------------------"
if [ -f "$OUTPUT_FILE" ] && [ -s "$OUTPUT_FILE" ]; then
    echo -e "${GREEN}[$$$] BOOM! Vulnerabilities found! Check ${OUTPUT_FILE}${NC}"
    cat "$OUTPUT_FILE"
else
    echo -e "${RED}[-] Scan complete. No confirmed XSS found this time.${NC}"
fi

if [ -f "$TODO_FILE" ]; then
    echo -e "${YELLOW}[!] Note: Not all URLs were scanned. Check ${TODO_FILE} to resume later.${NC}"
fi
