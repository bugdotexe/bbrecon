#!/bin/bash

# =========================================================
#  URL Sanitizer for KNOXSS (Advanced)
#  - Removes static assets
#  - Deduplicates parameters (id=1 & id=2 becomes one entry)
# =========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$#" -ne 2 ]; then
    echo -e "${RED}[!] Usage: ./prep_urls.sh <input_raw.txt> <output_clean.txt>${NC}"
    exit 1
fi

INPUT=$1
OUTPUT=$2

# Check if qsreplace is installed
if ! command -v qsreplace &> /dev/null; then
    echo -e "${RED}[!] Error: 'qsreplace' is not installed.${NC}"
    echo -e "${YELLOW}    Install it with: go install github.com/tomnomnom/qsreplace@latest${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Cleaning and Deduplicating Parameters in $INPUT...${NC}"

# THE LOGIC EXPLAINED:
# 1. grep "="       : Only keep lines with parameters.
# 2. grep -vE       : Remove static extensions.
# 3. qsreplace      : Replaces ALL parameter values with "bugdotexe".
#                     Ex: id=123 becomes id=bugdotexe
#                     Ex: id=456 becomes id=bugdotexe
# 4. sort -u        : Now that they look identical, this removes the duplicate.
# 5. grep "bugdotexe": Safety check to ensure we only output the lines we modified/verified.

cat "$INPUT" \
| grep "=" \
| grep -vE "\.(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js|xml)$" \
| qsreplace "bugdotexe" \
| sort -u \
| grep "bugdotexe" > "$OUTPUT"

# Calculate stats
ORIGINAL_COUNT=$(wc -l < "$INPUT")
FINAL_COUNT=$(wc -l < "$OUTPUT")
REMOVED=$((ORIGINAL_COUNT - FINAL_COUNT))

echo -e "${GREEN}[+] Done! Saved to $OUTPUT${NC}"
echo -e "    Original lines: $ORIGINAL_COUNT"
echo -e "    Unique Params : $FINAL_COUNT"
echo -e "    ${RED}Duplicates/Junk removed : $REMOVED${NC}"
