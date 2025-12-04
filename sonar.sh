#!/bin/bash
# Usage : ./sonar_fix.sh <path_to_downloaded_file.json.gz> <output_file>
# Example: ./sonar_fix.sh 2025-11-29-fdns_cname.json.gz takeovers.txt

set -u

# 1. Validation
if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: ./sonar_fix.sh <input_file.gz> <output_file>"
    exit 1
fi

INPUT_FILE="$1"
OUTPUT_FILE="$2"

if [ ! -f "$INPUT_FILE" ]; then
    echo "[!] Input file not found. Please download it manually first."
    exit 1
fi

# 2. Fingerprints (Updated & Expanded)
declare -a prints=(
  "\.s3-website" "\.s3.amazonaws.com" "\.herokuapp.com" "\.herokudns.com"
  "\.wordpress.com" "\.pantheonsite.io" "domains.tumblr.com" "\.zendesk.com"
  "\.github.io" "\.global.fastly.net" "\.ghost.io" "\.myshopify.com"
  "\.surge.sh" "\.bitbucket.io" "\.azurewebsites.net" "\.cloudapp.net"
  "\.trafficmanager.net" "\.blob.core.windows.net" "\.shop.lightspeed.com"
  "\.teamwork.com" "\.helpjuice.com" "\.helpscoutdocs.com" "\.intercom.help"
  "\.wishpond.com" "\.aftership.com" "\.ideas.aha.io" "\.createsend.com"
  "\.gr8.com" "\.simplebooklet.com" "\.mykajabi.com" "\.thinkific.com"
  "\.teachable.com" "\.bigcartel.com" "\.vendecommerce.com" "\.brightcovegallery.com"
  "\.gallery.video" "\.readme.io" "\.jetbrains.com" "\.mendix.net"
  "\.bcvp0rtal.com" "\.acquia-test.co" "\.proposify.biz" "\.activehosted.com"
  "\.smartjobboard.com"
)

# Join array with | for Regex
REGEX=$(IFS="|"; echo "${prints[*]}")

# 3. Processing Engine (Streamed)
echo "[*] Starting processing..."
echo "[i] Input: $INPUT_FILE"
echo "[i] Output: $OUTPUT_FILE"

# Detect Pigz for speed
DECOMPRESSOR="gzip -dc"
if command -v pigz &> /dev/null; then
    echo "[+] Using pigz for acceleration."
    DECOMPRESSOR="pigz -dc"
fi

start_time=$(date +%s)

# THE PIPELINE
# 1. Decompress
# 2. Grep for 'cname' AND the fingerprint (filters 99% of junk immediately)
# 3. Clean JSON
# 4. Remove "Recursive" records (where the subdomain contains the fingerprint)
#    Example: Avoids 'shop.myshopify.com -> myshopify.com' (Not a takeover)
# 5. Extract just the subdomain (column 1)
# 6. Sort Unique

$DECOMPRESSOR "$INPUT_FILE" \
    | grep -E "type\":\"cname\".*($REGEX)" \
    | sed -E 's/.*"name":"([^"]+)".*"value":"([^"]+)".*/\1 \2/' \
    | awk -v regex="$REGEX" '$1 !~ regex { print $0 }' \
    | sort -u > "$OUTPUT_FILE"

end_time=$(date +%s)
echo "[+] Done in $((end_time - start_time)) seconds."
echo "[+] Results saved to $OUTPUT_FILE"
