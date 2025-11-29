#!/bin/bash

RED="\e[31m"
RESET="\e[0m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }
success() { printf '\e[1;32m[SUCCESS]\e[0m %s\n' "$*"; }

if [ -z "$1" ]; then
    warn "Usage: $0 <domain> <output>"
    exit 1
fi

TARGET="$1"
OUTPUT="$2"
useragents_file="/home/bugdotexe/bbrecon/tools/wordlist/user-agents.txt"
UA=$(sort -R "$useragents_file" | head -n 1)

random_ip() {
    echo $((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256))
}

mkdir -p /tmp/$TARGET/ 2>/dev/null

COOKIE="PHPSESSID=30b1c93167db807b292773a6672dc827"
STEP1_FILE="/tmp/${TARGET}/whoxy-main.html"
STEP2_FILE="/tmp/${TARGET}/whoxy_company.html"

curl "https://www.whoxy.com/$TARGET" \
  -s \
  -H "User-Agent: $UA" \
  -H "Cookie: $COOKIE" \
  -o "$STEP1_FILE"

DOM_NAME=$(grep -oP "(?<=<span class='red'>)[^<]+" "$STEP1_FILE" | head -1)
SIMILAR_COUNT=$(grep -oP "keyword/[^\"]+\"[^>]+>\K[^<]+" "$STEP1_FILE" | head -1)

REG_NAME=$(grep -oP "<strong>Registrar:</strong>\s*<a[^>]+>\K[^<]+" "$STEP1_FILE" | head -1)
REG_COUNT=$(grep -oP "whois-database/registrar\.php\"[^>]+>\K[^<]+" "$STEP1_FILE" | head -1)

COMP_NAME=$(grep -oP "<strong>Company:</strong>\s*\K[^(]+" "$STEP1_FILE" | head -1 | sed 's/^\s*//;s/\s*$//')
COMP_LINK=$(grep -oP "href=\"(company/[0-9]+)\"" "$STEP1_FILE" | head -1 | cut -d'"' -f2)

[ -n "$DOM_NAME" ]  && success "Domain:    $DOM_NAME"
[ -n "$REG_NAME" ] && success "Registrar: $REG_NAME"
[ -n "$COMP_NAME" ] && success "Company:   $COMP_NAME"

echo "--------------------------------------------------"

if [ -z "$COMP_LINK" ]; then
    err "No Company information found from Whoxy(Privacy Redacted?)."
    exit 1
fi

SEARCH_TERM="$COMP_NAME"

if [[ -z "$SEARCH_TERM" ]]; then
   COMP_NAME=$TARGET
fi

notice " Reverse WHOIS lookup on whoxy.com for: $TARGET"
curl "https://www.whoxy.com/$COMP_LINK" \
  -s \
  -H "User-Agent: $UA" \
  -H "Cookie: $COOKIE" \
  -H "Referer: https://www.whoxy.com/$TARGET" \
  -o "$STEP2_FILE"

grep -oP "href=['\"]\.\./\K[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}" "$STEP2_FILE" \
  | grep -vE "\.(php|ico|css|js|png|jpg|svg)$" \
  | sort -u | anew -q ${OUTPUT}/reverse.whois

COMPANY_QUERY=$(echo "$COMP_NAME" | sed 's/ /+/g')
OUTPUT_FILE="/tmp/${TARGET}/viewdns_result.html"

COOKIE="PHPSESSID=bc25cvq3u11rbe1p09eg0p26e1"

notice "Reverse WHOIS lookup on ViewDNS.info for Company: $COMP_NAME"

curl "https://viewdns.info/reversewhois/?q=$COMPANY_QUERY" \
  -s \
  -H "accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" \
  -H "accept-language: en-US,en;q=0.8" \
  -H "cache-control: max-age=0" \
  -b "$COOKIE" \
  -H "priority: u=0, i" \
  -H "referer: https://viewdns.info/" \
  -H "sec-ch-ua: \"Chromium\";v=\"142\", \"Brave\";v=\"142\", \"Not_A Brand\";v=\"99\"" \
  -H "sec-ch-ua-mobile: ?0" \
  -H "sec-ch-ua-platform: \"Windows\"" \
  -H "sec-fetch-dest: document" \
  -H "sec-fetch-mode: navigate" \
  -H "sec-fetch-site: same-origin" \
  -H "sec-fetch-user: ?1" \
  -H "upgrade-insecure-requests: 1" \
  -H "user-agent: $UA" \
  -o "$OUTPUT_FILE"

grep -oP '(?<=dark:text-gray-100">)[^<]+\.[a-z]{2,}' "$OUTPUT_FILE" | sort -u | anew -q ${OUTPUT}/reverse.whois

COUNT=$(wc -l < ${OUTPUT}/reverse.whois | tr -d ' ')
success "Found $COUNT unique domains."

success "Saved reverse whois results to: ${OUTPUT}/reverse.whois"
rm -rf "/tmp/${TARGET}/" 2>/dev/null
