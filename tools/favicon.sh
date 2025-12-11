#!/bin/bash

if ! command -v jq &> /dev/null; then
    echo "Error: 'jq' is not installed."
    exit 1
fi

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }
success() { printf '\e[1;32m[SUCCESS]\e[0m %s\n' "$*"; }
debug()   { printf '\e[1;36m[DEBUG]\e[0m %s\n' "$*"; }

if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

DOMAIN=$1
useragents_file="/home/bugdotexe/bbrecon/tools/wordlist/user-agents.txt"
USER_AGENT=$(sort -R "$useragents_file" | head -n 1)


if [[ ! $DOMAIN =~ ^http ]]; then URL="https://$DOMAIN"; else URL=$DOMAIN; DOMAIN=$(echo "$URL" | awk -F/ '{print $3}'); fi

notice "Resolving favicon for: $DOMAIN"

HTML=$(curl -s -L -k "$URL" -A "$USER_AGENT")
ICON_PATH=$(echo "$HTML" | grep -oP '<link[^>]+rel=["'\'']?(shortcut )?icon["'\'']?[^>]+href=["'\'']?\K[^"'\'' >]+' | head -n 1)

if [ -z "$ICON_PATH" ]; then
    FULL_ICON_URL="https://$DOMAIN/favicon.ico"
else
    if [[ "$ICON_PATH" =~ ^http ]]; then FULL_ICON_URL="$ICON_PATH"
    elif [[ "$ICON_PATH" =~ ^// ]]; then FULL_ICON_URL="https:$ICON_PATH"
    elif [[ "$ICON_PATH" =~ ^/ ]]; then FULL_ICON_URL="https://$DOMAIN$ICON_PATH"
    else FULL_ICON_URL="https://$DOMAIN/$ICON_PATH"
    fi
fi

curl -s -G "https://favicon-hash.kmsec.uk/api/" --data-urlencode "url=$FULL_ICON_URL" | jq -r '
  "--------------------------------",
  "Favicon URL: \(.req_location)",
  "MD5:         \(.md5)",
  "MMH3:        \(.favicon_hash)",
  "--------------------------------",
  "Shodan Dork: https://www.shodan.io/search?query=http.favicon.hash:\(.favicon_hash)",
  "Censys Dork: https://search.censys.io/search/getting-started?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=services.http.response.favicons.md5_hash%3A\(.md5)"
' >/dev/null
