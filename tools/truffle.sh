#!/bin/bash

TARGETS_FILE="$1"
OUTPUT="$2"

github_dorks="/home/bugdotexe/bbrecon/tools/wordlist/github.dorks"
github_pats="/home/bugdotexe/bbrecon/.config/GITHUB.tokens"
LOG_FILE="/tmp/trufflehog_scan.log"
STATE_DIR="/tmp/found_leaks"

mkdir -p "$STATE_DIR"

IGNORED_DETECTORS="Infura|OpenWeather|Alchemy|Mapbox|GoogleMaps|SauceLabs|BrowserStack|TwitterConsumerkey|Rawg|Flickr|GitHubOauth2"
TELEGRAM_API_KEY="8001910878:AAHV7sLYtsKhMRTcxaTtN1OABhwPeuofmgI"
TELEGRAM_CHAT_ID="6729179510"

GITHUB_TOKENS=(
    "$GITHUB_TOKEN"
)

CURRENT_TOKEN_INDEX=0

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date '+%T')]${NC} $1" | tee -a "$LOG_FILE"; }
info() { echo -e "${BLUE}[$(date '+%T')]${NC} $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[$(date '+%T')]${NC} $1" | tee -a "$LOG_FILE"; }
err() { echo -e "${RED}[$(date '+%T')]${NC} $1" | tee -a "$LOG_FILE"; }

if ! command -v jq &> /dev/null; then
    err "Error: 'jq' is not installed."
    exit 1
fi

if ! command -v gh &> /dev/null; then
    err "Error: 'gh' cli is not installed."
    exit 1
fi

if ! command -v trufflehog &> /dev/null; then
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null
fi

if [[ ! -f "$TARGETS_FILE" ]]; then
    err "Error: File '$TARGETS_FILE' not found."
    exit 1
fi

get_token() {
    local token="${GITHUB_TOKENS[$CURRENT_TOKEN_INDEX]}"
    CURRENT_TOKEN_INDEX=$(( (CURRENT_TOKEN_INDEX + 1) % ${#GITHUB_TOKENS[@]} ))
    echo "$token"
}

send_telegram() {
    local msg="$1"
    local payload=$(jq -n --arg cid "$TELEGRAM_CHAT_ID" --arg txt "$msg" \
        '{chat_id: $cid, text: $txt, parse_mode: "Markdown", disable_web_page_preview: true}')

    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_API_KEY}/sendMessage" \
        -H "Content-Type: application/json" -d "$payload" > /dev/null
}

process_results() {
    local result_file="$1"
    local target_name="$2"

    if [[ -s "$result_file" ]]; then
        while IFS= read -r line; do
            local detector=$(echo "$line" | jq -r '.DetectorName')

            if [[ "$detector" =~ $IGNORED_DETECTORS ]]; then
                continue
            fi

            local raw=$(echo "$line" | jq -r '.Raw')
            local repo=$(echo "$line" | jq -r '.SourceMetadata.Data.Github.repository // .SourceMetadata.Data.Git.repository // "Unknown Repo"')
            local link=$(echo "$line" | jq -r '.SourceMetadata.Data.Github.link // .SourceMetadata.Data.Git.file // "Unknown Link"')

            local fingerprint=$(echo "${repo}${detector}${raw}" | md5sum | cut -d' ' -f1)
            local state_file="${STATE_DIR}/${fingerprint}"

            if [[ ! -f "$state_file" ]]; then
                warn "🚨 Verified Leak: $detector in $repo"

                local msg="🚨 *VERIFIED LEAK*
📦 *Target:* \`$target_name\`
📂 *Repo:* \`$repo\`
🔥 *Type:* \`$detector\`
🔗 *Link:* $link
🔑 *Key:* \`${raw:0:20}...\`"

                send_telegram "$msg"
                echo "$msg" | anew -q "OUTPUT/Github.secrets"
                touch "$state_file"
            fi
        done < "$result_file"
    fi
}

scan_target() {
    local target="$1"
    local token="$2"
    local temp_results=$(mktemp)

    export GITHUB_TOKEN="$token"

    local type_response=$(curl -s -H "Authorization: Bearer $token" "https://api.github.com/users/$target")
    local type=$(echo "$type_response" | jq -r '.type')

    if [[ "$type" == "Organization" ]]; then
        info "Scanning Leaked secrets Github org: $target"
        send_telegram "Scanning Leaked secrets Github org: $target"
        
        trufflehog github --only-verified --token="$token" \
          --issue-comments --pr-comments --gist-comments --include-members \
          --archive-max-depth=50 --org="$target" --json --concurrency=2 > "$temp_results"
        bash /home/bugdotexe/bbrecon/depende_audit/scan.sh -o $target
        
        process_results "$temp_results" "$target"
        info " Github Dorking started: $target"
            gitdorks_go -gd "${github_dorks}" -nws 20 -target "org:$target" -tf "${github_pats}" -ew 3 | anew $OUTPUT/github_dork

    elif [[ "$type" == "User" ]]; then
        info "Scanning Leaked secrets Github user: $target"
        send_telegram "Scanning Leaked secrets Github user: $target"
        
        gh repo list "$target" --limit 1000 --json name,isFork,isArchived,url | \
        jq -r '.[] | [.name, .isFork, .isArchived, .url] | @tsv' | while IFS=$'\t' read -r name isFork isArchived url; do
            
            info "  👉 Scanning: $url"
            
            trufflehog git "$url" --json --results=verified >> "$temp_results"
            bash /home/bugdotexe/bbrecon/depende_audit/scan.sh -u $target
            process_results "$temp_results" "$target"
            > "$temp_results"
            info " Github Dorking started: $target"
            gitdorks_go -gd "${github_dorks}" -nws 20 -target "user:$target" -tf "${github_pats}" -ew 3 | anew $OUTPUT/github_dork
        done
    else
        err "❌ Unknown type for '$target': $type"
    fi

    rm "$temp_results"
    log "✅ [Finish] $target"
}

send_telegram "🛡️ Github Leaked Scanner started :File: $TARGETS_FILE"

mapfile -t targets < "$TARGETS_FILE"

for target in "${targets[@]}"; do
    if [[ -n "$target" ]]; then
        current_token=$(get_token)
        scan_target "$target" "$current_token"
    fi
done
