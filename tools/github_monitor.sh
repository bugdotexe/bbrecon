#!/bin/bash

TARGETS_FILE="${1:-github.orgs}"

CONFIG_DIR="${HOME}/.github_monitor"
STATE_DIR="${CONFIG_DIR}/state"
LOG_FILE="${CONFIG_DIR}/monitor.log"
PROGRESS_FILE="${CONFIG_DIR}/progress.idx"

BATCH_SIZE=8      
BATCH_SLEEP=180  
LOOP_SLEEP=360   

IGNORED_DETECTORS="Infura|OpenWeather|Alchemy|Mapbox|GoogleMaps|SauceLabs|BrowserStack|TwitterConsumerkey|Rawg|Flickr|GitHubOauth2"

TELEGRAM_API_KEY="8001910878:AAHV7sLYtsKhMRTcxaTtN1OABhwPeuofmgI"
TELEGRAM_CHAT_ID="6729179510"

GITHUB_TOKENS=(
    ""
    ""
)

CURRENT_TOKEN_INDEX=0

mkdir -p "$STATE_DIR"
touch "$LOG_FILE"

if ! command -v trufflehog &> /dev/null; then
    echo "⚙️ Installing TruffleHog..."
    curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin 2>/dev/null || \
    (mkdir -p "$HOME/bin" && curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$HOME/bin" && export PATH="$HOME/bin:$PATH")
fi

log() { echo -e "\033[0;32m[$(date '+%T')]\033[0m $1" | tee -a "$LOG_FILE"; }
info() { echo -e "\033[0;34m[$(date '+%T')]\033[0m $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "\033[1;33m[$(date '+%T')]\033[0m $1" | tee -a "$LOG_FILE"; }

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

scan_org() {
    local target="$1"
    local token="$2"
    sleep $((RANDOM % 5))
    log "🚀 [Start] $target"
    local temp_results=$(mktemp)

    trufflehog github --only-verified --token="$token" \
      --issue-comments --pr-comments --gist-comments --include-members \
      --archive-max-depth=150 --org="$target" --json --concurrency=2 > "$temp_results"

    if [[ -s "$temp_results" ]]; then
        while IFS= read -r line; do
            local detector=$(echo "$line" | jq -r '.DetectorName')
            if [[ "$detector" =~ $IGNORED_DETECTORS ]]; then continue; fi
            
            local raw=$(echo "$line" | jq -r '.Raw')
            local repo=$(echo "$line" | jq -r '.SourceMetadata.Data.Github.repository')
            local link=$(echo "$line" | jq -r '.SourceMetadata.Data.Github.link')
            local fingerprint=$(echo "${repo}${detector}${raw}" | md5sum | cut -d' ' -f1)
            local state_file="${STATE_DIR}/${fingerprint}"

            if [[ ! -f "$state_file" ]]; then
                warn "🚨 Verified Leak: $detector in $repo"
                local msg="🚨 *VERIFIED LEAK*
📦 *Org:* \`$target\`
📂 *Repo:* \`$repo\`
🔥 *Type:* \`$detector\`
🔗 *Link:* [GitHub]($link)
🔑 *Key:* \`${raw:0:10}...\`"
                send_telegram "$msg"
                touch "$state_file"
            fi
        done < "$temp_results"
    fi
    rm "$temp_results"
    log "✅ [Finish] $target"
}


if [[ ! -f "$TARGETS_FILE" ]]; then
    echo "Error: File '$TARGETS_FILE' not found."
    exit 1
fi

send_telegram "🛡️ Sentinel Started."

while true; do
    mapfile -t targets < "$TARGETS_FILE"
    
    START_INDEX=0
    if [[ -f "$PROGRESS_FILE" ]]; then
        START_INDEX=$(cat "$PROGRESS_FILE")
        if [[ "$START_INDEX" -gt 0 ]]; then
            info "🔄 System recovered. Resuming from target #$START_INDEX..."
        fi
    fi

    count=0
    
    for i in "${!targets[@]}"; do
        
        if (( i < START_INDEX )); then
            continue
        fi

        target="${targets[$i]}"
        
        if [[ -n "$target" ]]; then
            current_token=$(get_token)
            scan_org "$target" "$current_token" &
            ((count++))
            
            if (( count % BATCH_SIZE == 0 )); then
                info "⏳ Batch of $BATCH_SIZE running. Waiting..."
                wait 
                
                echo "$((i + 1))" > "$PROGRESS_FILE"
                
                info "💾 Checkpoint saved (Index: $((i + 1))). Sleeping $BATCH_SLEEP..."
                sleep "$BATCH_SLEEP"
            fi
        fi
    done
    
    wait
    
    echo "0" > "$PROGRESS_FILE"
    log "🎉 Full list scanned. Sleeping 1 hour."
    sleep "$LOOP_SLEEP"
done
