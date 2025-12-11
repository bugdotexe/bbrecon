#!/bin/bash

# ==========================================
# GitHub OSINT & Reconnaissance Tool
# ==========================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

if ! command -v jq &> /dev/null; then
    echo -e "${RED}[!] Error: 'jq' is not installed. Please install it (apt install jq / brew install jq).${NC}"
    exit 1
fi

if ! command -v anew &> /dev/null; then
    anew() {
        local target_file=$1
        while read -r line; do
            if [ ! -f "$target_file" ] || ! grep -qFx "$line" "$target_file"; then
                echo "$line" >> "$target_file"
                echo "$line" 
            fi
        done
    }
fi

if [ $# -eq 0 ]; then
    echo -e "${YELLOW}Usage: $0 <domain> <output>${NC}"
    echo "Example: $0 fofa.info fofa"
    exit 1
fi

DOMAIN=$1
OUTPUT=$2
TOKEN="${GITHUB_TOKEN}"
RESULTS_DIR="$OUTPUT"
mkdir -p "$RESULTS_DIR/.tmp"

CHECKED_CANDIDATES_FILE="$RESULTS_DIR/.tmp/checked_hashes.tmp"
FOUND_LIST_FILE="$RESULTS_DIR/.tmp/github_users.2"
> "$CHECKED_CANDIDATES_FILE" 
> "$FOUND_LIST_FILE"        

if [ -z "$TOKEN" ]; then
    echo -e "${RED}[!] WARNING: No GITHUB_TOKEN detected.${NC}"
    echo -e "${YELLOW}    Usage: export GITHUB_TOKEN=your_token_here${NC}"
    sleep 2
fi

github_api() {
    local endpoint=$1
    local url="https://api.github.com/$endpoint"
    
    if [ -z "$TOKEN" ]; then
        curl -s -H "Accept: application/vnd.github.v3+json" "$url"
    else
        curl -s -H "Authorization: token $TOKEN" -H "Accept: application/vnd.github.v3+json" "$url"
    fi
}

search_github() {
    local type=$1
    local query=$2
    local encoded_query=$(echo "$query" | sed 's/ /%20/g')
    github_api "search/$type?q=$encoded_query&per_page=100"
}

generate_priority_permutations() {
    local domain=$1
    local base_name=$(echo "$domain" | cut -d. -f1)
    local tld=$(echo "$domain" | cut -d. -f2)
    local no_dots=$(echo "$domain" | tr -d '.')
    
    echo "$base_name"
    echo "$no_dots"
    
    echo "${base_name}-${tld}"
    echo "${base_name}-inc"
    echo "${base_name}-org"
    echo "${base_name}-tech"
    echo "${base_name}-labs"
    echo "${base_name}-corp"
    echo "${base_name}0x01"
    echo "${base_name}io"
    echo "${base_name}app"
    echo "${base_name}cloud"
    echo "${base_name}-Cash"
    echo "${base_name}-protocol"
    echo "${base_name}-dao"
    echo "${base_name}-pool"
    echo "${base_name}-network"
    echo "${base_name}-fi"
    echo "${base_name}Labs"
    echo "${base_name}Inc"
    echo "${base_name}HQ"
    echo "${base_name}Official"
    echo "${base_name}Security"
    echo "${base_name}-security"
    echo "${base_name}-dev"
    echo "${base_name}Dev"
    echo "${base_name}-team"
    echo "${base_name}Team"
    echo "${base_name}-studio"
    echo "${base_name}Studio"
    echo "${base_name}-solutions"
    echo "${base_name}Solutions"
    echo "${base_name}-services"
    echo "${base_name}Services"
    echo "${base_name}-foundation"
    echo "${base_name}Foundation"
    echo "${base_name}-project"
    echo "${base_name}Project"
    echo "${base_name}-community"
    echo "${base_name}Community"
    echo "${base_name}-group"
    echo "${base_name}Group"
    echo "${base_name}-ventures"
    echo "${base_name}Ventures"
    echo "${base_name}-capital"
    echo "${base_name}Capital"
    echo "${base_name}-partners"
    echo "${base_name}Partners"
    echo "${base_name}-global"
    echo "${base_name}Global"
    echo "${base_name}-intl"
    echo "${base_name}Intl"
    echo "${base_name}-international"
    echo "${base_name}International"
    echo "${base_name}-crypto"
    echo "${base_name}Crypto"
    echo "${base_name}-finance"
    echo "${base_name}Finance"
    echo "${base_name}-pay"
    echo "${base_name}Pay"
    echo "${base_name}-wallet"
    echo "${base_name}Wallet"
    echo "${base_name}-data"
    echo "${base_name}Data"
    echo "${base_name}-web"
    echo "${base_name}Web"
    echo "${base_name}-mobile"
    echo "${base_name}Mobile"
    echo "${base_name}-platform"
    echo "${base_name}Platform"
    echo "${base_name}-infrastructure"
    echo "${base_name}Infrastructure"
    echo "${base_name}-infra"
    echo "${base_name}Infra"    
}

generate_discovery_permutations() {
    local domain=$1
    local base_name=$(echo "$domain" | cut -d. -f1)
    
    local suffixes=(
        "group" "holdings" "ventures" "capital" "partners" "global" "intl" "international"
        "software" "systems" "sys" "data" "web" "mobile" "platform" "infra"
        "solutions" "services" "consulting" "studio" "design" "tools"
        "foundation" "project" "community" "oss" "open-source"
        "finance" "pay" "wallet" "crypto" "chain" "exchange"
    )

    for suffix in "${suffixes[@]}"; do
        echo "${base_name}-${suffix}"
        echo "${base_name}${suffix}"

    done
}


process_candidate_list() {
    local candidate_file=$1
    local NO_DOTS_NAME=$(echo "$DOMAIN" | tr -d '.')
    local BASE_NAME=$(echo "$DOMAIN" | cut -d. -f1)

    while read -r org_name; do
        [ -z "$org_name" ] && continue
        if grep -q "^$org_name$" "$CHECKED_CANDIDATES_FILE"; then continue; fi
    
        echo "$org_name" >> "$CHECKED_CANDIDATES_FILE" >/dev/null

        sleep 0.5 
        echo -ne "${YELLOW}[~] Checking: $org_name\r${NC}"

        org_result=$(github_api "users/$org_name")
        
        if [ "$(echo "$org_result" | jq -r '.message' 2>/dev/null)" == "Not Found" ]; then
            continue
        fi

        if [[ "$(echo "$org_result" | jq -r '.message' 2>/dev/null)" == *"API rate limit exceeded"* ]]; then
            echo -e "\n${RED}[!] API RATE LIMIT EXCEEDED. Stopping validation.${NC}"
            return 2
        fi

        blog_url=$(echo "$org_result" | jq -r '.blog // empty')
        account_type=$(echo "$org_result" | jq -r '.type // "Unknown"')
        is_verified=$(echo "$org_result" | jq -r '.is_verified // false')
        
        repo_check=$(search_github "repositories" "user:$org_name")
        repo_count=$(echo "$repo_check" | jq -r '.total_count // 0' 2>/dev/null)

        match_found=false

        if [[ "${org_name,,}" == "${BASE_NAME,,}" ]] || [[ "${org_name,,}" == "${NO_DOTS_NAME,,}" ]]; then
            if [ "$repo_count" -gt 0 ]; then
                echo -e "\n${GREEN}[+] Found: $org_name${NC}"
                match_found=true
            fi
        fi

        if [ "$match_found" = false ] && [ "$is_verified" == "true" ]; then
            echo -e "\n${GREEN}[+] Found: $org_name${NC}"
            match_found=true
        fi

        if [ "$match_found" = false ] && [[ "$blog_url" == *"$DOMAIN"* ]]; then
            if [[ "$org_name" == *"$BASE_NAME"* ]] || [[ "$account_type" == "Organization" ]]; then
                echo -e "\n${GREEN}[+] Found: $org_name${NC}"
                match_found=true
            fi
        fi
        
        if [ "$match_found" = true ]; then
            echo "$org_name" | anew "$FOUND_LIST_FILE" >/dev/null
            continue 
        fi

    done < "$candidate_file"
    return 0
}

generate_priority_permutations "$DOMAIN" > "$RESULTS_DIR/.tmp/phase1.candidates"
COUNT_P1=$(wc -l < "$RESULTS_DIR/.tmp/phase1.candidates")

process_candidate_list "$RESULTS_DIR/.tmp/phase1.candidates"
RESULT=$?

if [ $RESULT -eq 2 ]; then
    echo -e "\n${RED}[!] Scan aborted due to Rate Limiting.${NC}"
    exit 1
fi

> "$RESULTS_DIR/.tmp/phase2.candidates"

search_github "repositories" "$DOMAIN" | jq . > "$RESULTS_DIR/.tmp/repos_search.json"
jq -r '.items[]?.owner.login' "$RESULTS_DIR/.tmp/repos_search.json" 2>/dev/null \
    | awk 'length($0) <= 30' | grep -vE "(-s-random-fork|test-user|temp-)" \
    >> "$RESULTS_DIR/.tmp/phase2.candidates"

search_github "users" "$DOMAIN in:blog" | jq . > "$RESULTS_DIR/.tmp/blog_search.json"
jq -r '.items[]?.login' "$RESULTS_DIR/.tmp/blog_search.json" 2>/dev/null \
    | awk 'length($0) <= 30' | grep -vE "(-s-random-fork|test-user|temp-)" \
    >> "$RESULTS_DIR/.tmp/phase2.candidates"
echo ""
generate_discovery_permutations "$DOMAIN" >> "$RESULTS_DIR/.tmp/phase2.candidates"

sort -u "$RESULTS_DIR/.tmp/phase2.candidates" | grep -vFf "$CHECKED_CANDIDATES_FILE" | anew "$RESULTS_DIR/.tmp/phase2.final" >/dev/null

COUNT_P2=$(wc -l < "$RESULTS_DIR/.tmp/phase2.final")

process_candidate_list "$RESULTS_DIR/.tmp/phase2.final"

if [ -s "$FOUND_LIST_FILE" ]; then
    cat "$FOUND_LIST_FILE"
else
    echo -e "${RED}[-] No confirmed matches found.${NC}"
fi
