#!/usr/bin/env bash

HUNTER_API_KEY="eecaf22699bf4895331d3ef88ed58a1b04e89877"
GITHUB_TOKEN=$GITHUB_TOKEN

DOMAIN=$1
ORG=$2

if [[ -z "$DOMAIN" || -z "$ORG" ]]; then
    echo "Usage: $0 <domain> <org_name>"
    echo "Example: $0 example.com mycompany"
    exit 1
fi

OUTPUT="${ORG}"
mkdir -p "$OUTPUT"

RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
CYAN=$(tput setaf 6)
PURPLE=$(tput setaf 5)
ORANGE=$(tput setaf 214 2>/dev/null || echo "$YELLOW")
NC=$(tput sgr0)

random_ip() {
    echo $((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256))
}

make_api_request() {
    local endpoint="$1"
    local form_field="$2"
    local domain="$3"
    local rand_ip=$(random_ip)

    curl -s --location --request POST "$endpoint" \
        --header "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) Safari/604.1" \
        --header "Accept: application/json" \
        --header "X-Forwarded-For: $rand_ip" \
        --header "X-Real-IP: $rand_ip" \
        --form "${form_field}=${domain}" \
        --compressed \
        --connect-timeout 15 \
        --max-time 30
}

collect_emails() {
    echo -e "${YELLOW}[*] Searching emails for $DOMAIN...${NC}"
    local tmp_emails="$OUTPUT/emails.tmp"
    response=$(make_api_request "https://api.ful.io/email-search-website" "domain_url" "$DOMAIN")

    results=$(echo "$response" | jq -c '(.results_found // [])[]?')

    while IFS= read -r result; do
        email=$(echo "$result" | jq -r '.Email')
        purified=$(echo ${email} | sed -E 's/u[0-9a-fA-F]{4}//g' | grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')

        if [[ -n "$purified" ]]; then
            echo "$purified" | anew "$tmp_emails" >/dev/null
            echo -e "${CYAN}[Ful.io] ${purified}${NC}"
        fi
    done <<< "$results"

    if [[ -z "$HUNTER_API_KEY" ]]; then
        echo -e "${RED}[!] HUNTER_API_KEY not set. Skipping Hunter.io.${NC}"
    else
        curl -s "https://api.hunter.io/v2/domain-search?domain=${DOMAIN}&api_key=${HUNTER_API_KEY}" |

            jq -r '(.data.emails // [])[].value' |

            sed -E 's/u[0-9a-fA-F]{4}//g' |
            grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' |
            anew "$tmp_emails" |
            while IFS= read -r email; do
                echo -e "${CYAN}[Hunter.io] ${email}${NC}"
            done
    fi
}

find_github_profiles() {
    echo -e "${YELLOW}[*] Searching GitHub for profiles based on emails...${NC}"
    local tmp_emails="$OUTPUT/emails.tmp"
    mkdir -p "$OUTPUT/.tmp"
    local github_users_file="$OUTPUT/.tmp/github_users.1"
    if [[ ! -f "$tmp_emails" ]]; then
        echo -e "${RED}[!] Email list ($tmp_emails) not found. Run collect_emails first.${NC}"
        return 1
    fi

    if [[ -z "$GITHUB_TOKEN" ]]; then
        echo -e "${RED}[!] GITHUB_TOKEN environment variable is not set.${NC}"
        echo -e "${RED}[!] Please set it to avoid rate limiting. Skipping GitHub search.${NC}"
        return 1
    fi

    > "$github_users_file"

    while IFS= read -r email; do
        echo -e "${PURPLE}[GitHub] Searching for: $email${NC}"

        response=$(curl -s -G "https://api.github.com/search/users" \
                        -H "Accept: application/vnd.github.v3+json" \
                        -H "Authorization: token $GITHUB_TOKEN" \
                        --data-urlencode "q=${email}")

        username=$(echo "$response" | jq -r '.items[0].login // empty')

        if [[ -n "$username" ]]; then
            echo -e "${GREEN}[+] Found: $email -> $username${NC}"
            echo "$username" | anew -q "$github_users_file"
        fi
        sleep 1
    done < "$tmp_emails"

}

main() {
    collect_emails
    find_github_profiles
}

main
