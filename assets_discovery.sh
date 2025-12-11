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
debug()   { printf '\e[1;36m[DEBUG]\e[0m %s\n' "$*"; }

DOMAIN=$1
OUTPUT=$2
LOG="$OUTPUT/.tmp/recon.log"
HAKTRAILS_COOKIE="$HOME/.cookie"
SUBDOMAIN_WORDLIST="/home/bugdotexe/bbrecon/tools/wordlist/allDNS.txt"

mkdir -p "$OUTPUT/.tmp"
PASSIVE_ENUM() {
    local DOMAIN=$1
    local OUTPUT=$2

    notice "Starting Passive Subdomain enumeration: $DOMAIN" 
    mkdir -p "$OUTPUT/PASSIVE"

    notice "Passive Subdomain Enumeration: haktrailsfree " 
    if [ -f "$HAKTRAILS_COOKIE" ]; then
        echo "$DOMAIN" | haktrailsfree -c "$HAKTRAILS_COOKIE" --silent | anew -q "$OUTPUT/PASSIVE/haktrails.sub"
        success "Haktrailsfree found $(wc -l < "$OUTPUT/PASSIVE/haktrails.sub") subdomains" 
        else
        err "No cookies provided $HOME/.cookie : https://securitytrails.com/list/apex_domain/krazeplanet.com?page=1"
        exit
    fi
    echo -e

    notice "Passive Subdomain Enumeration: bbot " 
    mkdir -p "$OUTPUT/bbot"
    bbot -t "$DOMAIN" -p subdomain-enum -o "$OUTPUT/bbot" -om subdomains >/dev/null
    find "$OUTPUT/bbot" -name "subdomains.txt" -exec cat {} + | anew -q "$OUTPUT/PASSIVE/bbot.sub"
    success "Bbot found $(wc -l < "$OUTPUT/PASSIVE/bbot.sub") subdomains" 
    echo -e

    notice "Passive Subdomain Enumeration: cert " 
    sed -ne 's/^\( *\)Subject:/\1/p;/X509v3 Subject Alternative Name/{
    N;s/^.*\n//;:a;s/^\( *\)\(.*\), /\1\2\n\1/;ta;p;q; }' < <(
    openssl x509 -noout -text -in <(
    openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "$DOMAIN:443" ) ) | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | anew -q "$OUTPUT/PASSIVE/cert.sub"
    success "Cert found $(wc -l < "$OUTPUT/PASSIVE/cert.sub") subdomains" 
    echo -e

    notice "Passive Subdomain Enumeration: crt.sh " 
    curl -s "https://crt.sh?q=$DOMAIN&output=json" | jq -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$' | sort -u | anew -q "$OUTPUT/PASSIVE/crtsh.sub"
    success "crt.sh found $(wc -l < "$OUTPUT/PASSIVE/crtsh.sub") subdomains" 
    echo -e

    notice "Passive Subdomain Enumeration: virustotal " 
    bash /home/bugdotexe/bbrecon/tools/vt.sh $DOMAIN "$OUTPUT/PASSIVE/virustotal.sub"
    curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=99e4922915b2a1c753dfd66e541d41df6a3522cb906b6c0d6ae7c1df6f529ae5&domain=$DOMAIN" | jq -r '.subdomains[]' | anew -q "$OUTPUT/PASSIVE/virustotal.sub"
    success "VirusTotal found $(wc -l < "$OUTPUT/PASSIVE/virustotal.sub") subdomains" 
    echo -e

    notice "Passive Subdomain Enumeration: web.archive " 
    curl -s "http://web.archive.org/cdx/search/cdx?url=*.${DOMAIN}/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' | anew -q "$OUTPUT/PASSIVE/webarchive.sub"
    success "Web.archive found $(wc -l < "$OUTPUT/PASSIVE/webarchive.sub") subdomains" 
    echo -e

    notice "Passive Subdomain Enumeration: subfinder " 
    subfinder -silent -all -recursive -d "$DOMAIN" | anew -q "$OUTPUT/PASSIVE/subfinder.sub"
    success "Subfinder found $(wc -l < "$OUTPUT/PASSIVE/subfinder.sub") subdomains" 
    echo -e

    notice "Passive Subdomain Enumeration: assetfinder " 
    assetfinder -subs-only "$DOMAIN" | anew -q "$OUTPUT/PASSIVE/assetfinder.sub"
    success "Assetfinder found $(wc -l < "$OUTPUT/PASSIVE/assetfinder.sub") subdomains" 
    echo -e

    notice "Passive Subdomain Enumeration: chaos " 
    chaos -silent -key 7e42cd92-b317-420b-8eac-dbd5eb1c5516 -d "$DOMAIN" | anew -q "$OUTPUT/PASSIVE/chaos.sub"
    success "Chaos found $(wc -l < "$OUTPUT/PASSIVE/chaos.sub") subdomains" 
    echo -e

    notice "Passive Subdomain Enumeration: shosubgo " 
    shosubgo -s $SHODAN_API_KEY -d "$DOMAIN" | anew -q "$OUTPUT/PASSIVE/shosubgo.sub"
    success "Shosubgo found $(wc -l < "$OUTPUT/PASSIVE/shosubgo.sub") subdomains" 
    echo -e

    notice "Passive Subdomain Enumeration: gitlab " 
    gitlab-subdomains -t $GITLAB_TOKEN -d "$DOMAIN" | anew -q "$OUTPUT/PASSIVE/gitlab.sub"
    success "Gitlab found $(wc -l < "$OUTPUT/PASSIVE/gitlab.sub") subdomains" 
    echo -e
    
    notice "Passive Subdomain Enumeration: github " 
    github-subdomains -t "$GITHUB_TOKEN" -d "$DOMAIN" -o "$OUTPUT/PASSIVE/github.sub" >/dev/null
    success "Github found $(wc -l < "$OUTPUT/PASSIVE/github.sub") subdomains" 
    echo -e

    notice "Passive Subdomain Enumeration: amass " 
    amass enum -passive -d "$DOMAIN" -timeout 12 -o "$OUTPUT/PASSIVE/amass.tmp" >/dev/null
    cat "$OUTPUT/PASSIVE/amass.tmp" 2>/dev/null | anew -q "$OUTPUT/PASSIVE/amass.sub" 
    success "Amass found $(wc -l < "$OUTPUT/PASSIVE/amass.sub") subdomains" 
    echo -e

    notice "Passive Subdomain Enumeration: findomain " 
    findomain -t "$DOMAIN" -q | anew -q "$OUTPUT/PASSIVE/findomain.sub"
    success "Findomain found $(wc -l < "$OUTPUT/PASSIVE/findomain.sub") subdomains" 
    echo -e

    notice "Gathering additional passive intelligence: ctfr" 
    ctfr -d "$DOMAIN" -o "$OUTPUT/PASSIVE/ctfr.sub" >/dev/null 2>&1
    cat "$OUTPUT/PASSIVE/ctfr.sub" 2>/dev/null | grep "*" | anew -q "$OUTPUT/wildcard.scopes" 
    cat "$OUTPUT/PASSIVE/ctfr.sub" | sed 's/^\*\.//' | sort -u -o "$OUTPUT/PASSIVE/ctfr.sub" >/dev/null 2>&1
    success "CTFR found $(wc -l < "$OUTPUT/PASSIVE/ctfr.sub") subdomains" 
    
    echo -e
    success "Passive Subdomain Enumeration completed for $DOMAIN" 
    cat "$OUTPUT"/PASSIVE/*.sub 2>/dev/null | sort -u | anew -q "$OUTPUT/ASSETS/all.passive.sub"
    local TOTAL_PASSIVE=$(wc -l < "$OUTPUT/ASSETS/all.passive.sub")
    success "Total Unique Passive Subdomains found: $TOTAL_PASSIVE" 
}

ACTIVE_ENUM() {
    local DOMAIN=$1
    local OUTPUT=$2

    notice "Starting Active Subdomain enumeration: $DOMAIN" 
    mkdir -p "$OUTPUT/ACTIVE"

    notice "Active Subdomain Enumeration: Alterx " 
    cat "$OUTPUT/ASSETS/all.passive.sub" | alterx -silent -en \
            -p "{{sub}}-{{word}}.{{suffix}}" \
            -p "{{word}}-{{sub}}.{{suffix}}" \
            -p "{{word}}{{sub}}.{{suffix}}" \
            -p "staging-{{root}}" \
            -p "stage-{{root}}" \
            -p "system-{{root}}" \
            -p "debug-{{root}}" \
            -p "log-{{root}}" \
            -p "internal-{{root}}" \
            -p "prod-{{root}}" \
            -p "alpha-{{root}}" \
            -p "agent-{{root}}" \
            -p "dev-{{root}}" \
            -p "test-{{root}}" \
            -p "uat-{{root}}" \
            -p "beta-{{root}}" \
            -p "api-{{root}}" \
            -p "admin-{{root}}" | \
            dnsx -silent -a -cname -retry 2 | awk '{print $1}' | anew -q "$OUTPUT/ACTIVE/alterx.sub"
    success "Alterx found $(wc -l < "$OUTPUT/ACTIVE/alterx.sub") subdomains" 
    echo -e

    notice "Active Subdomain Enumeration: Alterx with crt.sh wordlist " 
    curl -s "https://crt.sh/?q=%25.$DOMAIN&output=json" | \
    jq -r '.[].common_name' 2>/dev/null | \
    grep -E "$DOMAIN" | \
    sort -u | \
    alterx -silent -en \
        -p "{{sub}}-{{word}}.{{suffix}}" \
        -p "{{word}}-{{sub}}.{{suffix}}" \
        -p "system-{{root}}" \
        -p "stage-{{root}}" \
        -p "staging-{{root}}" \
        -p "log-{{root}}" \
        -p "debug-{{root}}" \
        -p "internal-{{root}}" \
        -p "prod-{{root}}" \
        -p "alpha-{{root}}" \
        -p "agent-{{root}}" \
        -p "dev-{{root}}" \
        -p "test-{{root}}" \
        -p "uat-{{root}}" \
        -p "beta-{{root}}" \
        -p "api-{{root}}" \
        -p "admin-{{root}}" | \
    dnsx -silent -a -cname -retry 2 | \
    awk '{print $1}' | anew -q "$OUTPUT/ACTIVE/alterx_crt.sub"
    success "Alterx with crt.sh wordlist found $(wc -l < "$OUTPUT/ACTIVE/alterx_crt.sub") subdomains" 
    
    notice "Active Subdomain Enumeration: Gobuster " 
    gobuster dns --domain "$DOMAIN" --wordlist "$SUBDOMAIN_WORDLIST" -q --nc --wildcard | awk '{print $1}' | anew -q "$OUTPUT/ACTIVE/gobuster.sub"
    success "Gobuster found $(wc -l < "$OUTPUT/ACTIVE/gobuster.sub") subdomains" 
    
    notice "Active Subdomain Enumeration: FFUF " 
    ffuf -c -r -u "https://$DOMAIN/" -s -H "Host: FUZZ.${DOMAIN}" -w "$SUBDOMAIN_WORDLIST" -o "$OUTPUT/ACTIVE/ffuf.json" -of json 
    cat "$OUTPUT/ACTIVE/ffuf.json" | jq -r '.results[].host' | anew -q "$OUTPUT/ACTIVE/ffuf.sub"
    success "FFUF found $(wc -l < "$OUTPUT/ACTIVE/ffuf.sub") subdomains" 
    echo -e

    notice "Active Subdomain Enumeration: Mksub " 
    mksub -d "$DOMAIN" -l 2 -w "$SUBDOMAIN_WORDLIST" -r "^[a-zA-Z0-9\.-_]+$" | dnsx -silent -a -cname -retry 2 | anew -q "$OUTPUT/ACTIVE/mksub.sub" 
    success "Mksub found $(wc -l < "$OUTPUT/ACTIVE/mksub.sub") subdomains" 
    echo -e

    notice "Active Subdomain Enumeration: dnsBruteforce " 
    altdns -i "$OUTPUT/ASSETS/all.passive.sub" -o "$OUTPUT/ACTIVE/altdns.txt" -w "$SUBDOMAIN_WORDLIST" >/dev/null 2>&1
    cat "$OUTPUT/ACTIVE/altdns.txt" | dnsx -silent -a -cname -retry 2 | anew -q "$OUTPUT/ACTIVE/dnsbruteforce.sub"
    success "dnsBruteforce found $(wc -l < "$OUTPUT/ACTIVE/dnsbruteforce.sub") subdomains" 
    echo -e

    success "Active Subdomain Enumeration completed for $DOMAIN" 
    cat "$OUTPUT"/ACTIVE/*.sub 2>/dev/null | sort -u | anew -q "$OUTPUT/ASSETS/all.active.sub"
    local TOTAL_ACTIVE=$(wc -l < "$OUTPUT/ASSETS/all.active.sub")
    success "Total Unique Active Subdomains found: $TOTAL_ACTIVE" 

    }

LIVE_ASSET_IDENTIFICATION() {
    local OUTPUT=$2
    notice "Starting Live Asset Identification" 
    cd $OUTPUT || exit
    notice "Identifying Live Subdomains using httpx " 
    cat "$OUTPUT/ASSETS/all.active.sub" "$OUTPUT/ASSETS/all.passive.sub" | sort -u | httpx -silent -random-agent -H "X-Forwarded-For: 127.0.0.1" -H "Referrer: 127.0.0.1" -H "X-Forward-For: 127.0.0.1" -H "X-Forwarded-Host: 127.0.0.1" -timeout 10 -status-code -content-length -title -tech-detect -cdn -server -method -follow-redirects -cname -asn -jarm -sr -srd "$OUTPUT" -o "$OUTPUT/LIVE/live.sub"
    success "Live Asset Identification completed for $DOMAIN" 
    local TOTAL_LIVE=$(wc -l < "$OUTPUT/LIVE/live.sub")
    success "Total Live Subdomains found: $TOTAL_LIVE"

    cat "$OUTPUT/LIVE/live.sub" | awk '{print $1}' | anew -q "$OUTPUT/LIVE/all.live.sub"
}

PASSIVE_ENUM "$DOMAIN" "$OUTPUT"
ACTIVE_ENUM "$DOMAIN" "$OUTPUT"
LIVE_ASSET_IDENTIFICATION "$DOMAIN" "$OUTPUT"
