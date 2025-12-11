#!/bin/bash

RED="\e[31m"
RESET="\e[0m"
GREEN="\e[32m"

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }
success() { printf '\e[1;32m[SUCCESS]\e[0m %s\n' "$*"; }
debug()   { printf '\e[1;36m[DEBUG]\e[0m %s\n' "$*"; }

DOMAIN=$1
OUTPUT=$2

LIVE_ASSET_CRAWLING() {
    
    DOMAIN=$1
    OUTPUT=$2
    mkdir -p "$OUTPUT"/{CRAWLING,JS,LIVE}
    notice "Starting Asset Crawling for Live Subdomains: $DOMAIN"
    if [ ! -s "$OUTPUT/LIVE/all.live.sub" ]; then
        err "No live subdomains found to crawl."
        return 1
    fi
    
    notice "Crawling Live Subdomains using gau"
    cat "$OUTPUT/LIVE/all.live.sub" | gau --threads 10 --subs --blacklist png,jpg,jpeg,gif,svg,css,woff,woff2,ttf,eot,ico,mp4,mp3 | sort -u | anew -q "$OUTPUT/CRAWLING/gau.urls"
    success "Found $(wc -l < "$OUTPUT/CRAWLING/gau.urls") URLs using gau"

    notice "Crawling Live Subdomains using urlfinder"
    urlfinder -list "$OUTPUT/LIVE/all.live.sub" -threads 10 | sort -u | anew -q "$OUTPUT/CRAWLING/urlfinder.urls"
    success "Found $(wc -l < "$OUTPUT/CRAWLING/urlfinder.urls") URLs using urlfinder"

    notice "Crawling Live Subdomains using waymore"
    waymore -i "$OUTPUT/LIVE/all.live.sub" -mode U -oU "$OUTPUT/CRAWLING/waymore.urls" -c 5 >/dev/null 2>&1
    success "Found $(wc -l < "$OUTPUT/CRAWLING/waymore.urls") URLs using waymore"

    notice "Crawling Live Subdomains using katana"
    katana -silent -xhr -aff -kf -jsl -fx -td -d 3 -jc -list "$OUTPUT/LIVE/all.live.sub" -o "$OUTPUT/CRAWLING/katana.urls" >/dev/null 2>&1
    success "Found $(wc -l < "$OUTPUT/CRAWLING/katana.urls") URLs using katana"

    notice "Crawling Live Subdomains using gobuster"
    gospider --subs --include-subs --js --delay 2 -S "$OUTPUT/LIVE/all.live.sub" -o "$OUTPUT/CRAWLING/gobuster.tmp" >/dev/null 2>&1
    cat "$OUTPUT/CRAWLING/gobuster.tmp" 2>/dev/null | awk '$NF ~ /^https?:\/\// {print $NF}' | sort -u | anew -q "$OUTPUT/CRAWLING/gobuster.urls"
    success "Found $(wc -l < "$OUTPUT/CRAWLING/gobuster.urls") URLs using gospider"

    notice "Crawling Live Subdomains using hakrawler"
    cat "$OUTPUT/LIVE/all.live.sub" | hakrawler -insecure -u -d 2 -subs | sort -u | anew -q "$OUTPUT/CRAWLING/hakrawler.urls"
    success "Found $(wc -l < "$OUTPUT/CRAWLING/hakrawler.urls") URLs using hakrawler"

    success "Asset Crawling Completed for Live Subdomains"
    cat "$OUTPUT/CRAWLING/"*.urls | sort -u | uro | anew -q "$OUTPUT/CRAWLING/all.crawled.urls"
    success "Total Unique URLs found from Crawling: $(wc -l < "$OUTPUT/CRAWLING/all.crawled.urls")"

}

JS_EXTRACTOR() {
    notice "Starting JavaScript Extraction from Crawled URLs"
    cat "$OUTPUT/CRAWLING/all.crawled.urls" | grep -E "\.js($|\?)" | sort -u | anew -q "$OUTPUT/JS/js.urls"
    success "Total JavaScript Files found: $(wc -l < "$OUTPUT/JS/js.urls")"

    notice "Starting JavaScript Extraction using getJs"
    cat "$OUTPUT/LIVE/all.live.sub" | getJS | sort -u | anew -q "$OUTPUT/JS/getjs.urls"
    success "Total JavaScript Files found using getJs: $(wc -l < "$OUTPUT/JS/getjs.urls")"

    notice "Starting JavaScript Extraction using subJs"
    cat "$OUTPUT/LIVE/all.live.sub" | subJS | sort -u | anew -q "$OUTPUT/JS/subjs.urls"
    success "Total JavaScript Files found using subJs: $(wc -l < "$OUTPUT/JS/subjs.urls")"

    cat "$OUTPUT/JS/"*.urls | sort -u | anew -q "$OUTPUT/JS/all.js.urls"
    success "Total Unique JavaScript Files found: $(wc -l < "$OUTPUT/JS/all.js.urls")"
}

LIVE_ASSET_IDENTIFICATION() {
    local OUTPUT=$2
    notice "Starting Live Asset Identification" 
    cd $OUTPUT || exit
    notice "Identifying Live Subdomains using httpx " 
    cat "$OUTPUT/CRAWLING/all.crawled.urls" "$OUTPUT/JS/all.js.urls" | sort -u | httpx -silent -random-agent -H "X-Forwarded-For: 127.0.0.1" -H "Referrer: 127.0.0.1" -H "X-Forward-For: 127.0.0.1" -H "X-Forwarded-Host: 127.0.0.1" -timeout 10 -status-code -content-length -title -tech-detect -cdn -server -method -follow-redirects -cname -asn -jarm -sr -srd "$OUTPUT" -o "$OUTPUT/LIVE/httpx.urls"
    success "Live Asset Identification completed"
    notice "Findind Javascript sourcemap files"
    python3 /home/bugdotexe/bbrecon/tools/getSrc.py -d $OUTPUT -o "$OUTPUT/JS/jsFiles.txt" --download "$OUTPUT/JS/" --findmaps
    mkdir -p "$OUTPUT/JS/MAP" 
    notice "Downloading Javascript sourcemap files"
    for map in $(cat $OUTPUT/JS/jsFiles.sourcemaps.txt);do
    sourcemapper -url "$map" -insecure -output "$OUTPUT/JS/MAP" 
    done
    
}

LIVE_ASSET_CRAWLING "$DOMAIN" "$OUTPUT"
JS_EXTRACTOR "$DOMAIN" "$OUTPUT"
LIVE_ASSET_IDENTIFICATION "$DOMAIN" "$OUTPUT"
