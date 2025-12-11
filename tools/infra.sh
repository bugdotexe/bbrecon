#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: ./origin.sh <DOMAIN> <OUTPUT>"
    exit 1
fi

OUT=$2
OUTPUT="$OUT/.tmp"

mkdir -p "$OUTPUT" 2>/dev/null

useragents_file="/home/bugdotexe/bbrecon/tools/wordlist/user-agents.txt"
if [ -f "$useragents_file" ]; then
    UA=$(sort -R "$useragents_file" | head -n 1)
else
    UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
fi

name=$(echo $1 | tr . _ )
random_ip() {
    echo $((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256)).$((RANDOM % 256))
}

CDN_RANGES=(
    "173.245.48.0/20" "103.21.244.0/22" "103.22.200.0/22" "103.31.4.0/22" "141.101.64.0/18"
    "108.162.192.0/18" "190.93.240.0/20" "188.114.96.0/20" "197.234.240.0/22" "198.41.128.0/17"
    "162.158.0.0/15" "104.16.0.0/12" "172.64.0.0/13" "131.0.72.0/22" "23.0.0.0/12"
    "23.32.0.0/11" "23.64.0.0/14" "23.72.0.0/13" "104.64.0.0/10" "184.24.0.0/13"
    "184.50.0.0/15" "2.16.0.0/13" "23.235.32.0/20" "43.249.72.0/22" "103.244.50.0/24"
    "103.245.222.0/23" "103.245.224.0/24" "104.156.80.0/20" "151.101.0.0/16" "157.52.64.0/18"
    "167.82.0.0/17" "172.111.64.0/18" "185.31.16.0/22" "199.27.72.0/21" "199.232.0.0/16"
    "13.32.0.0/15" "13.35.0.0/16" "13.224.0.0/14" "13.249.0.0/16" "18.64.0.0/14"
    "52.46.0.0/18" "52.84.0.0/15" "52.222.128.0/17" "54.182.0.0/16" "54.192.0.0/16"
    "54.230.0.0/16" "54.239.128.0/18" "99.84.0.0/16" "130.176.0.0/16" "143.204.0.0/16"
    "204.246.164.0/22" "205.251.192.0/19" "199.83.128.0/21" "198.143.32.0/19" "149.126.72.0/21"
    "103.28.248.0/22" "185.11.124.0/22" "45.60.0.0/16" "192.124.249.0/24" "185.93.228.0/22"
    "66.248.200.0/22" "159.203.144.0/22" "195.78.66.0/23" "85.153.138.0/24" "161.117.0.0/17" 
    "185.175.196.0/22" "62.233.128.0/17" "94.154.117.0/24" "216.198.79.0/24" "5.181.161.0/24"
    "42.61.0.0/16" "172.252.108.0/24" "181.176.242.0/24" "217.65.3.0/24" "159.60.128.0/20"
    "167.172.176.0/20" "66.235.200.0/24" "165.232.112.0/20" 
)
printf "%s\n" "${CDN_RANGES[@]}" > $OUTPUT/cdn_filters_cidr.txt

CDN_FILTERS="Telecom|BroadBand|Voyager|Internet|Superonline|Internet|Hetzner|JSC|NTT|RackForest|Cloud|Kft|Singapore|Kazteleport|Initiative|Transports|Antagonist|VAIMO|iNET|InMotion|eBay|Bharti|Airtel|Bodis|Parking|Bigcommerce|Web-hosting.com|Twitter|FranTech Solutions|F5|WPEngine|Cloudflare|AWS|Alicloud|SendGrid|Twilio|Akamai|ALIBABA|Amazon|Google|Microsoft|Azure|Fastly|Imperva|Incapsula|Sucuri|Vercel|Netlify|Heroku|Fly\.io|Render|StackPath|KeyCDN|Bunny|Edgio|Limelight|Edgecast|CacheFly|Arvan|CDNetworks|Zenlayer|DDoS|Qrator|Reblaze|Prolexic|SiteLock|Section\.io|Zscaler|Cisco|OpenDNS|GoDaddy|Namecheap|Bluehost|HostGator|Shopify|Squarespace|Wix|Automattic|Kinsta|WP Engine|Pantheon|CDN77|G-Core|Dosarrest|Sentinel|Alibaba|Tencent|Baidu|Huawei|Oracle|IBM|RIPE|APNIC|LACNIC|AFRINIC|University|College|School|Hosting|Solutions|Services|Telekom|Netia|Home|Consumer|Cable"
ISP_TRIGGERS="Bharti|Airtel|Comcast|Verizon|Vodafone|Deutsche Telekom|Orange|Telefonica|Liberty Global|Charter|AT&T|CenturyLink|Reliance|Jio|Tata|China Telecom|China Unicom|NTT|SoftBank|KDDI|SK Telecom|KT|British Telecommunications|Virgin Media"
ASN_FILTERS="AS9891|AS63956|AS47583|AS396362|AS327782|AS153656|AS46844|AS24951|AS13649|AS51167|AS203053|AS398485|AS31477|AS701|AS59642|AS400940|AS140227|AS135905|AS37963|AS16509|AS51852|AS135905|AS37582|AS4766|AS45910|AS26347|AS24309|AS52030|AS56048|AS133119|AS23724|AS4837|AS16625|AS8796|AS55720|AS63473|AS133119|AS27647|AS63949|AS19871|AS32244|AS27357|AS23470|AS14061|AS202053|AS201446|AS54113|AS29873|AS20940|AS2914|AS62214|AS56030|AS34984|AS2497|AS24940|AS51162|AS64050|AS152194|AS210579|AS133398|AS20940|AS152194|AS209242|AS8560|AS36351|AS19679|AS48854|AS142403|AS58955|AS401696|AS134149|AS46606|AS62610"

target=$1
temp_file="${OUTPUT}/candidates_tagged.txt"
map_file="${OUTPUT}/ip_source_map.txt"
host_map="${OUTPUT}/shodan_hostnames.txt"
ips_file="${OUTPUT}/ips_only.txt"

> $temp_file
> $host_map

echo -e "\033[1;34m[*] Gathering Intel for: $target...\033[0m"


echo -ne "    > SecurityTrails... "
if [ ! -z "$SECURITYTRAILS_API_KEY" ]; then
    st_res=$(curl -s -A "$UA" "https://api.securitytrails.com/v1/history/$target/dns/a" -H "APIKEY: $SECURITYTRAILS_API_KEY")
    if echo "$st_res" | grep -q "exceeded"; then
        echo -e "\033[1;31mQUOTA EXCEEDED\033[0m"
    elif echo "$st_res" | grep -q "message"; then
        echo -e "\033[1;31mAPI ERROR\033[0m"
    else
        ips=$(echo "$st_res" | jq -r '.records[]?.values[]?.ip' 2>/dev/null)
        count=$(echo "$ips" | grep -v "^$" | wc -l)
        if [ "$count" -gt 0 ]; then 
            echo -e "\033[1;32mFOUND $count IPs\033[0m"
            echo "$ips" | grep -v "^$" | sed 's/$/|SecurityTrails/' >> $temp_file
        else 
            echo -e "\033[1;33m0 Results\033[0m"
        fi
    fi
else
    echo -e "\033[1;33mSKIPPED (No Key)\033[0m"
fi

echo -ne "    > Urlscan... "
urlscan_res=$(curl -s -A "$UA" "https://urlscan.io/api/v1/search/?q=domain:$target&size=1000")
ips=$(echo "$urlscan_res" | jq -r '.results[]?.page?.ip' 2>/dev/null)
count=$(echo "$ips" | grep -v "^$" | wc -l)
if [ "$count" -gt 0 ]; then 
    echo -e "\033[1;32mFOUND $count IPs\033[0m"
    echo "$ips" | grep -v "^$" | sed 's/$/|Urlscan/' >> $temp_file
else 
    echo -e "\033[1;33m0 Results\033[0m"
fi

echo -ne "    > Shodan... "

shodan_res=$(curl -s "https://api.shodan.io/dns/domain/$target?key=$SHODAN_API_KEY")
if echo "$shodan_res" | grep -q "error"; then
    echo -e "\033[1;31mAPI ERROR\033[0m"
else
    echo "$shodan_res" | jq -r '.data[] | select(.type=="A") | "\(.value) \(.subdomain).'$target'"' 2>/dev/null | grep -v "null" >> $host_map
    echo "$shodan_res" | jq -r --arg d "$target" '.data[] | if .subdomain == "" then $d else .subdomain + "." + $d end' | sort -u | anew -q "$OUTPUT/shodan_$name.subs"
    echo "$shodan_res" | jq -r --arg d "$target" '.data[] | select(.type=="CNAME") | 
    (if .subdomain == "" then $d else .subdomain + "." + $d end) + " -> " + .value' \
    | grep -E --color=always "s3|amazonaws|cloudfront|herokuapp|github|azure|bitbucket|fastly|shop|myshopify|sendgrid|ghost|cargo|helpjuice|helprace|intercom|jetbrains|kinsta|launchrock|mashery|pantheon|readme|statuspage|surge|tumblr|wordpress|unbounce|elb.amazonaws" | anew -q "$OUTPUT/shodan_$name.cname" 

    ips=$(echo "$shodan_res" | jq -r '.data[] | select(.type=="A") | .value' 2>/dev/null)
    count=$(echo "$ips" | grep -v "^$" | wc -l)
    if [ "$count" -gt 0 ]; then 
        echo -e "\033[1;32mFOUND $count IPs\033[0m"
        echo "$ips" | grep -v "^$" | sed 's/$/|Shodan/' >> $temp_file
    else 
        echo -e "\033[1;33m0 Results\033[0m"
    fi
fi

echo -ne "    > VirusTotal... "
vt_res=$(curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=$VT_API_KEY&domain=$target")
if echo "$vt_res" | grep -q "response_code.:0"; then
    echo -e "\033[1;33mNOT FOUND\033[0m"
else
    ips=$(echo "$vt_res" | jq -r '.resolutions[]? | .ip_address' 2>/dev/null)
    count=$(echo "$ips" | grep -v "^$" | wc -l)
    if [ "$count" -gt 0 ]; then 
        echo -e "\033[1;32mFOUND $count IPs\033[0m"
        echo "$ips" | grep -v "^$" | sed 's/$/|VirusTotal/' >> $temp_file
    else 
        echo -e "\033[1;33m0 Results\033[0m"
    fi
fi

sort -u $temp_file | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | grep -v "127.0.0.1" | \
awk -F'|' '{sources[$1] = sources[$1] ? sources[$1] "," $2 : $2} END {for (ip in sources) print ip "|" sources[ip]}' > $map_file

cut -d'|' -f1 $map_file > $ips_file
total=$(wc -l < $ips_file)

echo -e "\033[1;30m    > Total Unique IPs: $total. Starting Turbo Analysis...\033[0m\n"

if [ "$total" -eq 0 ]; then exit 0; fi

declare -A IP_SOURCES
while IFS="|" read -r ip src; do IP_SOURCES["$ip"]="$src"; done < $map_file

split -l 100 $ips_file $OUTPUT/ip_chunk_

for chunk in $OUTPUT/ip_chunk_*; do
    if [ ! -f "$chunk" ]; then continue; fi

    jq -R '{query: .}' $chunk | jq -s . > $OUTPUT/chunk_payload.json
    curl -s -A "$UA" -X POST "http://ip-api.com/batch?fields=query,org,isp,as,status" -d @$OUTPUT/chunk_payload.json > $OUTPUT/chunk_results.json
    
    cat $OUTPUT/chunk_results.json | jq -c '.[]' | while read -r item; do
        ip=$(echo "$item" | jq -r '.query')
        org=$(echo "$item" | jq -r '.org // .isp')
        as=$(echo "$item" | jq -r '.as')
        sources="${IP_SOURCES[$ip]}"
        
        if [ -z "$org" ] || [ "$org" == "null" ]; then org="Unknown"; fi
        if echo "$org" | grep -iqE "$CDN_FILTERS"; then continue; fi

        if python3 -c "import ipaddress, sys; [sys.exit(0) for line in open('$OUTPUT/cdn_filters_cidr.txt') if ipaddress.ip_address('$ip') in ipaddress.ip_network(line.strip())]; sys.exit(1)"; then
             continue
        fi

        cidr="N/A"
        
        if echo "$org" | grep -iqE "$ISP_TRIGGERS" || [ "$org" == "Unknown" ]; then
              sleep 1.5 
              bgp_data=$(curl -s -A "$UA" --max-time 4 "https://api.bgpview.io/ip/$ip" -H "X-Forwarded-For: $random_ip")
              
              if echo "$bgp_data" | grep -q "status"; then
                  new_org=$(echo "$bgp_data" | jq -r '(.data.prefixes[0].asn.name // .data.prefixes[0].asn.description) // empty')
                  new_as=$(echo "$bgp_data" | jq -r '(.data.prefixes[0].asn.asn | tostring) // empty')
                  new_cidr=$(echo "$bgp_data" | jq -r '.data.prefixes[0].prefix // empty')
                  
                  if [ ! -z "$new_org" ]; then org="$new_org"; fi
                  if [ ! -z "$new_as" ]; then as="AS$new_as"; fi
                  if [ ! -z "$new_cidr" ]; then cidr="$new_cidr"; fi
              fi
        fi

        if echo "$org" | grep -iqE "$CDN_FILTERS"; then continue; fi
        if echo "$as" | grep -iqE "$ASN_FILTERS"; then continue; fi

        if [ "$cidr" == "N/A" ]; then
              sleep 1 
              bgp_data=$(curl -s -A "$UA" --max-time 3 "https://api.bgpview.io/ip/$ip")
              if echo "$bgp_data" | grep -q "status"; then
                 cidr=$(echo "$bgp_data" | jq -r '.data.prefixes[0].prefix // "N/A"')
              fi
        fi
        
        host_info="N/A"
        chk_host=$(grep "^$ip " $host_map | head -n 1 | awk '{print $2}')
        if [ ! -z "$chk_host" ]; then host_info="$chk_host"; fi

        echo -e "\033[1;32m[+] POTENTIAL ORIGIN:\033[0m"
        echo -e "    IP:   \033[1;31m$ip\033[0m"
        echo -e "    HOST: \033[1;35m$host_info\033[0m"
        echo -e "    CIDR: $cidr"
        echo -e "    ORG:  $org"
        echo -e "    ASN:  $as"
        echo -e "    SRC:  \033[1;36m$sources\033[0m"
        echo "---------------------------------------------"

       echo "IP: $ip | HOST: $host_info | CIDR: $cidr | ASN: $as | ORG: $org | SRC: [$sources]" | anew -q "$OUTPUT/Infra.intel"
    done
done

mv $ips_file "$OUTPUT/$target.ips"
echo -e "\033[1;32m[+] Scanning Finished : Cleaning battlefield\033[0m"
rm $temp_file $ips_file $map_file $host_map $OUTPUT/chunk_results.json $OUTPUT/chunk_payload.json $OUTPUT/ip_chunk_* $OUTPUT/cdn_filters_cidr.txt 2>/dev/null
