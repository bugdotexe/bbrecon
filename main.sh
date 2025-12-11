#!/bin/bash

RED="\e[31m"
RESET="\e[0m"
GREEN="\e[32m"

notice() { printf '\e[1;34m[INFO]\e[0m %s\n' "$*"; }
warn()   { printf '\e[1;33m[WARN]\e[0m %s\n' "$*"; }
err()    { printf '\e[1;31m[ERROR]\e[0m %s\n' "$*"; }
success() { printf '\e[1;32m[SUCCESS]\e[0m %s\n' "$*"; }
debug()   { printf '\e[1;36m[DEBUG]\e[0m %s\n' "$*"; }

BANNER() {
    echo
echo -e "[+] World \e[31mOFF\e[0m,Terminal \e[32mON \e[0m"
echo -e " █████                             █████           █████
░░███                             ░░███           ░░███
 ░███████  █████ ████  ███████  ███████   ██████  ███████    ██████  █████ █████  ██████
 ░███░░███░░███ ░███  ███░░███ ███░░███  ███░░███░░░███░    ███░░███░░███ ░░███  ███░░███
 ░███ ░███ ░███ ░███ ░███ ░███░███ ░███ ░███ ░███  ░███    ░███████  ░░░█████░  ░███████
 ░███ ░███ ░███ ░███ ░███ ░███░███ ░███ ░███ ░███  ░███ ███░███░░░    ███░░░███ ░███░░░
 ████████  ░░████████░░███████░░████████░░██████   ░░█████ ░░██████  █████ █████░░██████
░░░░░░░░    ░░░░░░░░  ░░░░░███ ░░░░░░░░  ░░░░░░     ░░░░░   ░░░░░░  ░░░░░ ░░░░░  ░░░░░░
                      ███ ░███
                     ░░██████
                      ░░░░░░                                                             "
echo -e "[+] Make \e[31mCritical\e[0m great again"
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -d|--domain)
      DOMAIN=$2
      shift 2
      ;;
    -o|--org)
      ORG=$2
      shift 2
      ;;
    *)
    notice "Usage: sh main.sh -d replit.com -o replit"
      exit 1
      ;;
  esac
done

mkdir -p $ORG/$DOMAIN/{ASSETS,INTEL,OSINT,CRAWLING,JS,.tmp,LIVE}
echo "$DOMAIN" > "$ORG/wildcard.scopes"
OUTPUT="$ORG/$DOMAIN"
LOG="$ORG/$DOMAIN/.tmp/recon.log"
rm -rf $LOG
success "Starting Bug Bounty Reconnaissance: $DOMAIN" | tee -a $LOG

notice "Starting Intel Gathering: $DOMAIN" | tee -a $LOG
bash /home/bugdotexe/bbrecon/intel.sh $ORG/$DOMAIN | tee -a $LOG
success "Intel Gathering Completed: $DOMAIN" | tee -a $LOG


notice "Starting OSINT Gathering: $DOMAIN" | tee -a $LOG
bash /home/bugdotexe/bbrecon/osint.sh $ORG $ORG | tee -a $LOG
success "OSINT Gathering Completed: $DOMAIN" | tee -a $LOG

notice "Starting Subdomain Enumeration: $DOMAIN" | tee -a $LOG
bash /home/bugdotexe/bbrecon/assets_discovery.sh $DOMAIN "$ORG/$DOMAIN" | tee -a $LOG
success "Subdomain Enumeration Completed: $DOMAIN" | tee -a $LOG

notice "Starting Web Crawling: $DOMAIN" | tee -a $LOG
bash /home/bugdotexe/bbrecon/crawling.sh $DOMAIN "$ORG/$DOMAIN" | tee -a $LOG
success "Web Crawling Completed: $DOMAIN" | tee -a $LOG
