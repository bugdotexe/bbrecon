#!/bin/bash

# --- COLORS ---
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
RESET="\e[0m"
BOLD="\e[1m"

notice()  { printf "${BLUE}[INFO]${RESET} %s\n" "$*"; }
success() { printf "${GREEN}[OK]${RESET} %s\n" "$*"; }
warn()    { printf "${YELLOW}[INSTALLING]${RESET} %s\n" "$*"; }
err()     { printf "${RED}[ERROR]${RESET} %s\n" "$*"; }

# --- CONFIGURATION ---
# Matches your specific script path
WORDLIST_DIR="/home/bugdotexe/findsomeluck/recon/wordlists"
WORDLIST_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
ALTDNS_WORDS="https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt"

# Export paths immediately
export GOPATH=$HOME/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin:$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

echo -e "${BOLD}--- PATIENT PREDATOR: FULL SETUP v2 ---${RESET}"

# --- 1. SYSTEM DEPENDENCIES ---
notice "Step 1: Checking System Essentials..."
# Added libssl-dev for openssl/ctfr and libffi-dev for python builds
DEPS="git curl wget unzip jq build-essential libpcap-dev libssl-dev libffi-dev python3-full python3-pip golang-go ruby-full openssl"
MISSING_DEPS=""

for dep in $DEPS; do
    if ! dpkg -s "$dep" >/dev/null 2>&1; then
        MISSING_DEPS="$MISSING_DEPS $dep"
    fi
done

if [ -n "$MISSING_DEPS" ]; then
    warn "Installing missing system packages..."
    sudo apt update -y
    sudo DEBIAN_FRONTEND=noninteractive apt install -y $MISSING_DEPS
else
    success "System dependencies OK."
fi

# --- 2. PYTHON PIPX ---
notice "Step 2: Checking Pipx..."
if ! command_exists pipx; then
    warn "Installing Pipx..."
    python3 -m pip install --user pipx --break-system-packages 2>/dev/null || python3 -m pip install --user pipx
    python3 -m pipx ensurepath --force
    export PATH=$PATH:$HOME/.local/bin
fi

# --- 3. GO TOOLS ---
notice "Step 3: Checking Go Tools..."

declare -A GO_TOOLS=(
    [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [assetfinder]="github.com/tomnomnom/assetfinder@latest"
    [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    [gobuster]="github.com/OJ/gobuster/v3@latest"
    [ffuf]="github.com/ffuf/ffuf/v2@latest"
    [amass]="github.com/owasp-amass/amass/v3/cmd/amass@latest"
    [gau]="github.com/lc/gau/v2/cmd/gau@latest"
    [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
    [hakrawler]="github.com/hakluke/hakrawler@latest"
    [gospider]="github.com/jaeles-project/gospider@latest"
    [haktrailsfree]="github.com/rix4uni/haktrailsfree@latest"
    [chaos]="github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    [shosubgo]="github.com/incogbyte/shosubgo@latest"
    [unfurl]="github.com/tomnomnom/unfurl@latest"
    [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    [github-subdomains]="github.com/gwen001/github-subdomains@latest"
    [gitlab-subdomains]="github.com/gwen001/gitlab-subdomains@latest"
    [mksub]="github.com/trickest/mksub@latest"
    [webanalyze]="github.com/rverton/webanalyze/cmd/webanalyze@latest"
    [getJS]="github.com/003random/getJS@latest"
    [subjs]="github.com/lc/subjs@latest"
    [anew]="github.com/tomnomnom/anew@latest"
    [gf]="github.com/tomnomnom/gf@latest"
    [waybackurls]="github.com/tomnomnom/waybackurls@latest"
)

for tool in "${!GO_TOOLS[@]}"; do
    if ! command_exists "$tool"; then
        warn "Installing $tool..."
        go install -v "${GO_TOOLS[$tool]}"
    else
        success "$tool is ready."
    fi
done

# --- 4. PYTHON TOOLS ---
notice "Step 4: Checking Python Tools..."
# Added py-altdns here
PIP_TOOLS="waymore arjun bbot uro dirsearch py-altdns"

for tool in $PIP_TOOLS; do
    # Logic for py-altdns which installs as 'altdns' command
    CHECK_CMD=$tool
    if [ "$tool" == "py-altdns" ]; then CHECK_CMD="altdns"; fi

    if ! command_exists "$CHECK_CMD"; then
        warn "Installing $tool..."
        pipx install "$tool" --include-deps
    else
        success "$CHECK_CMD is ready."
    fi
done

# --- 5. MANUAL BINARIES / GIT CLONES ---
notice "Step 5: Checking Manual Tools..."

# Findomain
if ! command_exists findomain; then
    warn "Installing Findomain..."
    wget -q https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
    unzip -o findomain-linux.zip
    chmod +x findomain
    mv findomain /usr/local/bin/ 2>/dev/null || sudo mv findomain /usr/local/bin/
    rm findomain-linux.zip
fi

# WhatWeb
if ! command_exists whatweb; then
    warn "Installing WhatWeb..."
    sudo apt install -y whatweb 2>/dev/null || gem install whatweb
fi

# CTFR (New Requirement)
if ! command_exists ctfr; then
    warn "Installing CTFR..."
    mkdir -p $HOME/tools
    if [ ! -d "$HOME/tools/ctfr" ]; then
        git clone https://github.com/UnaPibaGeek/ctfr.git $HOME/tools/ctfr
    fi
    # Install deps
    pip3 install -r $HOME/tools/ctfr/requirements.txt --break-system-packages 2>/dev/null || pip3 install -r $HOME/tools/ctfr/requirements.txt
    # Create symlink
    echo '#!/bin/bash' > ctfr_launcher
    echo "python3 $HOME/tools/ctfr/ctfr.py \"\$@\"" >> ctfr_launcher
    chmod +x ctfr_launcher
    sudo mv ctfr_launcher /usr/local/bin/ctfr
fi

# --- 6. SYMLINK FIXES ---
if command_exists subjs && ! command_exists subJS; then
    notice "Fixing Case Sensitivity for subJS..."
    sudo ln -s $(which subjs) /usr/local/bin/subJS 2>/dev/null || cp $(which subjs) $HOME/go/bin/subJS
fi

# --- 7. WORDLISTS & CONFIG ---
notice "Step 7: Finalizing..."

# Subdomain Wordlist
if [ ! -f "$WORDLIST_DIR/subdomains-top1million-5000.txt" ]; then
    mkdir -p "$WORDLIST_DIR"
    wget -q "$WORDLIST_URL" -O "$WORDLIST_DIR/subdomains-top1million-5000.txt"
fi

# AltDNS Wordlist (Required for altdns to work)
if [ ! -f "/usr/share/wordlists/altdns_words.txt" ]; then
    sudo mkdir -p /usr/share/wordlists
    sudo wget -q "$ALTDNS_WORDS" -O /usr/share/wordlists/altdns_words.txt
fi

if command_exists nuclei; then
    nuclei -ut >/dev/null 2>&1
fi

grep -q "export PATH=\$PATH:\$HOME/go/bin" "$HOME/.bashrc" || echo 'export PATH=$PATH:$HOME/go/bin:$HOME/.local/bin' >> "$HOME/.bashrc"

echo -e "\n${GREEN}${BOLD}=== SYSTEM READY ===${RESET}"
echo "Run: source ~/.bashrc"

