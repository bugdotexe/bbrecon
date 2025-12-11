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

INPUT=$1
BASE_OUTPUT=$2

BANNER() {
    echo -e "${CYAN}"
    echo -e "
       *******    ******** ** ****     ** **********
  **/////**  **////// /**/**/**   /**/////**/// 
 **     //**/**       /**/**//**  /**    /**    
/**      /**/*********/**/** //** /**    /**    
/**      /**////////**/**/**  //**/**    /**    
//**     **        /**/**/**   //****    /**    
 //*******   ******** /**/**    //***    /**    
  ///////   ////////  // //      ///     //     
"
    echo -e "${RESET}"
}

third_party_misconfigs() {
    local target=$1
    local out_dir=$2

    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return
    fi


    local company_name
    if command -v unfurl &> /dev/null; then
        company_name=$(echo "$target" | unfurl format %r)
    else
        company_name=$(echo "$target" | awk -F. '{if (NF>1) print $(NF-1); else print $1}')
    fi

    mkdir -p "$out_dir"
    notice "Running Misconfig Mapper for: $company_name"

           misconfig-mapper -target "$company_name" -service "*" 2>&1 | grep -v "\-\]" | grep -v "Failed" > "$out_dir/3rdparts_misconfigurations.txt"


    if [ -s "$out_dir/3rdparts_misconfigurations.txt" ]; then
        success "Saved to $out_dir/3rdparts_misconfigurations.txt"
    fi
}

ApiLeak() {
local target=$1
local out_dir=$2
local swaggerspy="/home/bugdotexe/bbrecon/tools/SwaggerSpy/swaggerspy.py"

notice "Scanning for leaks in public API directories"
if [ -f "$swaggerspy" ];then
python3 "$swaggerspy" $target 2>/dev/null | grep -i "[*]\|URL" >"${out_dir}/swagger_leaks.txt"
fi

porch-pirate -s "$target" -l 25 | anew -q "$out_dir/postman.tmp"

cat "$out_dir/postman.tmp" | sed 's/\x1b\[[0-9;]*m//g' | grep -o "\[workspace\] \[[0-9a-f-]*\]" | awk '{print $2}' | tr -d '[]' | anew -q "$out_dir/postman_workspace.tmp"
cat "$out_dir/postman.tmp" | sed 's/\x1b\[[0-9;]*m//g' | grep -o "\[collection\] \[[0-9a-f-]*\]" | awk '{print $2}' | tr -d '[]' | anew -q "$out_dir/postman_collections.tmp"

}

LeakSearch() {
local target=$1
local out_dir=$2
local LeakSearch="/home/bugdotexe/bbrecon/tools/LeakSearch/LeakSearch.py"

if [ -f "$metagoofil_path" ]; then
     python3 "$LeakSearch" -k $target -o "$out_dir/LeakCredentials.txt"
else
return
fi

if [ -s "$out_dir/LeakCredentials.txt" ]; then
            notice "Leaked Credentials saved to: $out_dir/LeakCredentials.txt"
fi

}

extractMetadata() {
    local target=$1
    local out_dir=$2
    local download_dir="$out_dir/metagoofil"
    local metagoofil_path="/home/bugdotexe/bbrecon/tools/metagoofil/metagoofil.py"

    mkdir -p "$download_dir"
    notice "Scanning metadata in public files for: $target"

    if [ -f "$metagoofil_path" ]; then
        python3 "$metagoofil_path" -d "$target" -t pdf,docx,xlsx -l 20 -w -o "$download_dir"
    else
        metagoofil -d "$target" -t pdf,docx,xlsx -l 20 -w -o "$download_dir"
    fi

    if ls "$download_dir"/* &>/dev/null; then
        notice "Extracting metadata with Exiftool..."
        exiftool -r "$download_dir"/* 2>/dev/null \
        | grep -iE "Author|Creator|Email|Producer|Template" \
        | sort -u \
        | anew "$out_dir/metadata.txt"
        
        if [ -s "$out_dir/metadata.txt" ]; then
            notice "Metadata saved to: $out_dir/metadata.txt"
        fi
    else
        echo "No files were downloaded by Metagoofil."
    fi
}

scopify() {
    local target=$1
    local company_name=$(unfurl format %r <<<"$target")
    local out_dir=$2
    local target_dir="$out_dir/$target/osint"
    scopify="/home/bugdotexe/bbrecon/tools/Scopify/scopify.py"
python ${scopify} -c $company_name --analyze | anew -q "$target_dir/scopify.txt"

}

scan_domain() {
    local target=$1
    local out_dir=$2
    local target_dir="$out_dir/OSINT"
    
    mkdir -p "$target_dir"

    echo -e "${MAGENTA}------------------------------------------------------${RESET}"
    notice "Targeting: $target"
    
    notice "Starting Email to Github Username enumeration..."
    bash /home/bugdotexe/bbrecon/tools/email2username.sh "$target" "$target_dir"
    
    notice "Starting Github Username Prefix enumeration..."
    bash /home/bugdotexe/bbrecon/tools/ghPrefix.sh "$target" "$target_dir"

    if [ -f "$target_dir/.tmp/github_users.1" ] || [ -f "$target_dir/.tmp/github_users.2" ]; then
        cat "$target_dir"/.tmp/github_users.* 2>/dev/null | anew "$target_dir/github_users.txt" >/dev/null
    fi

    notice "Checking leaked secrets from Github..."
    if [ -f "$target_dir/github_users.txt" ]; then
        bash /home/bugdotexe/bbrecon/tools/truffle.sh "$target_dir/github_users.txt" "$target_dir"
    else
        warn "No users found for $target, skipping truffle scan."
    fi
    third_party_misconfigs "$target" "$target_dir"
    LeakSearch "$target" "$target_dir"
    ApiLeak "$target" "$target_dir"
    extractMetadata "$target" "$target_dir"
    scopify "$target" "$target_dir"
}

process_file() {
    local file_path=$1
    local output_path=$2

    notice "Reading domains from file: $file_path"
    while IFS= read -r line; do
        clean_line=$(echo "$line" | tr -d '[:space:]')
        [ -z "$clean_line" ] && continue
        
        scan_domain "$clean_line" "$output_path"
    done < "$file_path"
}

BANNER

if [ -z "$INPUT" ] || [ -z "$BASE_OUTPUT" ]; then
    err "Usage: $0 <domain|file|folder> <output_directory>"
    exit 1
fi

if [ ! -d "$BASE_OUTPUT" ]; then
    mkdir -p "$BASE_OUTPUT"
fi

if [ -d "$INPUT" ]; then
    notice "Processing target Dir: $INPUT"
    SCOPE_FILE="$INPUT/wildcard.scopes"

    if [ -f "$SCOPE_FILE" ]; then
        success "Found wildcard.scopes found inside the directory!"
        process_file "$SCOPE_FILE" "$BASE_OUTPUT"
    else
        err "Directory found, but wildcard.scopes does not exist inside $INPUT"
        exit 1
    fi

elif [ -f "$INPUT" ]; then
    notice "Processing scopes file: "$SCOPE_FILE""
    process_file "$INPUT" "$BASE_OUTPUT"

else
    notice "Processing target domain: $INPUT"
    scan_domain "$INPUT" "$BASE_OUTPUT"
fi

echo -e "${MAGENTA}------------------------------------------------------${RESET}"
