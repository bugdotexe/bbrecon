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

BANNER() {
echo -e "${CYAN}"
echo -e "
 ** ****     ** ********** ******** **      
/**/**/**   /**/////**/// /**///// /**      
/**/**//**  /**    /**    /**      /**      
/**/** //** /**    /**    /******* /**      
/**/**  //**/**    /**    /**////  /**      
/**/**   //****    /**    /**      /**      
/**/**    //***    /**    /********/********
// //      ///     //     //////// //////// 
"
echo -e "${RESET}"
}

BANNER

if [ -z "$1" ]; then
    warn "Usage: $0 <output>"
    exit 1
fi
TARGET=$1
OUTPUT="$TARGET/INTEL"

mkdir -p "$OUTPUT"/.tmp 2>/dev/null

process_file() {
    local file_path=$1
    local output_path=$2

    notice "Reading domains from file: $file_path"
    while IFS= read -r line; do
        clean_line=$(echo "$line" | tr -d '[:space:]')
        [ -z "$clean_line" ] && continue
        bash /home/bugdotexe/bbrecon/tools/reverse-whois.sh ${clean_line} ${output_path}
        bash /home/bugdotexe/bbrecon/tools/favicon.sh ${clean_line} | anew ${output_path}/favicon 
        bash /home/bugdotexe/bbrecon/tools/infra.sh ${clean_line} ${output_path} 
    done < "$file_path"
}

if [ -d "$OUTPUT" ]; then
    SCOPE_FILE="$OUTPUT/../../wildcard.scopes"
    BASE_OUTPUT="$OUTPUT"

    if [ -f "$SCOPE_FILE" ]; then
        success "Found scopes file: $SCOPE_FILE"
        process_file "$SCOPE_FILE" "$BASE_OUTPUT"
    else
        err "scopes file does not exist inside $SCOPE_FILE"
        exit 1
    fi
fi

