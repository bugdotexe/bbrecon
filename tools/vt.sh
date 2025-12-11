#!/bin/bash

target=$1
output=$2

url="https://www.virustotal.com/api/v3/domains/$target/subdomains"
api_key="$VIRUSTOTAL_API"

if [[ $# -eq 0 ]];then
        echo "[-] Usage: ./$0 <target.com> <ouput>"
        exit 1;
fi

count=$(curl -s -X GET "$url" --header "x-apikey: $api_key" | jq -r .meta.count)
check=$(expr $count / 40)
check_2=$(expr $count % 40)
if [ "$check_2" -gt 0 ];then
        iters=$(expr $check + 1)
else
        iters=$check
fi

cursor="?cursor=&limit=40"
for ((i = 1 ; i <= "$iters" ; i++));do
        curl -s -X GET "$url$cursor" --header "x-apikey: $api_key" | jq -r .data[].id | anew -q $output
        next=$(curl -s -X GET "$url$cursor" --header "x-apikey: $api_key" | jq -r .links.next)
        name=$(basename $next | grep -oE "\?.*")
        if [[ ! -z "$name" ]];then
                cursor=$name
        fi
done
