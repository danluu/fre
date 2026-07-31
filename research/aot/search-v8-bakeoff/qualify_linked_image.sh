#!/bin/bash -p
set -Eeuo pipefail

export LC_ALL=C
export TZ=UTC
umask 077
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
hash -r
unset BASH_ENV ENV CDPATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
    PYTHONHOME PYTHONPATH PYTHONINSPECT PYTHONSTARTUP 2>/dev/null || :

usage='usage: qualify_linked_image.sh ABSOLUTE_BUILD_RECEIPT ABSOLUTE_OBJECT ABSOLUTE_EXECUTABLE ABSOLUTE_LINK_MAP ABSOLUTE_NEW_OUTPUT_DIRECTORY'
[[ $# -eq 5 ]] || {
    printf '%s\n' "$usage" >&2
    exit 2
}
receipt=$1
object=$2
executable=$3
link_map=$4
output=$5
case "$receipt:$object:$executable:$link_map:$output" in
    /*:/*:/*:/*:/*) ;;
    *) printf '%s\n' 'all arguments must be absolute paths' >&2; exit 2 ;;
esac
for input in "$receipt" "$object" "$executable" "$link_map"; do
    [[ -f $input && ! -L $input ]]
done
[[ -x $executable ]]
[[ ! -e $output && ! -L $output ]]

script_dir=$(CDPATH= cd -P -- "$(dirname -- "$0")" && pwd -P)
verifier=$script_dir/verify_linked_image.py
[[ -f $verifier && ! -L $verifier ]]

receipt_value() {
    local key=$1
    /usr/bin/awk -F '	' -v key="$key" '
        $1 == key {
            if (seen++ || NF != 2 || $2 == "") exit 2
            value = $2
        }
        END {
            if (seen != 1) exit 2
            print value
        }
    ' "$receipt"
}

sha256() {
    /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{ print $1 }'
}

[[ $link_map == "$(receipt_value link_map_path)" ]]
executable_sha256=$(sha256 "$executable")
mkdir -m 0700 -- "$output"
/usr/bin/nm -n "$executable" > "$output/nm.txt"
/usr/bin/otool -l "$executable" > "$output/otool.txt"
/bin/cp "$link_map" "$output/link-map.txt"
/usr/bin/python3 "$verifier" \
    "$receipt" \
    "$object" \
    "$executable" \
    "$output/link-map.txt" \
    "$output/nm.txt" \
    "$output/otool.txt" \
    > "$output/verification.tsv"
[[ $(sha256 "$executable") == "$executable_sha256" ]]
[[ $(receipt_value object_identity) == "$(sha256 "$object")" ]]
