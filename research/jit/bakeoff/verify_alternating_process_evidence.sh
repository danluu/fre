#!/bin/sh
set -eu

usage() {
    echo "usage: verify_alternating_process_evidence.sh DIRECTORY EXPECTED_CELLS EXPECTED_REPETITIONS BASELINE_SOURCE CANDIDATE_SOURCE [REQUIRED_CELL]" >&2
    exit 2
}

if [ "$#" -lt 5 ] || [ "$#" -gt 6 ]; then
    usage
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
. "$script_dir/runner_support.sh"
tab=$(printf '\t')

directory=$1
expected_cells=$2
expected_repetitions=$3
baseline_source=$4
candidate_source=$5
required_cell=${6:-}
for number in "$expected_cells" "$expected_repetitions"; do
    case "$number" in
        ""|*[!0-9]*) usage ;;
    esac
    if [ "$number" -le 0 ]; then
        usage
    fi
done

for required in \
    "$directory/baseline.header.csv" \
    "$directory/candidate.header.csv" \
    "$directory/baseline.raw.csv" \
    "$directory/candidate.raw.csv" \
    "$directory/cells.txt" \
    "$directory/sequence.tsv"
do
    if [ ! -f "$required" ] || [ -L "$required" ]; then
        echo "missing regular alternating evidence file: $required" >&2
        exit 2
    fi
done
if [ ! -d "$directory/processes" ] || [ -L "$directory/processes" ]; then
    echo "missing regular alternating process-output directory" >&2
    exit 2
fi

temporary=$(mktemp -d "${TMPDIR:-/tmp}/fre-jit-process-evidence.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

for variant in baseline candidate; do
    header="$directory/$variant.header.csv"
    test -s "$header"
    test "$(wc -l < "$header" | tr -d ' ')" = 1
    test "$(sed -n '1p' "$directory/$variant.raw.csv")" = \
        "$(sed -n '1p' "$header")"
done

LC_ALL=C awk '
    NF != 4 { bad = 1; next }
    {
        for (field = 1; field <= NF; field++) {
            if ($field !~ /^[a-z0-9-]+$/) bad = 1
        }
        cell = $1 "-" $2 "-" $3 "-" $4
        if (seen[cell]++) bad = 1
        print NR "\t" cell
    }
    END { exit bad }
' "$directory/cells.txt" > "$temporary/catalog.tsv"
test "$(wc -l < "$temporary/catalog.tsv" | tr -d ' ')" = "$expected_cells"
if [ -n "$required_cell" ]; then
    test "$expected_cells" = 1
    test "$(awk -F '	' 'NR == 1 { print $2 }' "$temporary/catalog.tsv")" = \
        "$required_cell"
fi

LC_ALL=C awk -F '	' \
    -v expected_cells="$expected_cells" \
    -v expected_repetitions="$expected_repetitions" \
    -v baseline_source="$baseline_source" \
    -v candidate_source="$candidate_source" '
    FNR == NR {
        if (NF != 2 || $1 != FNR) bad = 1
        catalog[$1] = $2
        next
    }
    FNR == 1 {
        if ($0 != "sequence\tcell\trepetition\tvariant\tsource_state\tpid\tprocess_output") {
            bad = 1
        }
        next
    }
    {
        row = FNR - 1
        if (NF != 7 || $1 !~ /^[0-9]+$/ ||
            sprintf("%d", $1 + 0) != $1 || $1 + 0 != row) bad = 1
        cell_index = int((row - 1) / (2 * expected_repetitions)) + 1
        within_cell = (row - 1) % (2 * expected_repetitions)
        repetition = int(within_cell / 2)
        position = within_cell % 2
        if (repetition % 2 == 0) {
            expected_variant = position == 0 ? "baseline" : "candidate"
        } else {
            expected_variant = position == 0 ? "candidate" : "baseline"
        }
        expected_source = expected_variant == "baseline" \
            ? baseline_source : candidate_source
        expected_output = sprintf("processes/%06d.csv", row)
        if (cell_index > expected_cells ||
            $2 != catalog[cell_index] ||
            $3 !~ /^[0-9]+$/ || sprintf("%d", $3 + 0) != $3 ||
            $3 + 0 != repetition ||
            $4 != expected_variant ||
            $5 != expected_source ||
            $6 !~ /^[0-9]+$/ || sprintf("%d", $6 + 0) != $6 ||
            $6 + 0 <= 0 ||
            seen_pid[$6]++ ||
            $7 != expected_output) {
            bad = 1
        }
        print $4 "\t" $6 "\t" $7 "\t" $5 "\t" $3 "\t" $2
    }
    END {
        expected_rows = 2 * expected_cells * expected_repetitions
        if (FNR - 1 != expected_rows) bad = 1
        exit bad
    }
' "$temporary/catalog.tsv" "$directory/sequence.tsv" > "$temporary/plan.tsv"

cp -- "$directory/baseline.header.csv" "$temporary/baseline.raw.csv"
cp -- "$directory/candidate.header.csv" "$temporary/candidate.raw.csv"
: > "$temporary/expected-process-files.txt"
while IFS=$tab read -r variant pid relative source repetition cell; do
    case "$relative" in
        processes/[0-9][0-9][0-9][0-9][0-9][0-9].csv) ;;
        *) echo "non-canonical process-output path: $relative" >&2; exit 2 ;;
    esac
    process_output="$directory/$relative"
    fre_bakeoff_validate_process_output \
        "$process_output" "$directory/$variant.header.csv" \
        "$source" "$repetition" "$cell"
    test "$FRE_BAKEOFF_PROCESS_PID" = "$pid"
    cat "$process_output" >> "$temporary/$variant.raw.csv"
    printf '%s\n' "$relative" >> "$temporary/expected-process-files.txt"
done < "$temporary/plan.tsv"

cmp -s "$temporary/baseline.raw.csv" "$directory/baseline.raw.csv"
cmp -s "$temporary/candidate.raw.csv" "$directory/candidate.raw.csv"

find "$directory/processes" -type l -print > "$temporary/process-symlinks.txt"
test ! -s "$temporary/process-symlinks.txt"
find "$directory/processes" ! -type d ! -type f ! -type l -print \
    > "$temporary/process-special.txt"
test ! -s "$temporary/process-special.txt"
find "$directory/processes" -type d -print |
    while IFS= read -r child; do
        test "$child" = "$directory/processes"
    done
find "$directory/processes" -type f -print |
    while IFS= read -r process_output; do
        relative=${process_output#"$directory"/}
        test "$relative" != "$process_output"
        printf '%s\n' "$relative"
    done |
    LC_ALL=C sort > "$temporary/actual-process-files.txt"
LC_ALL=C sort "$temporary/expected-process-files.txt" \
    > "$temporary/expected-process-files.sorted.txt"
cmp -s \
    "$temporary/expected-process-files.sorted.txt" \
    "$temporary/actual-process-files.txt"

echo "verified: alternating order, unique process IDs, retained outputs, and raw-row bijection agree"
