#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository=$(CDPATH= cd -P -- "$script_dir/../../.." && pwd -P)
revision=$(git -C "$repository" rev-parse --verify HEAD^{commit})
tree=$(git -C "$repository" show -s --format=%T "$revision")
baseline=37fc5f9aa72b2ab549b2411c3ac6b9b9d6cbf798
git -C "$repository" rev-parse --verify "$baseline^{commit}" > /dev/null
temporary=$(mktemp -d "${TMPDIR:-/tmp}/fre-jit-qualification-bundle-test.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

. "$script_dir/runner_support.sh"
. "$script_dir/qualification_receipts.sh"
. "$script_dir/qualification_bundle_support.sh"
. "$script_dir/qualification_test_fixture.sh"

template="$temporary/template"
ephemeral="$temporary/ephemeral"
fre_jit_test_prepare_bundle_root \
    "$template" "$repository" "$revision" "$baseline" "$ephemeral" "$script_dir"

clone_template() {
    clone_name=$1
    clone_root="$temporary/$clone_name"
    cp -R -- "$template" "$clone_root"
    printf '%s\n' "$clone_root"
}

write_inputs() {
    input_root=$1
    input_name=$2
    input_path="$temporary/$input_name-inputs.tsv"
    fre_jit_test_write_inputs "$input_root" "$input_path"
    printf '%s\n' "$input_path"
}

assert_make_rejected() {
    case_name=$1
    case_root=$2
    case_inputs=$(write_inputs "$case_root" "$case_name")
    if "$script_dir/make_qualification_bundle.sh" \
        "$case_root" "$repository" "$revision" "$case_inputs" \
        > "$temporary/$case_name.stdout" 2> "$temporary/$case_name.stderr"
    then
        echo "invalid qualification bundle was accepted: $case_name" >&2
        exit 1
    fi
}

update_gate_input() {
    update_root=$1
    update_relative=$2
    update_file="$update_root/$update_relative"
    update_sha=$(fre_bakeoff_sha256 "$update_file")
    update_bytes=$(wc -c < "$update_file" | tr -d ' ')
    awk -F '	' -v OFS='	' \
        -v relative="$update_relative" \
        -v sha="$update_sha" -v bytes="$update_bytes" '
        $1 == "input_sha256" && $4 == relative {
            $2 = sha
            $3 = bytes
            found++
        }
        { print }
        END { if (found != 1) exit 2 }
    ' "$update_root/gates/promotion.tsv" \
        > "$update_root/gates/promotion.updated"
    {
        sed -n '1,20p' "$update_root/gates/promotion.updated"
        tail -n +21 "$update_root/gates/promotion.updated" | LC_ALL=C sort
    } > "$update_root/gates/promotion.tmp"
    rm -- "$update_root/gates/promotion.updated"
    mv -- "$update_root/gates/promotion.tmp" "$update_root/gates/promotion.tsv"
}

update_manifest_entry() {
    update_root=$1
    update_relative=$2
    update_file="$update_root/$update_relative"
    update_sha=$(fre_bakeoff_sha256 "$update_file")
    update_bytes=$(wc -c < "$update_file" | tr -d ' ')
    awk -F '	' -v OFS='	' \
        -v relative="$update_relative" \
        -v sha="$update_sha" -v bytes="$update_bytes" '
        $1 == "entry" && $5 == relative {
            $3 = sha
            $4 = bytes
            found++
        }
        { print }
        END { if (found != 1) exit 2 }
    ' "$update_root/qualification-bundle-v1.tsv" \
        > "$update_root/qualification-bundle-v1.tmp"
    mv -- \
        "$update_root/qualification-bundle-v1.tmp" \
        "$update_root/qualification-bundle-v1.tsv"
}

# A structurally complete synthetic 90/54/1 inventory must replay after both
# source-bound executable paths have disappeared.
valid=$(clone_template valid)
valid_inputs=$(write_inputs "$valid" valid)
valid_output=$(
    "$script_dir/make_qualification_bundle.sh" \
        "$valid" "$repository" "$revision" "$valid_inputs"
)
valid_sha=$(
    printf '%s\n' "$valid_output" |
        awk -F= '$1 == "bundle_sha256" { print $2 }'
)
"$script_dir/verify_qualification_bundle.sh" \
    "$valid" "$valid_sha" "$repository" > /dev/null

# The syntactic receipt validator must not accept the historical three-file
# bypass even before semantic replay is attempted.  Retain one sorted input
# from each evidence tree so this fixture is accepted by the vulnerable
# validator rather than failing its older prefix-presence checks.
awk -F '	' '
    NR <= 20 { print; next }
    $1 == "input_sha256" && $4 ~ /^adversarial\// && !adversarial {
        print
        adversarial = 1
        next
    }
    $1 == "input_sha256" && $4 ~ /^main\// && !main {
        print
        main = 1
        next
    }
    $1 == "input_sha256" && $4 ~ /^targeted\// && !targeted {
        print
        targeted = 1
        next
    }
    END {
        if (adversarial != 1 || main != 1 || targeted != 1) exit 2
    }
' "$template/gates/promotion.tsv" > "$temporary/truncated-receipt.tsv"
test "$(wc -l < "$temporary/truncated-receipt.tsv" | tr -d ' ')" = 23
historical_receipts="$temporary/qualification-receipts-q2.sh"
git -C "$repository" show \
    1ae32193:research/jit/bakeoff/qualification_receipts.sh \
    > "$historical_receipts"
(
    . "$script_dir/runner_support.sh"
    . "$historical_receipts"
    fre_jit_validate_promotion_gate_receipt \
        "$temporary/truncated-receipt.tsv" \
        "$repository" "$revision" "$tree"
)
if fre_jit_validate_promotion_gate_receipt \
    "$temporary/truncated-receipt.tsv" "$repository" "$revision" "$tree" \
    > /dev/null 2>&1
then
    echo "three-file promotion receipt bypass was accepted" >&2
    exit 1
fi

truncated=$(clone_template truncated)
rm -rf -- "$truncated/main" "$truncated/adversarial" "$truncated/targeted"
mkdir -- "$truncated/main" "$truncated/adversarial" "$truncated/targeted"
printf 'main\n' > "$truncated/main/raw.csv"
printf 'adversarial\n' > "$truncated/adversarial/raw.csv"
printf 'targeted\n' > "$truncated/targeted/raw.csv"
assert_make_rejected truncated "$truncated"

hash_mismatch=$(clone_template hash-mismatch)
printf '# changed binary\n' \
    >> "$hash_mismatch/binaries/candidate-fre-jit-bakeoff"
if fre_jit_bundle_validate_artifact_bindings "$hash_mismatch" \
    > /dev/null 2>&1
then
    echo "candidate binary hash mismatch was accepted" >&2
    exit 1
fi

missing_file=$(clone_template missing-file)
missing_inputs=$(write_inputs "$missing_file" missing-file)
rm -- "$missing_file/main/exact-span.instructions.txt"
if fre_jit_bundle_require_exact_inventory \
    "$missing_file" "$missing_inputs" "$temporary/missing-inventory" \
    > /dev/null 2>&1
then
    echo "missing declared result file was accepted" >&2
    exit 1
fi

extra_file=$(clone_template extra-file)
extra_inputs=$(write_inputs "$extra_file" extra-file)
printf 'unreported result\n' > "$extra_file/main/extra.txt"
if fre_jit_bundle_require_exact_inventory \
    "$extra_file" "$extra_inputs" "$temporary/extra-inventory" \
    > /dev/null 2>&1
then
    echo "unreported extra result file was accepted" >&2
    exit 1
fi

swapped=$(clone_template swapped-artifacts)
mv -- \
    "$swapped/binaries/candidate-fre-jit-bakeoff" \
    "$swapped/binaries/swap.tmp"
mv -- \
    "$swapped/binaries/baseline-fre-jit-bakeoff" \
    "$swapped/binaries/candidate-fre-jit-bakeoff"
mv -- \
    "$swapped/binaries/swap.tmp" \
    "$swapped/binaries/baseline-fre-jit-bakeoff"
if fre_jit_bundle_validate_artifact_bindings "$swapped" \
    > /dev/null 2>&1
then
    echo "swapped candidate and baseline artifacts were accepted" >&2
    exit 1
fi

changed_receipt=$(clone_template changed-in-tree-receipt)
awk -F '	' -v OFS='	' '
    $1 == "binary_path" { $2 = "/private/tmp/forged-candidate" }
    { print }
' "$changed_receipt/adversarial/provenance/candidate-build-receipt.tsv" \
    > "$changed_receipt/adversarial/provenance/candidate-build-receipt.tmp"
mv -- \
    "$changed_receipt/adversarial/provenance/candidate-build-receipt.tmp" \
    "$changed_receipt/adversarial/provenance/candidate-build-receipt.tsv"
update_gate_input \
    "$changed_receipt" \
    adversarial/provenance/candidate-build-receipt.tsv
if fre_jit_bundle_replay_gate \
    "$changed_receipt" "$repository" "$revision" \
    "$temporary/changed-receipt-replay" > /dev/null 2>&1
then
    echo "changed in-tree candidate receipt was accepted by replay" >&2
    exit 1
fi

# Even an attacker who recomputes the gate's input hash, the bundle entry
# hashes, and the external bundle hash cannot forge passing performance.
forged_bundle="$temporary/forged-bundle"
cp -R -- "$valid" "$forged_bundle"
awk -F, -v OFS=, '
    NR == 1 { print; next }
    !changed && $12 == "fre-qualified-exact" && $13 == "search" {
        $16 = 1000
        $17 = 1000
        changed = 1
    }
    { print }
    END { if (!changed) exit 2 }
' "$forged_bundle/main/raw.csv" > "$forged_bundle/main/raw.tmp"
mv -- "$forged_bundle/main/raw.tmp" "$forged_bundle/main/raw.csv"
update_gate_input "$forged_bundle" main/raw.csv
update_manifest_entry "$forged_bundle" main/raw.csv
update_manifest_entry "$forged_bundle" gates/promotion.tsv
fre_jit_validate_promotion_gate_receipt \
    "$forged_bundle/gates/promotion.tsv" \
    "$repository" "$revision" "$tree"
forged_sha=$(fre_bakeoff_sha256 "$forged_bundle/qualification-bundle-v1.tsv")
if "$script_dir/verify_qualification_bundle.sh" \
    "$forged_bundle" "$forged_sha" "$repository" \
    > "$temporary/forged-bundle.stdout" 2> "$temporary/forged-bundle.stderr"
then
    echo "self-consistent forged metrics bypassed semantic replay" >&2
    exit 1
fi

# Inject a concurrent mutation through a cp wrapper.  This does not add a test
# hook to production code.  Both source state A and copied state B are valid
# review receipts, so only the pre-copy/frozen-copy equality check rejects the
# A-to-B-for-copy-to-A splice.
wrapper_dir="$temporary/wrapper"
mkdir -- "$wrapper_dir"
awk -F '	' -v OFS='	' '
    $1 == "reviewer_task" { $2 = "/root/jit_v7_splice_review" }
    { print }
' "$template/reviews/independent.txt" > "$temporary/splice-review.txt"
fre_jit_validate_independent_review_receipt \
    "$temporary/splice-review.txt" "$repository" "$revision" "$tree"
{
    printf '#!/bin/sh\n'
    printf 'set -eu\n'
    printf 'splice=0\n'
    printf 'for argument in "$@"; do\n'
    printf '  if [ "$argument" = "$FRE_JIT_TEST_MUTATE_TARGET" ]; then splice=1; fi\n'
    printf 'done\n'
    printf 'if [ "$splice" = 1 ] && mkdir "$FRE_JIT_TEST_MUTATE_MARKER" 2>/dev/null; then\n'
    printf '  /bin/cp "$FRE_JIT_TEST_MUTATE_TARGET" "$FRE_JIT_TEST_MUTATE_BACKUP"\n'
    printf '  /bin/cp "$FRE_JIT_TEST_MUTATE_TRANSIENT" "$FRE_JIT_TEST_MUTATE_TARGET"\n'
    printf '  /bin/cp "$@"\n'
    printf '  /bin/cp "$FRE_JIT_TEST_MUTATE_BACKUP" "$FRE_JIT_TEST_MUTATE_TARGET"\n'
    printf '  exit 0\n'
    printf 'fi\n'
    printf '/bin/cp "$@"\n'
} > "$wrapper_dir/cp"
chmod 0755 "$wrapper_dir/cp"

maker_race=$(clone_template maker-race)
maker_race_inputs=$(write_inputs "$maker_race" maker-race)
maker_race_canonical=$(CDPATH= cd -P -- "$maker_race" && pwd -P)
if PATH="$wrapper_dir:$PATH" \
    FRE_JIT_TEST_MUTATE_TARGET="$maker_race_canonical/reviews/independent.txt" \
    FRE_JIT_TEST_MUTATE_TRANSIENT="$temporary/splice-review.txt" \
    FRE_JIT_TEST_MUTATE_MARKER="$temporary/maker-race-marker" \
    FRE_JIT_TEST_MUTATE_BACKUP="$temporary/maker-race-backup" \
    "$script_dir/make_qualification_bundle.sh" \
        "$maker_race" "$repository" "$revision" "$maker_race_inputs" \
        > "$temporary/maker-race.stdout" 2> "$temporary/maker-race.stderr"
then
    echo "bundle maker accepted a concurrent source mutation" >&2
    exit 1
fi
test -d "$temporary/maker-race-marker" || {
    echo "bundle-maker race injection did not trigger" >&2
    sed 's/^/  /' "$temporary/maker-race.stderr" >&2
    exit 1
}
grep -F 'frozen snapshot differs from the pre-copy qualification state' \
    "$temporary/maker-race.stderr" > /dev/null || {
    echo "bundle-maker race was rejected by the wrong invariant" >&2
    exit 1
}
cmp -s \
    "$maker_race/reviews/independent.txt" \
    "$template/reviews/independent.txt" || {
    echo "bundle-maker race did not restore source state A" >&2
    exit 1
}

verify_race="$temporary/verify-race"
cp -R -- "$valid" "$verify_race"
verify_race_sha=$valid_sha
verify_race_canonical=$(CDPATH= cd -P -- "$verify_race" && pwd -P)
if PATH="$wrapper_dir:$PATH" \
    FRE_JIT_TEST_MUTATE_TARGET="$verify_race_canonical/reviews/independent.txt" \
    FRE_JIT_TEST_MUTATE_TRANSIENT="$temporary/splice-review.txt" \
    FRE_JIT_TEST_MUTATE_MARKER="$temporary/verify-race-marker" \
    FRE_JIT_TEST_MUTATE_BACKUP="$temporary/verify-race-backup" \
    "$script_dir/verify_qualification_bundle.sh" \
        "$verify_race" "$verify_race_sha" "$repository" \
        > "$temporary/verify-race.stdout" 2> "$temporary/verify-race.stderr"
then
    echo "bundle verifier accepted a concurrent source mutation" >&2
    exit 1
fi
test -d "$temporary/verify-race-marker" || {
    echo "bundle-verifier race injection did not trigger" >&2
    sed 's/^/  /' "$temporary/verify-race.stderr" >&2
    exit 1
}
grep -F 'frozen snapshot differs from the pre-copy qualification state' \
    "$temporary/verify-race.stderr" > /dev/null || {
    echo "bundle-verifier race was rejected by the wrong invariant" >&2
    exit 1
}
cmp -s \
    "$verify_race/reviews/independent.txt" \
    "$valid/reviews/independent.txt" || {
    echo "bundle-verifier race did not restore source state A" >&2
    exit 1
}

echo "verified: complete frozen replay rejects truncation, forgery, swaps, drift, and races"
