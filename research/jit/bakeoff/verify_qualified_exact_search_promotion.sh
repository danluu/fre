#!/bin/sh
set -eu

subject_revision=88e9c22c4ac382531bc1026ca0e25587905f5206
subject_tree=131e38a4bfe5946bba6e994ee376ad239e1cca97
bundle_sha256=de084ff0564acdb89889f28b9dcfddce9b6f0955a1b2aead30d75770039e0453
promotion_gate_sha256=7c645a31641d41678e2847d6b49b5f73fcc077537c6b97eca5026c97737332ef
independent_review_sha256=1c50399d2b4c3b3e7a49abac54c1ec7ae2dafd88086555c4278f6c475a5a2751
findings_sha256=bdd3d43db72d8ab4918976899764ff0982c927a5cf56910b7688ebbe13adf04b
qualification_path=crates/fre/src/qualified_exact_search_qualification.rs
qualification_sha256=b88da4abf05858048bd09f404496f9d2549723cd4d918316799ba8246e6cf2b0
qualification_parent_blob=f2eba5e5cf3354cc7ff4a2f71d0c3268538ad1cc
qualification_promoted_blob=3e34f2976cf0c89caa7165261842eec13d3edd43
contract_path=research/jit/bakeoff/qualified_exact_search_promotion.tsv
contract_sha256=30dd4b89562ea67d565d6aefbc975fc4030531d2f9ee8ae5f97b01688e8b5380

usage() {
    cat >&2 <<'EOF'
usage:
  verify_qualified_exact_search_promotion.sh PROMOTION_REVISION BUNDLE_ROOT REPOSITORY
  verify_qualified_exact_search_promotion.sh --source-only PROMOTION_REVISION REPOSITORY
EOF
    exit 2
}

promotion_error() {
    echo "$*" >&2
    return 2
}

sha256_file() {
    shasum -a 256 "$1" | awk '{ print $1 }'
}

validate_exact_commit() {
    revision=$1
    label=$2
    case "$revision" in
        *[!0-9a-f]*|"")
            promotion_error "$label must be exactly 40 lowercase hexadecimal digits"
            return $?
            ;;
    esac
    if [ "${#revision}" != 40 ]; then
        promotion_error "$label must be exactly 40 lowercase hexadecimal digits"
        return $?
    fi
    resolved=$(
        git -C "$repository" rev-parse --verify "$revision^{commit}" 2>/dev/null
    ) || {
        promotion_error "$label is not an exact commit"
        return $?
    }
    if [ "$resolved" != "$revision" ]; then
        promotion_error "$label did not resolve exactly"
        return $?
    fi
}

verify_source_contract() {
    validate_exact_commit "$subject_revision" qualification_subject
    validate_exact_commit "$promotion_revision" promotion_revision
    if [ "$(git -C "$repository" show -s --format=%T \
        "$subject_revision")" != "$subject_tree" ]
    then
        promotion_error "qualification subject tree does not match the sealed Q8 tree"
        return $?
    fi

    parents=$(git -C "$repository" show -s --format=%P "$promotion_revision")
    if [ "$parents" != "$subject_revision" ]; then
        promotion_error \
            "promotion must have the exact Q8 qualification commit as its sole parent"
        return $?
    fi

    expected_delta="$temporary/expected-delta.tsv"
    actual_delta="$temporary/actual-delta.tsv"
    cat > "$expected_delta" <<'EOF'
A	research/jit/bakeoff/qualified_exact_search_promotion.tsv
A	research/jit/bakeoff/test_qualified_exact_search_promotion.sh
A	research/jit/bakeoff/verify_qualified_exact_search_promotion.sh
M	crates/fre/src/qualified_exact_search_qualification.rs
M	crates/fre/tests/qualified_exact_search.rs
M	docs/PROGRESS.md
M	docs/RISK_REGISTER.md
M	research/jit/STATUS.json
M	research/jit/aarch64/README.md
M	research/jit/bakeoff/README.md
EOF
    git -C "$repository" diff-tree --no-commit-id --name-status -r \
        "$subject_revision" "$promotion_revision" |
        LC_ALL=C sort > "$actual_delta"
    if ! cmp -s "$expected_delta" "$actual_delta"; then
        promotion_error \
            "promotion has an unexpected delta; audited execution source may have drifted"
        return $?
    fi

    if [ "$(git -C "$repository" rev-parse \
        "$subject_revision:$qualification_path")" != \
        "$qualification_parent_blob" ]
    then
        promotion_error "Q8 qualification atom differs from its sealed candidate blob"
        return $?
    fi
    if [ "$(git -C "$repository" rev-parse \
        "$promotion_revision:$qualification_path")" != \
        "$qualification_promoted_blob" ]
    then
        promotion_error \
            "promotion qualification atom is not the canonical bundle authorization"
        return $?
    fi

    git -C "$repository" show "$promotion_revision:$qualification_path" \
        > "$temporary/qualification.rs"
    if [ "$(sha256_file "$temporary/qualification.rs")" != \
        "$qualification_sha256" ]
    then
        promotion_error \
            "promotion qualification source differs from its sealed SHA-256"
        return $?
    fi

    git -C "$repository" show "$promotion_revision:$contract_path" \
        > "$temporary/promotion-contract.tsv"
    if [ "$(sha256_file "$temporary/promotion-contract.tsv")" != \
        "$contract_sha256" ]
    then
        promotion_error "promotion contract record differs from its closed canonical form"
        return $?
    fi
}

source_only=0
if [ "${1:-}" = --source-only ]; then
    if [ "$#" != 3 ]; then
        usage
    fi
    source_only=1
    promotion_revision=$2
    repository_argument=$3
else
    if [ "$#" != 3 ]; then
        usage
    fi
    promotion_revision=$1
    bundle_argument=$2
    repository_argument=$3
fi

case "$repository_argument" in
    /*) ;;
    *) promotion_error "repository must be an absolute path"; exit $? ;;
esac
if [ ! -d "$repository_argument" ] || [ -L "$repository_argument" ]; then
    promotion_error "repository must be an existing non-symlink directory"
    exit $?
fi
repository=$(CDPATH= cd -P -- "$repository_argument" && pwd -P)

temporary=$(mktemp -d "${TMPDIR:-/tmp}/fre-jit-qualified-promotion.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

verify_source_contract
if [ "$source_only" = 1 ]; then
    echo "verified source contract only; no bundle authorization was performed"
    exit 0
fi

case "$bundle_argument" in
    /*) ;;
    *) promotion_error "bundle root must be an absolute path"; exit $? ;;
esac
if [ ! -d "$bundle_argument" ] || [ -L "$bundle_argument" ]; then
    promotion_error "bundle root must be an existing non-symlink directory"
    exit $?
fi
bundle_root=$(CDPATH= cd -P -- "$bundle_argument" && pwd -P)

# Promotion verification deliberately runs the verifier implementation from
# the exact measured Q8 commit. A later worktree or descendant cannot weaken
# evidence replay while reusing the old bundle identity.
q_verifier="$temporary/q8-verifier"
mkdir -- "$q_verifier"
for verifier_file in \
    verify_qualification_bundle.sh \
    runner_support.sh \
    qualification_receipts.sh \
    qualification_bundle_support.sh
do
    verifier_object="$subject_revision:research/jit/bakeoff/$verifier_file"
    if [ "$(git -C "$repository" cat-file -t \
        "$verifier_object" 2>/dev/null)" != blob ]
    then
        promotion_error "Q8 bundle verifier source is incomplete"
        exit $?
    fi
    git -C "$repository" show "$verifier_object" \
        > "$q_verifier/$verifier_file"
done
chmod 0755 "$q_verifier/verify_qualification_bundle.sh"

"$q_verifier/verify_qualification_bundle.sh" \
    "$bundle_root" "$bundle_sha256" "$repository"

for binding in \
    "$promotion_gate_sha256 gates/promotion.tsv" \
    "$independent_review_sha256 reviews/independent.txt" \
    "$findings_sha256 reviews/findings.txt"
do
    expected=${binding%% *}
    relative=${binding#* }
    actual=$(sha256_file "$bundle_root/$relative")
    if [ "$actual" != "$expected" ]; then
        promotion_error "canonical bundle binding differs: $relative"
        exit $?
    fi
done

echo "verified: direct-child exact-search promotion and canonical Q8 bundle agree"
