#!/bin/sh
set -eu

usage() {
    echo "usage: capture_provenance.sh capture WORKSPACE DESTINATION | verify WORKSPACE CAPTURED_DIRECTORY" >&2
    exit 2
}

mode=${1:-}
workspace_argument=${2:-}
destination_argument=${3:-}
if [ -z "$mode" ] || [ -z "$workspace_argument" ] || [ -z "$destination_argument" ]; then
    usage
fi

workspace=$(CDPATH= cd -- "$workspace_argument" && pwd)

capture() {
    destination=$1
    mkdir -p "$destination"

    git -C "$workspace" rev-parse --verify HEAD > "$destination/head.txt"
    git -C "$workspace" status --porcelain=v1 --untracked-files=all \
        > "$destination/status.txt"
    git -C "$workspace" ls-files --others --exclude-standard \
        > "$destination/untracked.txt"
    if [ -s "$destination/untracked.txt" ]; then
        echo "refusing benchmark provenance with untracked source files:" >&2
        sed 's/^/  /' "$destination/untracked.txt" >&2
        echo "add, ignore, or remove them so the captured patch is complete" >&2
        exit 2
    fi

    if [ -f "$workspace/.gitmodules" ] &&
        ! git -C "$workspace" submodule foreach --quiet --recursive \
            'test -z "$(git status --porcelain=v1 --untracked-files=all)"'
    then
        echo "refusing benchmark provenance with a dirty submodule" >&2
        exit 2
    fi

    git -C "$workspace" diff --cached --binary --full-index --no-ext-diff --no-textconv \
        --src-prefix=a/ --dst-prefix=b/ --submodule=diff \
        > "$destination/staged.patch"
    git -C "$workspace" diff --binary --full-index --no-ext-diff --no-textconv \
        --src-prefix=a/ --dst-prefix=b/ --submodule=diff \
        > "$destination/worktree.patch"
    git -C "$workspace" submodule status --recursive \
        > "$destination/submodules.txt"

    (
        cd "$workspace"
        shasum -a 256 Cargo.lock research/jit/bakeoff/Cargo.lock
    ) > "$destination/lockfiles.sha256"
    (
        cd "$workspace"
        shasum -a 256 Cargo.toml research/jit/bakeoff/Cargo.toml
    ) > "$destination/manifests.sha256"

    (
        cd "$destination"
        shasum -a 256 \
            head.txt \
            status.txt \
            untracked.txt \
            staged.patch \
            worktree.patch \
            submodules.txt \
            lockfiles.sha256 \
            manifests.sha256
    ) > "$destination/source-inputs.sha256"

    source_digest=$(
        shasum -a 256 "$destination/source-inputs.sha256" | awk '{print $1}'
    )
    head=$(sed -n '1p' "$destination/head.txt")
    if [ -s "$destination/status.txt" ]; then
        dirty=1
        source_state_id="${head}+dirty.${source_digest}"
    else
        dirty=0
        source_state_id=$head
    fi
    printf '%s\n' "$dirty" > "$destination/dirty.txt"
    printf '%s\n' "$source_digest" > "$destination/source-digest.txt"
    printf '%s\n' "$source_state_id" > "$destination/source-state-id.txt"
    printf '%s\n' "$source_state_id"
}

case "$mode" in
    capture)
        capture "$destination_argument"
        ;;
    verify)
        captured=$destination_argument
        if [ ! -f "$captured/source-state-id.txt" ]; then
            echo "missing captured source state: $captured/source-state-id.txt" >&2
            exit 2
        fi
        temporary=$(mktemp -d "${TMPDIR:-/tmp}/fre-jit-provenance-verify.XXXXXX")
        trap 'rm -rf "$temporary"' EXIT HUP INT TERM
        capture "$temporary" > /dev/null
        if ! cmp -s \
            "$captured/source-state-id.txt" \
            "$temporary/source-state-id.txt"
        then
            echo "source changed after benchmark provenance was captured" >&2
            printf 'captured=' >&2
            sed -n '1p' "$captured/source-state-id.txt" >&2
            printf 'current=' >&2
            sed -n '1p' "$temporary/source-state-id.txt" >&2
            exit 2
        fi
        date -u '+%Y-%m-%dT%H:%M:%SZ' > "$captured/verified-at-finish.txt"
        ;;
    *)
        usage
        ;;
esac
