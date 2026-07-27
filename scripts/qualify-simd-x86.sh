#!/usr/bin/env bash
set -euo pipefail
umask 077

# Provider-neutral native x86 qualification for the fixed-width SIMD
# classifier. The complete gate process, including provenance collection and
# compilation, is pinned to one explicitly selected logical CPU. A successful
# receipt directory appears only after every mandatory gate and the benchmark
# receipt have been validated.

usage() {
    cat <<'EOF'
Usage:
  scripts/qualify-simd-x86.sh \
    --commit COMMIT --tree TREE --receipts PATH --bench-cpu CPU \
    [--bench-iters N] [--samples N] [--build-jobs N]

Required:
  --commit HEX       Exact 40-hex clean source commit to qualify.
  --tree HEX         Exact 40-hex root tree for COMMIT.
  --receipts PATH    New receipt-directory path outside the source tree.
  --bench-cpu CPU    One online logical CPU for the complete pinned process.

Options:
  --bench-iters N    Positive calls per implementation per sample (5000000).
  --samples N        Alternating AB/BA paired samples, at least 15 (16).
  --build-jobs N     Positive Cargo build-job limit (2).

Qualification always runs debug, release, release-codegen, unsafe-boundary,
feature-sentinel, and AVX2-versus-AVX-512 benchmark gates. There is no option
to skip the benchmark. The script is local and provider-neutral: it performs
no cloud, SSH, container, or service operation.
EOF
}

die() {
    printf 'qualify-simd-x86: %s\n' "$*" >&2
    exit 2
}

require_command() {
    command -v "$1" >/dev/null 2>&1 ||
        die "required command is absent: $1"
}

sha256_file() {
    sha256sum "$1" | awk '{print $1}'
}

original_arguments=("$@")
expected_commit=""
expected_tree=""
receipts=""
bench_cpu=""
bench_iters="5000000"
samples="16"
build_jobs="2"

while (($# > 0)); do
    case "$1" in
        --commit) expected_commit="${2:-}"; shift 2 ;;
        --tree) expected_tree="${2:-}"; shift 2 ;;
        --receipts) receipts="${2:-}"; shift 2 ;;
        --bench-cpu) bench_cpu="${2:-}"; shift 2 ;;
        --bench-iters) bench_iters="${2:-}"; shift 2 ;;
        --samples) samples="${2:-}"; shift 2 ;;
        --build-jobs) build_jobs="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] ||
    die "--commit must be 40 lowercase hex"
[[ "$expected_tree" =~ ^[0-9a-f]{40}$ ]] ||
    die "--tree must be 40 lowercase hex"
[[ -n "$receipts" ]] || die "--receipts is required"
[[ "$bench_cpu" =~ ^[0-9]+$ ]] || die "--bench-cpu must be one nonnegative integer"
[[ "$bench_iters" =~ ^[1-9][0-9]*$ ]] || die "--bench-iters must be positive"
[[ "$samples" =~ ^[1-9][0-9]*$ ]] || die "--samples must be positive"
((samples >= 15)) || die "--samples must be at least 15"
[[ "$build_jobs" =~ ^[1-9][0-9]*$ ]] || die "--build-jobs must be positive"

for command in awk cargo chmod find git grep lscpu python3 rustc sha256sum sort stat taskset uname; do
    require_command "$command"
done

for variable in $(compgen -e); do
    case "$variable" in
        FRE_SIMD_CODEGEN_TARGET|RUSTFLAGS|RUSTDOCFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_TARGET|CARGO_PROFILE_*|CARGO_TARGET_*_RUSTFLAGS|RUSTC|RUSTC_WRAPPER)
            die "build-affecting environment variable must be unset: $variable"
            ;;
    esac
done

[[ "$(uname -s)" == Linux ]] || die "native qualifier requires Linux"
[[ "$(uname -m)" == x86_64 ]] || die "native qualifier requires x86_64"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
script="$root/scripts/$(basename "${BASH_SOURCE[0]}")"
[[ -f "$script" && ! -L "$script" ]] ||
    die "qualifier must be a regular non-symlink file in the source tree"

receipts_parent="$(cd "$(dirname "$receipts")" && pwd -P)"
receipts="$receipts_parent/$(basename "$receipts")"
case "$receipts" in
    "$root"|"$root"/*) die "--receipts must be outside the source tree" ;;
esac
[[ ! -e "$receipts" && ! -L "$receipts" ]] ||
    die "receipt output already exists: $receipts"

observed_commit="$(git -C "$root" rev-parse HEAD)"
observed_tree="$(git -C "$root" rev-parse 'HEAD^{tree}')"
[[ "$observed_commit" == "$expected_commit" ]] ||
    die "commit mismatch: expected=$expected_commit observed=$observed_commit"
[[ "$observed_tree" == "$expected_tree" ]] ||
    die "tree mismatch: expected=$expected_tree observed=$observed_tree"
[[ -z "$(git -C "$root" status --porcelain=v1 --untracked-files=all)" ]] ||
    die "source worktree must be clean"

if [[ "${FRE_SIMD_X86_PINNED_PROCESS:-0}" != 1 ]]; then
    exec taskset -c "$bench_cpu" \
        env FRE_SIMD_X86_PINNED_PROCESS=1 \
        "$script" "${original_arguments[@]}"
fi

affinity_list="$(awk '/^Cpus_allowed_list:/ {print $2}' /proc/self/status)"
[[ "$affinity_list" == "$bench_cpu" ]] ||
    die "pinned process affinity mismatch: expected=$bench_cpu observed=$affinity_list"
[[ -r "/sys/devices/system/cpu/cpu${bench_cpu}/online" ]] &&
    [[ "$(cat "/sys/devices/system/cpu/cpu${bench_cpu}/online")" == 1 ]] ||
    [[ "$bench_cpu" == 0 ]] ||
    die "selected benchmark CPU is not online"

staging="$(mktemp -d "${receipts}.partial.XXXXXX")"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/fre-simd-x86-build.XXXXXX")"
published=0

cleanup() {
    local status=$?
    if ((published == 0)) && [[ -d "$staging" ]]; then
        rm -rf -- "$staging"
    fi
    if [[ -d "$scratch" ]]; then
        rm -rf -- "$scratch"
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

chmod 0700 "$staging"
[[ "$(stat -c '%a' -- "$staging")" == 700 ]] ||
    die "internal staging directory is not private"
benchmark_receipt="$staging/benchmark-receipt.txt"
sentinel_receipt="$staging/avx512-sentinel-receipt.txt"
for machine_receipt in "$benchmark_receipt" "$sentinel_receipt"; do
    [[ "$machine_receipt" == /* ]] ||
        die "internal machine receipt path is not absolute"
    [[ ! -e "$machine_receipt" && ! -L "$machine_receipt" ]] ||
        die "internal machine receipt path already exists"
done

export CARGO_BUILD_JOBS="$build_jobs"
export CARGO_INCREMENTAL=0
export CARGO_TARGET_DIR="$scratch/target"
export TMPDIR="$scratch/tmp"
mkdir -m 0700 "$TMPDIR"
cd "$root"

{
    printf 'schema=fre-simd-x86-avx512-qualification-v1\n'
    printf 'created_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'commit=%s\n' "$observed_commit"
    printf 'tree=%s\n' "$observed_tree"
    printf 'bench_cpu=%s\n' "$bench_cpu"
    printf 'bench_iters=%s\n' "$bench_iters"
    printf 'samples=%s\n' "$samples"
    printf 'build_jobs=%s\n' "$build_jobs"
    printf 'qualifier_sha256=%s\n' "$(sha256_file "$script")"
} >"$staging/request.env"

rustc -Vv >"$staging/rustc.txt"
cargo -Vv >"$staging/cargo.txt"
uname -a >"$staging/uname.txt"
lscpu --json >"$staging/lscpu.json"
lscpu -e=CPU,NODE,SOCKET,CORE,ONLINE,MAXMHZ,MINMHZ >"$staging/topology.txt"
cp /proc/cpuinfo "$staging/cpuinfo.txt"
{
    taskset -pc "$$"
    grep -E '^(Cpus_allowed|Cpus_allowed_list):' /proc/self/status
} >"$staging/affinity.txt"
{
    printf 'cpu=%s\n' "$bench_cpu"
    for field in core_id physical_package_id thread_siblings_list core_siblings_list; do
        path="/sys/devices/system/cpu/cpu${bench_cpu}/topology/${field}"
        if [[ -r "$path" ]]; then
            printf '%s=%s\n' "$field" "$(cat "$path")"
        else
            printf '%s=unavailable\n' "$field"
        fi
    done
} >"$staging/cpu-topology.env"
{
    microcode_path="/sys/devices/system/cpu/cpu${bench_cpu}/microcode/version"
    if [[ -r "$microcode_path" ]]; then
        printf 'sysfs=%s\n' "$(cat "$microcode_path")"
    else
        printf 'sysfs=unavailable\n'
    fi
    cpuinfo_microcode="$(awk -F: '/^microcode[[:space:]]*:/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' /proc/cpuinfo)"
    printf 'cpuinfo=%s\n' "${cpuinfo_microcode:-unavailable}"
} >"$staging/microcode.env"
{
    governor_root="/sys/devices/system/cpu/cpu${bench_cpu}/cpufreq"
    for field in scaling_governor scaling_driver energy_performance_preference scaling_min_freq scaling_max_freq; do
        path="$governor_root/$field"
        if [[ -r "$path" ]]; then
            printf '%s=%s\n' "$field" "$(cat "$path")"
        else
            printf '%s=unavailable\n' "$field"
        fi
    done
} >"$staging/governor.env"

run_gate() {
    local name="$1"
    shift
    {
        printf 'gate=%s\n' "$name"
        printf 'started_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        "$@"
        printf 'completed_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } >"$staging/${name}.log" 2>&1
    printf 'gate=%s\nstatus=pass\nlog_sha256=%s\n' \
        "$name" "$(sha256_file "$staging/${name}.log")" \
        >"$staging/${name}.env"
}

debug_gate() {
    cargo test \
        --locked --offline \
        -p fre-target-features \
        -p fre-simd-kernels
    [[ ! -e "$sentinel_receipt" && ! -L "$sentinel_receipt" ]] ||
        die "broad debug suite unexpectedly created the sentinel receipt"
    FRE_SIMD_REQUIRE_AVX512=1 \
    FRE_SIMD_AVX512_SENTINEL_RECEIPT_PATH="$sentinel_receipt" \
        cargo test \
            --locked --offline \
            -p fre-simd-kernels \
            tests::required_avx512_native_sentinel_fails_instead_of_skipping \
            -- \
            --exact --nocapture
}

release_gate() {
    cargo test \
        --locked --offline --release \
        -p fre-simd-kernels
}

codegen_gate() {
    env -u FRE_SIMD_CODEGEN_TARGET scripts/check-simd-codegen.sh
}

unsafe_gate() {
    scripts/check-unsafe-lint-boundary.sh
}

features_gate() {
    cargo run \
        --locked --offline --quiet \
        -p fre-target-features \
        --example host_features
}

benchmark_gate() {
    FRE_SIMD_REQUIRE_AVX512=1 \
    FRE_SIMD_BENCH_ITERS="$bench_iters" \
    FRE_SIMD_BENCH_SAMPLES="$samples" \
    FRE_SIMD_BENCH_RECEIPT_PATH="$benchmark_receipt" \
        cargo test \
            --locked --offline --release \
            -p fre-simd-kernels \
            tests::benchmark_avx2_against_avx512 \
            -- \
            --ignored --exact --nocapture
}

run_gate debug debug_gate
run_gate release release_gate
run_gate codegen codegen_gate
run_gate unsafe unsafe_gate
run_gate features features_gate
run_gate benchmark benchmark_gate

grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$staging/benchmark.log" ||
    die "benchmark test did not execute exactly once"
[[ -f "$benchmark_receipt" && ! -L "$benchmark_receipt" ]] ||
    die "benchmark did not create one regular dedicated receipt"
[[ "$(stat -c '%a' -- "$benchmark_receipt")" == 600 ]] ||
    die "benchmark dedicated receipt is not private"
[[ -f "$sentinel_receipt" && ! -L "$sentinel_receipt" ]] ||
    die "exact AVX-512 sentinel did not create one regular dedicated receipt"
[[ "$(stat -c '%a' -- "$sentinel_receipt")" == 600 ]] ||
    die "AVX-512 sentinel dedicated receipt is not private"
[[ "$(
    grep -Ec '^PASS host=x86_64-[^ ]+ assembly_sha256=[0-9a-f]{64} authenticated_leaf_sha256=[0-9a-f]{64}$' \
        "$staging/codegen.log"
)" == 1 ]] || die "codegen log lacks one native x86 authenticated leaf receipt"

python3 - "$sentinel_receipt" <<'PY'
import re
import sys

receipt_path = sys.argv[1]
with open(receipt_path, "rb") as receipt_file:
    raw_receipt = receipt_file.read()
try:
    receipt = raw_receipt.decode("ascii")
except UnicodeDecodeError as error:
    raise SystemExit(f"AVX-512 sentinel receipt is not ASCII: {error}") from error
if not receipt.endswith("\n") or receipt.count("\n") != 1:
    raise SystemExit(
        "AVX-512 sentinel receipt must be exactly one newline-terminated line"
    )
pattern = re.compile(
    r"^SIMD_AVX512_SENTINEL "
    r"variant=([^ ]+) required=([^ ]+) policy_usable=([^ ]+) "
    r"host_usable_contains_required=(true|false)$"
)
match = pattern.fullmatch(receipt[:-1])
if match is None:
    raise SystemExit("malformed AVX-512 sentinel receipt")
required = "x86.avx512f,x86.avx512bw,x86.avx512vl"
if match.groups() != (
    "ascii-byte-set.mask32.avx512f-bw-vl.v1",
    required,
    required,
    "true",
):
    raise SystemExit("AVX-512 sentinel receipt fields drifted")
PY

python3 - "$benchmark_receipt" "$staging/benchmark.json" \
    "$bench_iters" "$samples" <<'PY'
import json
import math
import re
import statistics
import sys

receipt_path, output_path, expected_iterations, expected_samples = sys.argv[1:]
with open(receipt_path, "rb") as receipt_file:
    raw_receipt = receipt_file.read()
try:
    receipt = raw_receipt.decode("ascii")
except UnicodeDecodeError as error:
    raise SystemExit(f"benchmark receipt is not ASCII: {error}") from error
if not receipt.endswith("\n") or receipt.count("\n") != 1:
    raise SystemExit("benchmark receipt must be exactly one newline-terminated line")
machine_line = receipt[:-1]
pattern = re.compile(
    r"^SIMD_X86_BENCH iterations=(\d+) samples=(\d+) "
    r"avx2_ns_per_call=([0-9.eE+-]+) "
    r"avx512_ns_per_call=([0-9.eE+-]+) "
    r"avx512_over_avx2=([0-9.eE+-]+) "
    r"orders=(\[[^\]]*\]) "
    r"avx2_samples=(\[[^\]]*\]) "
    r"avx512_samples=(\[[^\]]*\])$"
)
match = pattern.fullmatch(machine_line)
if match is None:
    raise SystemExit("malformed benchmark receipt")
iterations = int(match.group(1))
samples = int(match.group(2))
avx2_median = float(match.group(3))
avx512_median = float(match.group(4))
ratio = float(match.group(5))
orders = json.loads(match.group(6))
avx2_raw = json.loads(match.group(7))
avx512_raw = json.loads(match.group(8))
if iterations != int(expected_iterations) or iterations <= 0:
    raise SystemExit("benchmark iteration count drifted")
if samples != int(expected_samples) or samples < 15:
    raise SystemExit("benchmark sample count drifted or is below 15")
if len(orders) != samples or len(avx2_raw) != samples or len(avx512_raw) != samples:
    raise SystemExit("benchmark raw array length mismatch")
if orders != ["AB" if index % 2 == 0 else "BA" for index in range(samples)]:
    raise SystemExit("benchmark did not retain the declared AB/BA order")
if any(not math.isfinite(value) or value <= 0 for value in avx2_raw + avx512_raw):
    raise SystemExit("benchmark raw arrays contain a non-positive or non-finite value")
expected_avx2_median = statistics.median(avx2_raw)
expected_avx512_median = statistics.median(avx512_raw)
expected_ratio = expected_avx512_median / expected_avx2_median

def close(observed, expected):
    return abs(observed - expected) <= max(1e-9, abs(expected) * 2e-9)

if not close(avx2_median, expected_avx2_median):
    raise SystemExit("AVX2 median does not match its preserved raw array")
if not close(avx512_median, expected_avx512_median):
    raise SystemExit("AVX-512 median does not match its preserved raw array")
if not close(ratio, expected_ratio):
    raise SystemExit("AVX-512/AVX2 ratio does not match the preserved medians")
validated = {
    "schema": "fre-simd-x86-avx512-benchmark-v1",
    "iterations": iterations,
    "samples": samples,
    "orders": orders,
    "avx2_samples_ns_per_call": avx2_raw,
    "avx512_samples_ns_per_call": avx512_raw,
    "avx2_median_ns_per_call": avx2_median,
    "avx512_median_ns_per_call": avx512_median,
    "avx512_over_avx2": ratio,
}
with open(output_path, "x", encoding="utf-8") as output:
    json.dump(validated, output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
PY

final_commit="$(git -C "$root" rev-parse HEAD)"
final_tree="$(git -C "$root" rev-parse 'HEAD^{tree}')"
[[ "$final_commit" == "$expected_commit" && "$final_tree" == "$expected_tree" ]] ||
    die "source identity changed during qualification"
[[ -z "$(git -C "$root" status --porcelain=v1 --untracked-files=all)" ]] ||
    die "source worktree changed during qualification"

{
    printf 'schema=fre-simd-x86-avx512-final-v1\n'
    printf 'status=pass\n'
    printf 'completed_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'commit=%s\n' "$final_commit"
    printf 'tree=%s\n' "$final_tree"
    printf 'affinity=%s\n' "$affinity_list"
    printf 'mandatory_gates=debug,release,codegen,unsafe,features,benchmark\n'
    printf 'benchmark_required=true\n'
    printf 'benchmark_validated=true\n'
    printf 'avx512_sentinel_receipt_sha256=%s\n' "$(sha256_file "$sentinel_receipt")"
    printf 'benchmark_machine_receipt_sha256=%s\n' "$(sha256_file "$benchmark_receipt")"
    printf 'benchmark_sha256=%s\n' "$(sha256_file "$staging/benchmark.json")"
} >"$staging/final.env"

(
    cd "$staging"
    find . -type f ! -name SHA256SUMS -print0 |
        sort -z |
        xargs -0 sha256sum
) >"$staging/SHA256SUMS"
chmod -R a-w "$staging"
mv "$staging" "$receipts"
published=1

printf 'PASS commit=%s tree=%s receipts=%s manifest_sha256=%s\n' \
    "$final_commit" "$final_tree" "$receipts" \
    "$(sha256_file "$receipts/SHA256SUMS")"
