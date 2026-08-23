#!/usr/bin/env bash
#
# PAL task release acceptance: both retained MAIN proof corpora through the
# pre-implementation semantic validator, and both retained radio images
# through fresh release-mode decompose runs in tighten and datamark modes,
# from one isolated release binary built at the audited worktree's exact
# HEAD.
#
# This exists because the provenance gates are the point. A transcript of
# shell commands can fall through a reused root, a missing input, or a
# failed build and still look like it ran; this script fails closed on every
# one of them. A missing input means that named release gate is UNRUN,
# never passed: by default the script refuses to start, and --partial runs
# only the gates whose inputs are present while printing every unrun gate.
#
# It never touches the repository: inputs, output trees, logs, and timing
# all live under the acceptance root, which must not already exist.
#
# Usage:
#   scripts/pal-acceptance.sh \
#       --root /absolute/non-hidden/disk-backed/pal-acceptance \
#       --mustang-main /absolute/path/to/s5400/MAIN.bin \
#       --cheetah-main /absolute/path/to/s5300/MAIN.bin \
#       --mustang-radio /absolute/path/to/mustang-radio.img \
#       --cheetah-radio /absolute/path/to/cheetah-radio.img \
#       [--semantic-script /absolute/path/to/semantic-validation.rs] \
#       [--partial] [--print-legs]
#
# `--print-legs` performs every provenance gate, prints the leg commands,
# and exits without running them.

set -euo pipefail

die() {
    printf 'acceptance: %s\n' "$*" >&2
    exit 1
}

note() {
    printf '\n=== %s\n' "$*"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

usage() {
    awk 'NR < 3 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "${BASH_SOURCE[0]}"
}

accept_root=
mustang_main=
cheetah_main=
mustang_radio=
cheetah_radio=
semantic_script="${PME_SEMANTIC_SCRIPT:-$HOME/.superpowers/pixel-modem-extractor/2026-08-20-pal-task-semantic-validation.rs}"
partial=0
print_legs=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root) accept_root=${2:-}; shift 2 ;;
        --mustang-main) mustang_main=${2:-}; shift 2 ;;
        --cheetah-main) cheetah_main=${2:-}; shift 2 ;;
        --mustang-radio) mustang_radio=${2:-}; shift 2 ;;
        --cheetah-radio) cheetah_radio=${2:-}; shift 2 ;;
        --semantic-script) semantic_script=${2:-}; shift 2 ;;
        --partial) partial=1; shift ;;
        --print-legs) print_legs=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$accept_root" ] || { usage >&2; die "--root is required"; }

# A named gate is unrun, never passed, when its input is missing. The
# resolver sets GATE_VALUE on success; command substitution would swallow
# the unrun bookkeeping, so callers read the global instead.
GATE_VALUE=
unrun=()
gate_input() {
    local name=$1 value=$2
    GATE_VALUE=
    if [ -n "$value" ] && [ -f "$value" ]; then
        GATE_VALUE=$value
        return 0
    fi
    if [ -n "$value" ] && [ ! -f "$value" ]; then
        die "$name input is not a readable file: $value"
    fi
    unrun+=("$name")
    return 1
}

gate_input proof-s5400 "$mustang_main" && mustang_main=$GATE_VALUE || mustang_main=
gate_input proof-s5300 "$cheetah_main" && cheetah_main=$GATE_VALUE || cheetah_main=
gate_input s5400-decompose "$mustang_radio" && mustang_radio=$GATE_VALUE || mustang_radio=
gate_input s5300-decompose "$cheetah_radio" && cheetah_radio=$GATE_VALUE || cheetah_radio=

if [ "${#unrun[@]}" -gt 0 ] && [ "$partial" -eq 0 ]; then
    printf 'acceptance: refusing to run with unrun gates (pass --partial to run the subset):\n' >&2
    printf '  UNRUN %s\n' "${unrun[@]}" >&2
    exit 1
fi

for tool in cargo git jq sha256sum /usr/bin/time rust-script; do
    require_command "$tool"
done

if [ -n "$mustang_main" ] || [ -n "$cheetah_main" ]; then
    [ -f "$semantic_script" ] \
        || die "the semantic-validation script is missing: $semantic_script (override with --semantic-script)"
fi

# --- The audited worktree -----------------------------------------------------
# `--manifest-path` is anchored here rather than to the caller's directory, so
# the binary provably comes from the worktree holding this script.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel) \
    || die "this script must live inside the worktree under acceptance"
manifest="$repo_root/Cargo.toml"
[ -f "$manifest" ] || die "no Cargo.toml at $repo_root"

# --- Acceptance root ----------------------------------------------------------
case "$accept_root" in
    /*) ;;
    *) die "--root must be absolute: $accept_root" ;;
esac
case "$accept_root" in
    /tmp/*|/tmp) die "--root must be disk-backed, not under /tmp: $accept_root" ;;
esac
case "$accept_root" in
    "$repo_root"|"$repo_root"/*) die "--root must lie outside the repository" ;;
esac
if [ -e "$accept_root" ]; then
    die "--root must not already exist (a reused root is invalid provenance): $accept_root"
fi
# `mkdir` without -p: creating an existing root is an error, and the parent must
# already be there so a typo cannot fabricate a tree.
mkdir "$accept_root" || die "could not create a fresh acceptance root: $accept_root"

# --- Isolated build -----------------------------------------------------------
# A shared `target/` can be overwritten by another worktree, so the release
# binary is built into the acceptance root and `--locked` pins the lockfile.
note "building the audited binary"
CARGO_TARGET_DIR="$accept_root/cargo-target" \
    cargo build --release --locked --manifest-path "$manifest"
bin="$accept_root/cargo-target/release/pixel-modem-extractor"
[ -x "$bin" ] || die "the isolated build produced no binary at $bin"

# --- Provenance record --------------------------------------------------------
provenance="$accept_root/provenance.txt"
note "recording provenance -> $provenance"
{
    printf 'repo_root=%s\n' "$repo_root"
    printf 'head=%s\n' "$(git -C "$repo_root" rev-parse HEAD)"
    printf 'worktree_diff_sha256=%s\n' \
        "$(git -C "$repo_root" diff --binary HEAD | sha256sum | cut -d' ' -f1)"
    printf 'pkgid=%s\n' "$(cargo pkgid --manifest-path "$manifest")"
    printf 'binary=%s\n' "$(readlink -f "$bin")"
    printf 'binary_sha256=%s\n' "$(sha256sum "$bin" | cut -d' ' -f1)"
    printf 'semantic_script=%s\n' "$semantic_script"
    printf 'recorded_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$provenance"
cat "$provenance"

tool_version=$(sed -n 's/^pkgid=.*[#@]\(.*\)$/\1/p' "$provenance")
[ -n "$tool_version" ] || die "could not derive the package version from cargo pkgid"

# The binary must actually contain this feature: a stale binary from an older
# HEAD would otherwise pass every check above.
grep -aqF -e 'pal_TaskEntry_' "$bin" \
    || die "the built binary lacks the PAL task label marker"
grep -aqF -e 'pixel-modem-extractor-pal-tasks-v1' "$bin" \
    || die "the built binary lacks the PAL manifest format marker"
"$bin" decompose --help | grep -qF -- '--no-thumb-decompile' \
    || die "the built binary does not expose --no-thumb-decompile"

# --- Proof-corpus legs --------------------------------------------------------
# The pre-implementation research proof, run outside Git against the exact
# retained MAIN slices. It re-derives the initializer and table semantically;
# the expected task counts are the corrected corpus baseline.
run_proof_leg() {
    local name=$1 input=$2 expected_tasks=$3
    note "leg $name (semantic proof, expected $expected_tasks tasks)"
    local out_txt="$accept_root/$name.out.txt"
    rust-script "$semantic_script" "$input" 0x40010000 \
        | tee "$out_txt"
    # The proof prints `tasks=<n> ... arm_entries=<n> thumb_entries=<n>`;
    # every corpus entry is Thumb, so all three counts must agree.
    grep -qF -e "tasks=$expected_tasks " "$out_txt" \
        || die "$name semantic proof did not report tasks=$expected_tasks"
    grep -qF -e "arm_entries=0 " "$out_txt" \
        || die "$name semantic proof did not report arm_entries=0"
    grep -qF -e "thumb_entries=$expected_tasks" "$out_txt" \
        || die "$name semantic proof did not report thumb_entries=$expected_tasks"
}

# --- Decompose legs -----------------------------------------------------------
# Expected per-model facts: the MAIN split label and the corrected task count.
run_decompose_leg() {
    local name=$1 image=$2 main_label=$3 expected_tasks=$4
    shift 4
    note "leg $name (decompose, MAIN=$main_label, expected $expected_tasks tasks)"
    local -a argv=("$bin" decompose "$image" --out "$accept_root/$name")
    local mode=tighten
    local arg
    for arg in "$@"; do
        argv+=("$arg")
        [ "$arg" = "--no-thumb-decompile" ] && mode=datamark
    done
    /usr/bin/time -v -o "$accept_root/$name.time" "${argv[@]}"

    local report="$accept_root/$name/report.json"
    [ -f "$report" ] || die "$name produced no report.json"
    local observed
    observed=$(jq -r '.tool_version' "$report")
    [ "$observed" = "$tool_version" ] \
        || die "$name report tool_version $observed does not match the audited $tool_version"

    local row
    row=$(jq -c --arg label "$main_label" \
        '.images[] | select(.label == $label)' "$report")
    [ -n "$row" ] || die "$name report has no image row for $main_label"
    local tasks entries shared tighten_error
    tasks=$(jq -r '.pal_tasks // "missing"' <<<"$row")
    entries=$(jq -r '.pal_entries // "missing"' <<<"$row")
    shared=$(jq -r '.pal_shared_entries // "missing"' <<<"$row")
    tighten_error=$(jq -r '.thumb_tighten_error // empty' <<<"$row")
    [ "$tasks" = "$expected_tasks" ] \
        || die "$name MAIN pal_tasks is '$tasks', expected $expected_tasks"
    [ "$entries" = "$expected_tasks" ] \
        || die "$name MAIN pal_entries is '$entries', expected $expected_tasks"
    [ "$shared" = "0" ] \
        || die "$name MAIN pal_shared_entries is '$shared', expected 0 (corpus entries are unique)"
    if [ "$mode" = tighten ] && [ -n "$tighten_error" ]; then
        die "$name is a tighten leg but its MAIN row reports thumb_tighten_error: $tighten_error"
    fi

    jq -e 'any(.stages[]?; .stage == "pal_tasks" and .status == "ok")' \
        "$report" >/dev/null \
        || die "$name pal_tasks stage is missing, skipped, or failed"

    local manifest_path="$accept_root/$name/images/$main_label/pal_tasks/tasks.json"
    [ -f "$manifest_path" ] || die "$name has no terminal PAL manifest at $manifest_path"
    local manifest_tasks manifest_apps
    manifest_tasks=$(jq '.tasks | length' "$manifest_path")
    manifest_apps=$(jq '.applications | length' "$manifest_path")
    [ "$manifest_tasks" = "$expected_tasks" ] \
        || die "$name terminal manifest has $manifest_tasks tasks, expected $expected_tasks"
    [ "$manifest_apps" = "$expected_tasks" ] \
        || die "$name terminal manifest has $manifest_apps applications, expected $expected_tasks"

    printf '%s: pal tasks=%s entries=%s shared=%s manifest=%s time/RSS in %s.time\n' \
        "$name" "$tasks" "$entries" "$shared" "$manifest_tasks" "$accept_root/$name"
}

leg_summary() {
    printf '\n'
    printf 'gate summary:\n'
    local name
    local -a attempted=()
    [ -n "$mustang_main" ] && attempted+=(proof-s5400)
    [ -n "$cheetah_main" ] && attempted+=(proof-s5300)
    [ -n "$mustang_radio" ] && attempted+=(s5400-tighten s5400-datamark)
    [ -n "$cheetah_radio" ] && attempted+=(s5300-tighten s5300-datamark)
    for name in proof-s5400 proof-s5300 s5400-tighten s5400-datamark s5300-tighten s5300-datamark; do
        local attempted_name
        for attempted_name in "${attempted[@]}"; do
            [ "$attempted_name" = "$name" ] && break
            attempted_name=
        done
        if [ -z "${attempted_name:-}" ]; then
            printf '  UNRUN     %s (missing input; never passed)\n' "$name"
        elif [ "$print_legs" -eq 1 ]; then
            printf '  printed   %s (command only; --print-legs runs nothing)\n' "$name"
        else
            printf '  completed %s\n' "$name"
        fi
    done
    printf 'Review the .time files for wall time and peak RSS before signing off.\n'
}

if [ "$print_legs" -eq 1 ]; then
    note "leg commands (not run)"
    [ -n "$mustang_main" ] && printf 'rust-script %q %q 0x40010000\n' "$semantic_script" "$mustang_main"
    [ -n "$cheetah_main" ] && printf 'rust-script %q %q 0x40010000\n' "$semantic_script" "$cheetah_main"
    [ -n "$mustang_radio" ] && printf '/usr/bin/time -v -o %q %q decompose %q --out %q\n' \
        "$accept_root/s5400-tighten.time" "$bin" "$mustang_radio" "$accept_root/s5400-tighten"
    [ -n "$mustang_radio" ] && printf '/usr/bin/time -v -o %q %q decompose %q --out %q --no-thumb-decompile\n' \
        "$accept_root/s5400-datamark.time" "$bin" "$mustang_radio" "$accept_root/s5400-datamark"
    [ -n "$cheetah_radio" ] && printf '/usr/bin/time -v -o %q %q decompose %q --out %q\n' \
        "$accept_root/s5300-tighten.time" "$bin" "$cheetah_radio" "$accept_root/s5300-tighten"
    [ -n "$cheetah_radio" ] && printf '/usr/bin/time -v -o %q %q decompose %q --out %q --no-thumb-decompile\n' \
        "$accept_root/s5300-datamark.time" "$bin" "$cheetah_radio" "$accept_root/s5300-datamark"
    leg_summary
    exit 0
fi

[ -n "$mustang_main" ] && run_proof_leg proof-s5400 "$mustang_main" 133
[ -n "$cheetah_main" ] && run_proof_leg proof-s5300 "$cheetah_main" 162
[ -n "$mustang_radio" ] && run_decompose_leg s5400-tighten "$mustang_radio" 02_MAIN 133
[ -n "$mustang_radio" ] && run_decompose_leg s5400-datamark "$mustang_radio" 02_MAIN 133 --no-thumb-decompile
[ -n "$cheetah_radio" ] && run_decompose_leg s5300-tighten "$cheetah_radio" 01_MAIN 162
[ -n "$cheetah_radio" ] && run_decompose_leg s5300-datamark "$cheetah_radio" 01_MAIN 162 --no-thumb-decompile

note "all requested legs completed under $accept_root"
leg_summary
