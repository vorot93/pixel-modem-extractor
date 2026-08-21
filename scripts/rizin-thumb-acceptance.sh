#!/usr/bin/env bash
#
# Two-model dense-Thumb acceptance matrix: mustang and cheetah, each in default
# (radare2-only) and `--rizin-fallback` mode, from one isolated release binary
# built at the audited worktree's exact HEAD.
#
# This exists because the provenance gates are the point. A transcript of shell
# commands can fall through a reused root, a missing wrapper, or a failed build
# and still look like it ran; this script fails closed on every one of them.
#
# It never touches the repository: inputs, output trees, captures, logs, and
# timing all live under the acceptance root, which must not already exist.
#
# Usage:
#   scripts/rizin-thumb-acceptance.sh \
#       --root /absolute/non-hidden/disk-backed/rizin-thumb-fallback-acceptance \
#       --mustang /absolute/path/to/mustang-radio.img \
#       --cheetah /absolute/path/to/cheetah-radio.img \
#       [--rizin /absolute/path/to/rizin] [--print-legs]
#
# `--print-legs` performs every provenance gate, prints the four leg commands,
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
mustang_img=
cheetah_img=
rizin_bin=
print_legs=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --root) accept_root=${2:-}; shift 2 ;;
        --mustang) mustang_img=${2:-}; shift 2 ;;
        --cheetah) cheetah_img=${2:-}; shift 2 ;;
        --rizin) rizin_bin=${2:-}; shift 2 ;;
        --print-legs) print_legs=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$accept_root" ] || { usage >&2; die "--root is required"; }
[ -n "$mustang_img" ] || die "--mustang is required"
[ -n "$cheetah_img" ] || die "--cheetah is required"

for tool in cargo git jq sha256sum /usr/bin/time; do
    require_command "$tool"
done

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
    */.*) die "--root must not contain a dot-prefixed component: $accept_root" ;;
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

for image in "$mustang_img" "$cheetah_img"; do
    [ -f "$image" ] || die "radio image is not a file: $image"
done

# --- Audit wrapper ------------------------------------------------------------
# One wrapper, first on PATH for every leg including the default ones, so an
# empty default log proves no discovery, no version probe, and no spawn —
# not merely that no region needed Rizin.
if [ -z "$rizin_bin" ]; then
    rizin_bin=$(command -v rizin) || die "rizin not found on PATH; pass --rizin"
fi
rizin_bin=$(readlink -f "$rizin_bin")
[ -x "$rizin_bin" ] || die "rizin is not executable: $rizin_bin"

audit_bin="$accept_root/audit-bin"
mkdir "$audit_bin"
cat >"$audit_bin/rizin" <<WRAPPER
#!/bin/sh
# Logs argv, then execs the real Rizin unchanged. Behaviour-preserving.
printf '%s\n' "\$*" >>"\$PME_RIZIN_AUDIT_LOG"
exec $rizin_bin "\$@"
WRAPPER
chmod 0755 "$audit_bin/rizin"
[ -x "$audit_bin/rizin" ] || die "audit wrapper was not created executable"

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
    printf 'rizin=%s\n' "$rizin_bin"
    printf 'recorded_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$provenance"
cat "$provenance"

tool_version=$(sed -n 's/^pkgid=.*[#@]\(.*\)$/\1/p' "$provenance")
[ -n "$tool_version" ] || die "could not derive the package version from cargo pkgid"

# The binary must actually contain this feature: a stale binary from an older
# HEAD would otherwise pass every check above.
grep -aqF -e 'pixel-modem-extractor-thumb-functions-v3' "$bin" \
    || die "the built binary lacks the strict v3 format marker"
grep -aqF -e 'aaa;aflj;pdfj @@F;axlj' "$bin" \
    || die "the built binary lacks the Rizin analysis command marker"
"$bin" decompose --help | grep -qF -- '--rizin-fallback' \
    || die "the built binary does not expose --rizin-fallback"

# --- Legs ---------------------------------------------------------------------
# Sequential by construction: a parallel run would make peak-memory and wall-time
# measurements meaningless and could contend for the same Ghidra project.
leg_command() {
    local name=$1 image=$2
    shift 2
    printf 'PATH=%q:$PATH PME_RIZIN_AUDIT_LOG=%q /usr/bin/time -v -o %q %q decompose %q --out %q%s\n' \
        "$audit_bin" "$accept_root/$name.rizin.log" "$accept_root/$name.time" \
        "$bin" "$image" "$accept_root/$name" "${*:+ $*}"
}

# Each leg's report must identify the audited binary and the exact tools before
# the next leg starts, so a mismatch cannot be discovered only at the end.
check_report() {
    local name=$1 fallback=$2
    local report="$accept_root/$name/report.json"
    [ -f "$report" ] || die "$name produced no report.json"
    local observed
    observed=$(jq -r '.tool_version' "$report")
    [ "$observed" = "$tool_version" ] \
        || die "$name report tool_version $observed does not match the audited $tool_version"
    jq -e '.ghidra.radare2 | type == "string" and length > 0' "$report" >/dev/null \
        || die "$name report lacks an exact radare2 path"
    jq -e '.ghidra.radare2_version | type == "string" and length > 0' "$report" >/dev/null \
        || die "$name report lacks an exact radare2 version"
    [ "$(jq -r '.ghidra.rizin_fallback' "$report")" = "$fallback" ] \
        || die "$name report rizin_fallback does not match the leg's mode"
    if [ "$fallback" = true ]; then
        [ "$(jq -r '.ghidra.rizin' "$report")" = "$audit_bin/rizin" ] \
            || die "$name report did not record the audit wrapper as the Rizin executable"
        jq -e '.ghidra.rizin_version | type == "string" and length > 0' "$report" >/dev/null \
            || die "$name report lacks an exact Rizin version"
    else
        [ "$(jq -r '.ghidra | has("rizin")' "$report")" = false ] \
            || die "$name is a default leg but its report names a Rizin executable"
    fi
}

# Classify the wrapper log: `-v` is a version probe, `-c` an analyzer process.
# A configured-but-unused Rizin therefore has one probe and zero analyzer calls.
check_audit_log() {
    local name=$1 fallback=$2
    local log="$accept_root/$name.rizin.log"
    if [ "$fallback" = false ]; then
        [ ! -s "$log" ] \
            || die "$name is a default leg but Rizin was discovered, probed, or spawned"
        return
    fi
    local probes analyzer
    probes=$(grep -c -- '-v' "$log" || true)
    analyzer=$(grep -c -- ' -c ' "$log" || true)
    printf '%s: rizin version probes=%s analyzer processes=%s\n' "$name" "$probes" "$analyzer"
    [ "$probes" -ge 1 ] || die "$name enabled fallback but never version-probed Rizin"
}

run_leg() {
    local name=$1 image=$2 fallback=$3
    local log="$accept_root/$name.rizin.log"
    : >"$log"
    note "leg $name (rizin_fallback=$fallback)"
    local -a argv=("$bin" decompose "$image" --out "$accept_root/$name")
    if [ "$fallback" = true ]; then
        argv+=(--rizin-fallback)
    fi
    PATH="$audit_bin:$PATH" PME_RIZIN_AUDIT_LOG="$log" \
        /usr/bin/time -v -o "$accept_root/$name.time" "${argv[@]}"
    check_report "$name" "$fallback"
    check_audit_log "$name" "$fallback"
}

if [ "$print_legs" -eq 1 ]; then
    note "leg commands (not run)"
    leg_command mustang-default "$mustang_img"
    leg_command mustang-fallback "$mustang_img" --rizin-fallback
    leg_command cheetah-default "$cheetah_img"
    leg_command cheetah-fallback "$cheetah_img" --rizin-fallback
    exit 0
fi

run_leg mustang-default "$mustang_img" false
run_leg mustang-fallback "$mustang_img" true
run_leg cheetah-default "$cheetah_img" false
run_leg cheetah-fallback "$cheetah_img" true

note "all four legs completed under $accept_root"
printf 'Compare each fresh sidecar against the retained pre-v3 tree and audit the\n'
printf 'gates in CONTRIBUTING (raw/substantial/accepted/quarantined counts, accepted\n'
printf 'execution identities, region ownership, cheetah 0x42310000, globals yield and\n'
printf 'conflicts, wall time, and maximum RSS from the .time files).\n'
