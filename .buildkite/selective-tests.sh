#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"; shift || true

if [[ -z "${mode}" ]]; then
    echo "Usage: selective-tests.sh <mode> [args...]" >&2
    exit 1
fi

# Determine changed files compared to main
if git fetch origin main >/dev/null 2>&1; then
    changed_files=$(git diff --name-only origin/main...HEAD || true)
else
    changed_files=$(git diff --name-only HEAD~1..HEAD || true)
fi

if [[ -z "${changed_files}" ]]; then
    # No diff detected, run full workspace tests to be safe
    changed_files="__none__"
fi

workspace_changed=0

# Files that we consider "workspace-wide" changes
for f in ${changed_files}; do
    case "${f}" in
        Cargo.toml|Cargo.lock|rustfmt.toml|.buildkite/*|xtask/*)
            workspace_changed=1
            ;;
    esac
done

# Map paths to crates
crates=(
    vhost-device-can
    vhost-device-console
    vhost-device-gpio
    vhost-device-gpu
    vhost-device-i2c
    vhost-device-input
    vhost-device-rng
    vhost-device-scsi
    vhost-device-scmi
    vhost-device-sound
    vhost-device-spi
    vhost-device-template
    vhost-device-vsock
)

affected_crates=()
for f in ${changed_files}; do
    for c in "${crates[@]}"; do
        case "${f}" in
            "${c}"/*)
                affected_crates+=("${c}")
                ;;
        esac
    done
done

# Unique affected crates
if ((${#affected_crates[@]} > 0)); then
    mapfile -t affected_crates < <(printf '%s
' "${affected_crates[@]}" | sort -u)
fi

run_full_workspace=0
if [[ "${workspace_changed}" -eq 1 || ${#affected_crates[@]} -eq 0 ]]; then
    run_full_workspace=1
fi

cmd=(cargo test)

case "${mode}" in
    unittests-gnu)
        cmd+=(--all-features)
        ;;
    unittests-gnu-release)
        cmd+=(--release --all-features)
        ;;
    unittests-musl)
        target_platform="${1:-}"; shift || true
        if [[ -z "${target_platform:-}" ]]; then
            echo "target_platform argument required for unittests-musl" >&2
            exit 1
        fi
        cmd+=(--all-features --target "${target_platform}-unknown-linux-musl")
        ;;
    unittests-musl-release)
        target_platform="${1:-}"; shift || true
        if [[ -z "${target_platform:-}" ]]; then
            echo "target_platform argument required for unittests-musl-release" >&2
            exit 1
        fi
        cmd+=(--release --all-features --target "${target_platform}-unknown-linux-musl")
        ;;
    *)
        echo "Unknown mode: ${mode}" >&2
        exit 1
        ;;
esac

if [[ "${run_full_workspace}" -eq 1 ]]; then
    # Preserve previous behaviour: run on entire workspace.
    if [[ "${mode}" == "unittests-musl" || "${mode}" == "unittests-musl-release" ]]; then
        # Original musl commands excluded vhost-device-gpu.
        cmd+=(--workspace --exclude vhost-device-gpu)
    else
        cmd+=(--workspace)
    fi
else
    # Run only for affected crates. For musl jobs, skip vhost-device-gpu as before.
    for c in "${affected_crates[@]}"; do
        if [[ "${mode}" == unittests-musl* && "${c}" == "vhost-device-gpu" ]]; then
            continue
        fi
        cmd+=(-p "${c}")
    done

    if ((${#affected_crates[@]} == 0)); then
        # Nothing to run
        echo "No affected crates to test; exiting." >&2
        exit 0
    fi
fi

exec "${cmd[@]}"
