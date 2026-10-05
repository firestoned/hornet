#!/usr/bin/env bash
# Copyright (c) 2025 Erick Bourgeois, firestoned
# SPDX-License-Identifier: Apache-2.0
#
# Coverage for the BIND9 e2e suite (ADR-0002).
#
# The e2e suite drives the hornet binary from tests/e2e/run.sh, outside any
# cargo test harness, so this script handles the three steps itself. Each step
# works from files alone, so CI can split them across jobs:
#
#   build  <dir>                             instrumented hornet at <dir>/bin/hornet
#   run    <dir> <bind-version> <runtime>    run the suite once, profiles into
#                                            <dir>/profraw/
#   report <dir> <ignore-regex>              merge profiles; write <dir>/lcov.info,
#                                            <dir>/coverage.json and <dir>/html/
#
# The suite's own pass/fail is the job of `make e2e-run` with the release
# binary. `run` here never fails on a failing case: it only collects profiles.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

usage() {
    echo "usage: $0 build <dir> | run <dir> <bind-version> <runtime> | report <dir> <ignore-regex>" >&2
    exit 2
}

# llvm-profdata / llvm-cov from the rustup llvm-tools component, which matches
# the LLVM version rustc instruments with.
llvm_tool() {
    local sysroot host tool
    sysroot="$(rustc --print sysroot)"
    host="$(rustc -vV | sed -n 's/^host: //p')"
    tool="${sysroot}/lib/rustlib/${host}/bin/$1"
    if [ ! -x "${tool}" ]; then
        echo "error: ${tool} not found (rustup component add llvm-tools-preview)" >&2
        exit 1
    fi
    echo "${tool}"
}

build() {
    local dir="$1"
    local target_dir="${REPO_ROOT}/target/coverage-e2e-build"
    mkdir -p "${dir}/bin"
    # A separate target dir keeps instrumented artefacts out of target/debug.
    RUSTFLAGS="-C instrument-coverage --cfg coverage" \
        cargo build --locked --bin hornet --all-features --target-dir "${target_dir}"
    cp "${target_dir}/debug/hornet" "${dir}/bin/hornet"
    echo "instrumented hornet: ${dir}/bin/hornet"
}

run() {
    local dir="$1" version="$2" runtime="$3"
    local bin="${dir}/bin/hornet"
    if [ ! -f "${bin}" ]; then
        echo "error: ${bin} missing (make coverage-e2e-build)" >&2
        exit 1
    fi
    chmod +x "${bin}"  # artifact downloads drop the executable bit
    mkdir -p "${dir}/profraw"
    local profraw abs_bin status=0
    profraw="$(cd "${dir}/profraw" && pwd)"
    abs_bin="$(cd "$(dirname "${bin}")" && pwd)/hornet"
    LLVM_PROFILE_FILE="${profraw}/hornet-${version}-%p-%m.profraw" \
        BIND_VERSION="${version}" CONTAINER_RUNTIME="${runtime}" HORNET_BIN="${abs_bin}" \
        "${REPO_ROOT}/tests/e2e/run.sh" || status=$?
    if [ "${status}" -ne 0 ]; then
        echo "note: e2e suite exited ${status} under coverage; profiles kept, pass/fail is judged by make e2e-run"
    fi
    echo "profiles: $(find "${profraw}" -name '*.profraw' | wc -l | tr -d ' ') in ${profraw}"
}

report() {
    local dir="$1" ignore="$2"
    local bin="${dir}/bin/hornet"
    local profdata="${dir}/hornet.profdata"
    local -a profiles
    mapfile -t profiles < <(find "${dir}/profraw" -name '*.profraw' 2>/dev/null)
    if [ "${#profiles[@]}" -eq 0 ]; then
        echo "error: no .profraw files under ${dir}/profraw" >&2
        exit 1
    fi
    local profdata_tool cov_tool
    profdata_tool="$(llvm_tool llvm-profdata)"
    cov_tool="$(llvm_tool llvm-cov)"
    "${profdata_tool}" merge -sparse "${profiles[@]}" -o "${profdata}"

    # Only this repo's sources: drop the cargo registry, the Rust standard
    # library, and test-only files.
    local -a common=(
        -instr-profile="${profdata}"
        -ignore-filename-regex="/\.cargo/registry/|/\.cargo/git/|^/rustc/|/rustlib/|${ignore}"
        "${bin}"
    )
    "${cov_tool}" export -format=lcov "${common[@]}" >"${dir}/lcov.info"
    "${cov_tool}" export -format=text "${common[@]}" >"${dir}/coverage.json"
    rm -rf "${dir}/html"
    "${cov_tool}" show -format=html -output-dir="${dir}/html" \
        -show-line-counts-or-regions "${common[@]}"
    "${cov_tool}" report "${common[@]}"
}

[ "$#" -ge 2 ] || usage
cmd="$1"
shift
case "${cmd}" in
    build) build "$1" ;;
    run)
        [ "$#" -eq 3 ] || usage
        run "$1" "$2" "$3"
        ;;
    report)
        [ "$#" -eq 2 ] || usage
        report "$1" "$2"
        ;;
    *) usage ;;
esac
