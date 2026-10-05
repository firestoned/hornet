#!/usr/bin/env bash
# Copyright (c) 2025 Erick Bourgeois, firestoned
# SPDX-License-Identifier: Apache-2.0
#
# End-to-end round-trip of the hornet CLI against real BIND9 as the oracle.
#
# For every fixture under tests/e2e/fixtures/ this runs, against the ISC
# BIND9 image for $BIND_VERSION:
#
#   named.conf fixtures (fixtures/named-conf/*.conf)
#     bind-accepts-original   named-checkconf accepts the fixture itself
#     bind-accepts-parse      named-checkconf accepts `hornet parse` output
#     semantic-equivalent     `named-checkconf -p` of fixture and of hornet's
#                             output are identical (BIND's canonical print)
#     idempotent              `hornet parse` of hornet's output is unchanged
#     bind-accepts-convert    named-checkconf accepts `hornet convert` output
#     hornet-check-no-errors  `hornet check` reports no errors on the fixture
#     fmt-matches-parse       `hornet fmt` in place writes what `parse` prints
#     fmt-check-clean         `hornet fmt --check` passes on formatted output
#     convert-in-place        `convert --in-place` writes what `convert` prints
#
#   zone fixtures (fixtures/zones/<origin>.zone)
#     bind-accepts-original   named-checkzone accepts the fixture itself
#     bind-accepts-zone       named-checkzone accepts `hornet zone` output
#     semantic-equivalent     named-compilezone's canonical dump of fixture and
#                             of hornet's output are identical
#     idempotent              `hornet zone` of hornet's output is unchanged
#     hornet-check-zone-no-errors
#                             `hornet check-zone` reports no errors on it
#
# Known failures live in tests/e2e/known-failures.txt, one per line, with a
# reason. A listed case that fails is reported XFAIL; a listed case that
# passes is reported XPASS and fails the run, so the list cannot go stale.
#
# Environment:
#   BIND_VERSION       ISC image tag to test against (default 9.20)
#   HORNET_BIN         hornet binary (default target/release/hornet)
#   CONTAINER_RUNTIME  docker or podman (default docker)
#   BIND_IMAGE         full image reference (default derived from BIND_VERSION)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FIXTURES="${SCRIPT_DIR}/fixtures"
KNOWN_FAILURES="${SCRIPT_DIR}/known-failures.txt"

BIND_VERSION="${BIND_VERSION:-9.20}"
HORNET_BIN="${HORNET_BIN:-${REPO_ROOT}/target/release/hornet}"
CONTAINER_RUNTIME="${CONTAINER_RUNTIME:-docker}"
BIND_IMAGE="${BIND_IMAGE:-docker.io/internetsystemsconsortium/bind9:${BIND_VERSION}}"

if [ ! -x "${HORNET_BIN}" ]; then
    echo "error: hornet binary not found at ${HORNET_BIN} (run 'make build-release' or set HORNET_BIN)" >&2
    exit 1
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/hornet-e2e.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT
mkdir -p "${WORK}/in" "${WORK}/out"
cp -R "${FIXTURES}/." "${WORK}/in/"
chmod -R a+rX "${WORK}"

PASS=0
FAIL=0
XFAIL=0
XPASS=0
FAILED_CASES=""

# Run a BIND9 tool inside the ISC image with the work dir mounted read-only.
bind_tool() {
    local tool="$1"
    shift
    "${CONTAINER_RUNTIME}" run --rm --network none \
        -v "${WORK}:/w:ro,Z" -w /w \
        --entrypoint "${tool}" "${BIND_IMAGE}" "$@"
}

# Is <fixture> <check> listed as a known failure for this BIND version?
is_known_failure() {
    local fixture="$1" check="$2"
    [ -f "${KNOWN_FAILURES}" ] || return 1
    awk -v v="${BIND_VERSION}" -v f="${fixture}" -v c="${check}" '
        /^[[:space:]]*(#|$)/ { next }
        ($1 == "*" || $1 == v) && $2 == f && $3 == c { found = 1 }
        END { exit found ? 0 : 1 }
    ' "${KNOWN_FAILURES}"
}

# record <fixture> <check> <exit-status> [log-file]
record() {
    local fixture="$1" check="$2" status="$3" log="${4:-}"
    if is_known_failure "${fixture}" "${check}"; then
        if [ "${status}" -eq 0 ]; then
            XPASS=$((XPASS + 1))
            FAILED_CASES="${FAILED_CASES}\n  XPASS ${fixture} ${check} (remove it from known-failures.txt)"
            echo "XPASS ${fixture} ${check}"
        else
            XFAIL=$((XFAIL + 1))
            echo "XFAIL ${fixture} ${check}"
        fi
        return 0
    fi
    if [ "${status}" -eq 0 ]; then
        PASS=$((PASS + 1))
        echo "PASS  ${fixture} ${check}"
        return 0
    fi
    FAIL=$((FAIL + 1))
    FAILED_CASES="${FAILED_CASES}\n  FAIL  ${fixture} ${check}"
    echo "FAIL  ${fixture} ${check}"
    if [ -n "${log}" ] && [ -s "${log}" ]; then
        sed 's/^/      | /' "${log}"
    fi
}

# check <fixture> <check> <command...>: run a command, record its status.
check() {
    local fixture="$1" check_name="$2"
    shift 2
    local log="${WORK}/log"
    local status=0
    "$@" >"${log}" 2>&1 || status=$?
    record "${fixture}" "${check_name}" "${status}" "${log}"
}

# BIND keeps the legacy keyword spelling in `named-checkconf -p`, while
# hornet's writer emits the modern synonyms (master/slave/masters are the
# documented aliases of primary/secondary/primaries). Map both sides onto the
# modern spelling so the comparison is semantic, not lexical.
normalize_keywords() {
    sed -E \
        -e 's/^([[:space:]]*)type master;/\1type primary;/' \
        -e 's/^([[:space:]]*)type slave;/\1type secondary;/' \
        -e 's/^([[:space:]]*)masters /\1primaries /' \
        "$1" >"$1.norm"
    mv "$1.norm" "$1"
}

# diff_check <fixture> <check> <file-a> <file-b>
diff_check() {
    check "$1" "$2" diff -u "$3" "$4"
}

echo "hornet e2e: $("${HORNET_BIN}" --version) against ${BIND_IMAGE}"
bind_tool named -v
echo

# ── named.conf fixtures ─────────────────────────────────────────────────────
for src in "${WORK}"/in/named-conf/*.conf; do
    name="$(basename "${src}")"
    rel_in="in/named-conf/${name}"
    parsed="${WORK}/out/${name}.parse"
    reparsed="${WORK}/out/${name}.reparse"
    converted="${WORK}/out/${name}.convert"
    canon_in="${WORK}/out/${name}.canon-in"
    canon_out="${WORK}/out/${name}.canon-out"

    check "${name}" bind-accepts-original bind_tool named-checkconf "${rel_in}"

    status=0
    "${HORNET_BIN}" parse "${src}" >"${parsed}" 2>"${WORK}/log" || status=$?
    if [ "${status}" -ne 0 ]; then
        record "${name}" hornet-parse "${status}" "${WORK}/log"
        continue
    fi
    chmod a+r "${parsed}"

    check "${name}" bind-accepts-parse bind_tool named-checkconf "out/${name}.parse"

    bind_tool named-checkconf -p "${rel_in}" >"${canon_in}" 2>&1 || true
    bind_tool named-checkconf -p "out/${name}.parse" >"${canon_out}" 2>&1 || true
    normalize_keywords "${canon_in}"
    normalize_keywords "${canon_out}"
    diff_check "${name}" semantic-equivalent "${canon_in}" "${canon_out}"

    "${HORNET_BIN}" parse "${parsed}" >"${reparsed}" 2>&1 || true
    diff_check "${name}" idempotent "${parsed}" "${reparsed}"

    "${HORNET_BIN}" convert "${src}" >"${converted}" 2>"${WORK}/log" || true
    chmod a+r "${converted}"
    check "${name}" bind-accepts-convert bind_tool named-checkconf "out/${name}.convert"

    # hornet's validator raises no errors on a config BIND9 accepts.
    check "${name}" hornet-check-no-errors \
        "${HORNET_BIN}" check --allow-warnings --min-severity error "${src}"

    # `fmt` rewrites in place to exactly what `parse` prints, and `fmt --check`
    # then reports the file as already formatted.
    fmt_copy="${WORK}/out/${name}.fmt"
    cp "${src}" "${fmt_copy}"
    "${HORNET_BIN}" fmt "${fmt_copy}" >"${WORK}/log" 2>&1 || true
    diff_check "${name}" fmt-matches-parse "${parsed}" "${fmt_copy}"
    check "${name}" fmt-check-clean "${HORNET_BIN}" fmt --check "${fmt_copy}"

    # `convert --in-place` writes exactly what `convert` prints.
    conv_copy="${WORK}/out/${name}.convert-in-place"
    cp "${src}" "${conv_copy}"
    "${HORNET_BIN}" convert --in-place "${conv_copy}" >"${WORK}/log" 2>&1 || true
    diff_check "${name}" convert-in-place "${converted}" "${conv_copy}"
done

# ── zone fixtures: fixtures/zones/<origin>.zone ─────────────────────────────
for src in "${WORK}"/in/zones/*.zone; do
    name="$(basename "${src}")"
    origin="${name%.zone}"
    rel_in="in/zones/${name}"
    written="${WORK}/out/${name}.zone-out"
    rewritten="${WORK}/out/${name}.zone-reout"
    canon_in="${WORK}/out/${name}.canon-in"
    canon_out="${WORK}/out/${name}.canon-out"

    check "${name}" bind-accepts-original bind_tool named-checkzone "${origin}" "${rel_in}"

    status=0
    "${HORNET_BIN}" zone "${src}" >"${written}" 2>"${WORK}/log" || status=$?
    if [ "${status}" -ne 0 ]; then
        record "${name}" hornet-zone "${status}" "${WORK}/log"
        continue
    fi
    chmod a+r "${written}"

    check "${name}" bind-accepts-zone bind_tool named-checkzone "${origin}" "out/${name}.zone-out"

    bind_tool named-compilezone -q -o - "${origin}" "${rel_in}" >"${canon_in}" 2>&1 || true
    bind_tool named-compilezone -q -o - "${origin}" "out/${name}.zone-out" >"${canon_out}" 2>&1 || true
    diff_check "${name}" semantic-equivalent "${canon_in}" "${canon_out}"

    "${HORNET_BIN}" zone "${written}" >"${rewritten}" 2>&1 || true
    diff_check "${name}" idempotent "${written}" "${rewritten}"

    # hornet's zone validator raises no errors on a zone BIND9 accepts.
    check "${name}" hornet-check-zone-no-errors \
        "${HORNET_BIN}" check-zone --allow-warnings "${src}"
done

echo
echo "BIND ${BIND_VERSION}: ${PASS} passed, ${FAIL} failed, ${XFAIL} known failures, ${XPASS} unexpected passes"
if [ "${FAIL}" -ne 0 ] || [ "${XPASS}" -ne 0 ]; then
    printf "%b\n" "${FAILED_CASES}"
    exit 1
fi
