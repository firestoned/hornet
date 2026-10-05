#!/usr/bin/env bash
# Copyright (c) 2025 Erick Bourgeois, firestoned
# SPDX-License-Identifier: Apache-2.0
#
# Render an llvm-cov JSON export as a Markdown table (ADR-0002), for
# $GITHUB_STEP_SUMMARY or a terminal:
#
#   scripts/coverage-summary.sh <coverage.json> <title> [lcov.info]
#
# One row per source file with line, function and region coverage, a totals
# row, and, when an LCOV file is given, the missed line numbers of every file
# below 100% (as ranges, capped so one bad file cannot flood the summary).
# Works on both `cargo llvm-cov report --json` and `llvm-cov export
# -format=text` output, which share a schema.

set -euo pipefail

# Longest missed-lines string shown per file before it is truncated.
MAX_MISSED_CHARS=300

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <coverage.json> <title> [lcov.info]" >&2
    exit 2
fi
JSON="$1"
TITLE="$2"
LCOV="${3:-}"

if ! command -v jq >/dev/null 2>&1; then
    echo "error: jq is required" >&2
    exit 1
fi
if [ ! -s "${JSON}" ]; then
    echo "error: ${JSON} not found or empty" >&2
    exit 1
fi

# Paths in the export are absolute and differ between machines; show them from
# the first src/, tests/ or benches/ component on.
REL_FILTER='def rel: if test("/(src|tests|benches)/") then capture("/(?<p>(src|tests|benches)/.*)$").p else . end;'

echo "### ${TITLE}"
echo
jq -r "${REL_FILTER}"'
    def pct(s): if s.count == 0 then "n/a" else "\(s.percent * 100 | round / 100)%" end;
    def mark(s): if s.count == 0 or s.covered == s.count then "" else " ⚠️" end;
    "| File | Lines | Functions | Regions |",
    "|---|---:|---:|---:|",
    (.data[0].files | sort_by(.filename)[] |
        "| `\(.filename | rel)`\(mark(.summary.lines)) | \(pct(.summary.lines)) (\(.summary.lines.covered)/\(.summary.lines.count)) | \(pct(.summary.functions)) (\(.summary.functions.covered)/\(.summary.functions.count)) | \(pct(.summary.regions)) (\(.summary.regions.covered)/\(.summary.regions.count)) |"),
    (.data[0].totals |
        "| **Total** | **\(pct(.lines))** (\(.lines.covered)/\(.lines.count)) | **\(pct(.functions))** (\(.functions.covered)/\(.functions.count)) | **\(pct(.regions))** (\(.regions.covered)/\(.regions.count)) |")
' "${JSON}"

if [ -z "${LCOV}" ] || [ ! -s "${LCOV}" ]; then
    exit 0
fi

# Missed lines per file from the LCOV DA records (DA:<line>,<hits>), collapsed
# into ranges.
missed="$(awk -v max="${MAX_MISSED_CHARS}" '
    function rel(path) {
        if (match(path, /\/(src|tests|benches)\//)) return substr(path, RSTART + 1)
        return path
    }
    function flush(   out, i, start, prev) {
        if (file == "" || n == 0) return
        out = ""
        start = lines[1]; prev = lines[1]
        for (i = 2; i <= n + 1; i++) {
            if (i <= n && lines[i] == prev + 1) { prev = lines[i]; continue }
            out = out (out == "" ? "" : ", ") (start == prev ? start : start "-" prev)
            if (i <= n) { start = lines[i]; prev = lines[i] }
        }
        if (length(out) > max) out = substr(out, 1, max) "..."
        printf "| `%s` | %d | %s |\n", rel(file), n, out
    }
    /^SF:/ { file = substr($0, 4); n = 0; delete lines; delete seen; next }
    /^DA:/ {
        split(substr($0, 4), f, ",")
        if (f[2] == 0 && !(f[1] in seen)) { seen[f[1]] = 1; lines[++n] = f[1] + 0 }
        next
    }
    /^end_of_record/ {
        # DA records are not guaranteed sorted; insertion-sort the few misses.
        for (i = 2; i <= n; i++) {
            v = lines[i]; j = i - 1
            while (j >= 1 && lines[j] > v) { lines[j + 1] = lines[j]; j-- }
            lines[j + 1] = v
        }
        flush(); file = ""
    }
' "${LCOV}" | sort)"

echo
if [ -z "${missed}" ]; then
    echo "No missed lines."
    exit 0
fi
echo "<details><summary>Missed lines</summary>"
echo
echo "| File | Missed | Lines |"
echo "|---|---:|---|"
echo "${missed}"
echo
echo "</details>"
