#!/usr/bin/env bash
# Record a release manifest: which engine binary was verified against which
# golden set at which ssa-qa commit. The manifest is the rollback anchor — to
# reproduce or roll back, check out the recorded ssa_qa_commit (which holds the
# exact goldens) and verify the recorded binary_sha256.
#
# Usage:
#   scripts/record-release.sh --binary /path/to/yak-ssa [--out versions]
#
# Exits non-zero (and records nothing) if `ssa-qa verify` fails, so a manifest
# only ever describes a binary that actually passed the gate. Pass --allow-fail
# to record a failing run for debugging (verified=false).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BINARY=""
OUT="$ROOT/versions"
ALLOW_FAIL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --binary) BINARY="${2:?--binary needs a path}"; shift 2 ;;
    --out) OUT="${2:?--out needs a dir}"; shift 2 ;;
    --allow-fail) ALLOW_FAIL=1; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$BINARY" ]; then
  echo "error: --binary <path> is required" >&2
  exit 2
fi
BINARY="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
if [ ! -f "$BINARY" ]; then
  echo "error: binary not found: $BINARY" >&2
  exit 2
fi

sha256() { sha256sum "$1" | awk '{print $1}'; }
# Portable relative path (repo root may move; keep it readable, not machine-bound).
# Always emit forward slashes so the value is stable across platforms and safe
# to embed in JSON (Windows backslashes would otherwise be invalid escapes).
rel() { python - "$ROOT" "$1" <<'PY' 2>/dev/null || echo "$1"
import os,sys
try: print(os.path.relpath(sys.argv[2], sys.argv[1]).replace(os.sep,"/"))
except Exception: print(sys.argv[2])
PY
}

cd "$ROOT"

echo "== building ssa-qa =="
BINBIN="$(mktemp -d)"
trap 'rm -rf "$BINBIN"' EXIT
go build -o "$BINBIN/ssa-qa" ./cmd/ssa-qa

echo "== verifying engine binary: $BINARY =="
verified=true
if ! "$BINBIN/ssa-qa" verify --binary "$BINARY" --root "$ROOT"; then
  verified=false
  if [ "$ALLOW_FAIL" -eq 0 ]; then
    echo "error: verify FAILED; refusing to record a release manifest." >&2
    echo "       (fix the drift or re-run update-golden --confirm with review)" >&2
    exit 1
  fi
  echo "WARN: verify failed; recording with verified=false (--allow-fail)" >&2
fi

engine_version="$("$BINARY" -v 2>/dev/null | awk '{print $NF}' | head -1)"
[ -n "$engine_version" ] || engine_version="unknown"

binary_hash="$(sha256 "$BINARY")"
# Golden-set identity: hash of the sorted per-file digests.
golden_hash="$(
  { for f in $(ls goldens/*.json 2>/dev/null | sort); do printf '%s  %s\n' "$(sha256 "$f")" "$(basename "$f")"; done; } \
  | sha256sum | awk '{print $1}'
)"
qa_commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
recorded_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
case_names="$(ls -d cases/*/ 2>/dev/null | xargs -n1 basename | sort | paste -sd, -)"

short="${binary_hash:0:12}"
mkdir -p "$OUT"
manifest="$OUT/${engine_version}-${short}.json"

# Emit the manifest entirely in Python so paths (Windows backslashes) and the
# comma-joined case list are escaped correctly. A hand-rolled heredoc mangles
# Windows paths into invalid \escape sequences and cannot build a JSON array.
REL_BIN="$(rel "$BINARY")" \
RECORDED_AT="$recorded_at" ENGINE_VERSION="$engine_version" BINARY_HASH="$binary_hash" \
GOLDEN_HASH="$golden_hash" QA_COMMIT="$qa_commit" VERIFIED="$verified" \
CASE_NAMES="$case_names" OUT_PATH="$manifest" \
python - <<'PY'
import json, os
env = os.environ
d = {
    "recorded_at": env["RECORDED_AT"],
    "engine_version": env["ENGINE_VERSION"],
    "binary": env["REL_BIN"],
    "binary_sha256": env["BINARY_HASH"],
    "golden_set_sha256": env["GOLDEN_HASH"],
    "ssa_qa_commit": env["QA_COMMIT"],
    "verified": env["VERIFIED"] == "true",
    "cases": [c for c in env["CASE_NAMES"].split(",") if c],
}
with open(env["OUT_PATH"], "w", encoding="utf-8") as f:
    json.dump(d, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY

cp "$manifest" "$OUT/latest.json"
echo "== recorded: $manifest =="
echo "   engine=$engine_version binary=$short golden=$golden_hash commit=${qa_commit:0:12} verified=$verified"
