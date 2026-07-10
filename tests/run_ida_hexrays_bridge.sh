#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${IDAT:?set IDAT to the IDA text-mode executable}"
BUILD_DIR=${BUILD_DIR:-$ROOT/build-dev}
WORK=${VIY_IDA_HEXRAYS_TEST_DIR:-/tmp/viy-hexrays-bridge}
OBSERVABILITY_VERIFY=$ROOT/tests/verify_observability_log.py

test -x "$IDAT"
test -f "$BUILD_DIR/viy.dylib"

rm -rf "$WORK"
mkdir -p "$WORK/user/plugins" "$WORK/out"
cp "$BUILD_DIR/viy.dylib" "$WORK/user/plugins/viy.dylib"

# Keep the licensed smoke hermetic while reusing only the local license and
# standard IDAPython preferences required by this installed IDA.
for license in "$HOME"/.idapro/*.hexlic; do
  if test -f "$license"; then cp "$license" "$WORK/user/"; fi
done
for preference in ida-config.json ida.reg idapythonrc.py; do
  if test -f "$HOME/.idapro/$preference"; then
    cp "$HOME/.idapro/$preference" "$WORK/user/"
  fi
done

if command -v xcrun >/dev/null 2>&1; then
  INPUT=$WORK/out/input.macho
  xcrun clang -arch x86_64 -O0 -g -Wl,-no_pie \
    "$ROOT/tests/fixtures/integration_x86_64.c" -o "$INPUT"
else
  INPUT=$WORK/out/input
  "${CC:-clang}" -O0 -g -fno-pie -no-pie \
    "$ROOT/tests/fixtures/integration_x86_64.c" -o "$INPUT"
fi

DB=$WORK/out/hexrays.i64
LOG=$WORK/out/hexrays.log
env IDAUSR="$WORK/user" \
  VIY_LOG_LEVEL=2 VIY_PROGRESS_INTERVAL_MS=100 \
  VIY_HEXRAYS_BRIDGE=1 VIY_NATIVE=1 VIY_DEOBF=0 VIY_STATIC=0 \
  VIY_RAX_PATH="$WORK/out/does-not-exist.dylib" VIY_MAX_EPOCHS=1 \
  VIY_PERSIST_EVIDENCE=0 VIY_COMMENTS=0 VIY_WANT_CREFS=0 VIY_WANT_DREFS=0 \
  "$IDAT" -A -c -o"$DB" -L"$LOG" \
  -S"$ROOT/tests/ida_hexrays_bridge_smoke.py" "$INPUT"

if grep -Fq "VIY_HEXRAYS_SMOKE skipped:" "$LOG"; then
  echo "VIY_HEXRAYS_BRIDGE skipped; compatible licensed decompiler unavailable"
  exit 0
fi
if ! grep -Eq 'VIY_HEXRAYS_SMOKE annotation=.*\[viy\]' "$LOG"; then
  echo "error: real Hex-Rays callback did not render a viy annotation" >&2
  exit 1
fi
if ! grep -Fq 'lifecycle=recent-cfunc' "$LOG"; then
  echo "error: Hex-Rays teardown lifecycle surface was not retained" >&2
  exit 1
fi
if ! grep -Fq '[viy] event=start ' "$LOG" \
  || ! grep -Fq '[viy] event=complete ' "$LOG"; then
  echo "error: real Hex-Rays run did not expose the viy lifecycle" >&2
  exit 1
fi
python3 "$OBSERVABILITY_VERIFY" hexrays "$LOG"

echo "VIY_HEXRAYS_BRIDGE passed; log: $LOG"
