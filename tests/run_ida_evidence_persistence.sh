#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
: "${IDAT:?set IDAT to the IDA text-mode executable}"
BUILD_DIR=${BUILD_DIR:-$ROOT/build-dev}
RAX_LIB=${VIY_RAX_PATH:-$ROOT/vendor/rax/target/release/librax.dylib}
WORK=${VIY_IDA_TEST_DIR:-/tmp/viy-evidence-persistence}

test -x "$IDAT"
test -f "$BUILD_DIR/viy.dylib"
test -f "$RAX_LIB"

rm -rf "$WORK"
mkdir -p "$WORK/user/plugins/viy" "$WORK/out"
cp "$BUILD_DIR/viy.dylib" "$WORK/user/plugins/viy.dylib"
cp "$RAX_LIB" "$WORK/user/plugins/viy/$(basename "$RAX_LIB")"

# An isolated IDAUSR keeps the test hermetic. Reuse only the local license,
# never repository state or the user's installed viy plugin.
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

SCRIPT=$ROOT/tests/ida_evidence_persistence.py
DB=$WORK/out/evidence.i64
STATE=$WORK/out/state.json
COMMON="IDAUSR=$WORK/user VIY_RAX_PATH=$RAX_LIB VIY_WORKERS=2 VIY_EXPLORE_RUNS=2 VIY_MAX_EPOCHS=1 VIY_HEXRAYS_BRIDGE=0"

run_ida() {
  mode=$1
  shift
  log=$WORK/out/$mode.log
  env $COMMON VIY_EVIDENCE_MODE=$mode VIY_EVIDENCE_STATE=$STATE "$@" \
    "$IDAT" -A -L"$log" -S"$SCRIPT" "$DB"
}

# Create and populate the IDB, then reopen once so both retained slots contain
# independently committed valid envelopes.
env $COMMON VIY_EVIDENCE_MODE=verify VIY_EVIDENCE_STATE=$STATE \
  "$IDAT" -A -c -o"$DB" -L"$WORK/out/create.log" -S"$SCRIPT" \
  "$INPUT"
run_ida verify

# Corrupt the committed envelope while retaining a valid fallback. A disabled
# analysis run still restores the ledger in the plugmod constructor.
run_ida corrupt_active VIY_ENABLED=0
run_ida expect_fallback VIY_ENABLED=0

# Re-enable one sweep to replace the deliberately corrupt inactive slot, then
# destroy the marker itself. With two valid slots, recovery must merge them and
# atomically commit slot A.
run_ida verify
run_ida invalidate_marker VIY_ENABLED=0
run_ida expect_marker_merge VIY_ENABLED=0

# Finally recreate the former adjacent-index representation with a single
# intact slot. The current adapter must validate and migrate it into a separate
# slot node without losing any observation.
run_ida setup_legacy_layout VIY_ENABLED=0
run_ida expect_legacy_migration VIY_ENABLED=0

# A fresh converging IDB must reuse completed dynamic jobs in its second epoch
# when neither function bytes, global bytes, call summaries nor entry contexts
# changed. Static/main-thread consumers still run for every function.
CACHE_DB=$WORK/out/cache.i64
CACHE_LOG=$WORK/out/cache.log
env $COMMON VIY_MAX_EPOCHS=3 \
  "$IDAT" -A -c -o"$CACHE_DB" -L"$CACHE_LOG" \
  -S"$ROOT/tests/ida_worker_smoke.py" "$INPUT"
if ! grep -Eq '[1-9][0-9]* dynamic cache hit\(s\)' "$CACHE_LOG"; then
  echo "error: real-IDAT run did not exercise the incremental dynamic cache" >&2
  exit 1
fi

# Memory hooks remain active for runtime strings/SMC, but VIY_WANT_DREFS=0 must
# be an absolute gate on computed add_dref mutations.
NO_DREF_DB=$WORK/out/no-drefs.i64
NO_DREF_LOG=$WORK/out/no-drefs.log
env $COMMON VIY_WANT_DREFS=0 \
  "$IDAT" -A -c -o"$NO_DREF_DB" -L"$NO_DREF_LOG" \
  -S"$ROOT/tests/ida_worker_smoke.py" "$INPUT"
if ! grep -Eq '0 data xref\(s\)' "$NO_DREF_LOG"; then
  echo "error: VIY_WANT_DREFS=0 did not suppress computed IDB drefs" >&2
  exit 1
fi

# Remove the companion engine entirely and prove both IDA-only producers still
# run through the real plugin lifecycle and persist their own provenance. The
# fixture contains deterministic opposite-branch and wrapper shapes.
COMPANION=$WORK/user/plugins/viy/$(basename "$RAX_LIB")
DISABLED_COMPANION=$COMPANION.disabled
mv "$COMPANION" "$DISABLED_COMPANION"
trap 'test ! -f "$DISABLED_COMPANION" || mv "$DISABLED_COMPANION" "$COMPANION"' EXIT HUP INT TERM
for provider in native deobf; do
  PROVIDER_DB=$WORK/out/$provider-only.i64
  PROVIDER_LOG=$WORK/out/$provider-only.log
  if test "$provider" = native; then
    PRODUCER=viy.native.ida
    PROVIDER_ENV="VIY_NATIVE=1 VIY_DEOBF=0"
  else
    PRODUCER=viy.deobf.ida
    PROVIDER_ENV="VIY_NATIVE=0 VIY_DEOBF=1"
  fi
  env IDAUSR="$WORK/user" VIY_RAX_PATH="$WORK/out/does-not-exist.dylib" \
    VIY_STATIC=0 VIY_MAX_EPOCHS=1 VIY_PERSIST_EVIDENCE=1 \
    VIY_COMMENTS=0 VIY_WANT_DREFS=0 VIY_EXPECT_PRODUCER="$PRODUCER" \
    $PROVIDER_ENV \
    "$IDAT" -A -c -o"$PROVIDER_DB" -L"$PROVIDER_LOG" \
    -S"$ROOT/tests/ida_provider_smoke.py" "$INPUT"
  if ! grep -Fq "VIY_PROVIDER_SMOKE producer=$PRODUCER" "$PROVIDER_LOG"; then
    echo "error: real-IDAT $provider-only provider smoke did not finish" >&2
    exit 1
  fi
done
mv "$DISABLED_COMPANION" "$COMPANION"
trap - EXIT HUP INT TERM

echo "VIY_EVIDENCE_PERSISTENCE passed; logs: $WORK/out"
