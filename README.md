# viy

An IDA plugin that uses **[rax](https://github.com/hexrayssa/rax) — both its emulator and its
decoder — to hand the main analysis the cross-references it missed.** Two
complementary passes run per function:

- a **dynamic (emulation)** pass that resolves the *indirect* control flow and
  computed data accesses a static disassembler cannot — indirect calls/jumps,
  jump-table targets, vtable/computed calls;
- a **static (decode)** pass that uses rax's comprehensive x86 and ARM decoder to
  recover the *direct* branch/call targets IDA's own decode left unlinked.

Everything it finds is checked against the existing database and only the
genuinely missing references are added.

It is designed to be **as transparent and invisible as possible**:

- It loads into every database, hooks the end of auto-analysis, does its work in
  small main-thread batches so the UI never stalls, and prints *at most* one
  summary line — only when it actually recovered something.
- It **never links against librax**. The engine is `dlopen`'d at runtime behind
  an ABI gate. If librax is missing, unloadable, or ABI-incompatible, viy is a
  completely silent no-op — the plugin still loads, it just does nothing.

## How it works

1. **Wake** on `idb_event::auto_empty_finally` (the first auto-analysis pass has
   finished), once per database.
2. **Snapshot** the program on the main thread: every segment's bytes + an
   initialized-byte bitmap, and every real function entry. Detect the target
   architecture (x86/x86-64, AArch64, …) and endianness.
3. **Emulate** each function through rax (the dynamic pass): the image is
   mirrored into guest memory once; each function runs from its entry over a
   scratch stack whose top holds a sentinel return address (so the outermost
   `ret` stops the run cleanly). Runs are bounded by an instruction count *and* a
   wall-clock timeout; an invalid-instruction hook absorbs faults; per-run
   isolation uses rax context snapshots. Only edges/accesses whose *source* lies
   inside the function being emulated are recorded, so callee bodies don't add
   noise (each function is mined from its own entry).
   - A **code hook** records every executed PC. A taken branch whose *source* is
     an indirect call/jump and whose target is not the static fall-through is a
     candidate — this is how indirect call/jump and jump-table targets surface.
   - A **memory hook** records data reads/writes — computed data references.
4. **Decode** each function statically with rax (the static pass): for every
   control-transfer instruction IDA left without a resolved outgoing xref, rax's
   decoder is asked whether the encoding carries a *direct* target, and the cref
   is added if so. AArch32's ARM/Thumb state is taken from IDA per address.
5. **Diff & add** on the main thread: each candidate is classified (call vs.
   jump; read vs. write), required to sit in an *executable* segment at an
   instruction head, and compared against the existing xrefs. Only genuinely
   **missing** refs are added (as `add_cref` / `add_dref` marked `XREF_USER`, so
   they survive reanalysis). Freshly discovered code targets are queued for
   analysis (`auto_make_code` / `plan_ea`).

The two passes are complementary: the emulator observes what the code *does*
(indirect flow), while the decoder reads what each instruction *is* (direct
flow) — together they resolve targets a single static pass had to leave blank.

## Building

rax is vendored as a git submodule under `vendor/rax`, so a recursive clone (or
`git submodule update --init`) is all you need besides the IDA SDK and kvasir's
`ida-cmake`. The `Makefile` builds **both** librax (from the submodule, via
cargo) and the viy plugin, staging both artifacts into `build/`:

```sh
git submodule update --init --depth 1 vendor/rax   # if not cloned recursively
export IDASDK=/path/to/ida-sdk                      # required
export IDA_CMAKE_DIR=/path/to/ida-cmake             # optional (has a default)
make                                                # -> build/viy.dylib + build/librax.dylib
```

`make help` lists the targets. viy itself links nothing against librax — the
header (`vendor/rax/capi/include/rax.h`) is used only for the ABI typedefs, and
librax is `dlopen`'d at runtime.

## Installing / deploying librax

```sh
export IDABIN=/path/to/ida        # your IDA install dir
make install                      # viy.* AND librax.* -> $IDABIN/plugins
# or:
make install-ida-folder           # viy.* -> $IDABIN/plugins ; librax.* -> $IDABIN (the IDA folder)
```

librax is found at runtime, in this order:

1. `$VIY_RAX_PATH` (explicit path), then
2. the platform loader search path, then
3. **next to the `viy` plugin binary** (`…/plugins/librax.*`), then
4. **the IDA folder** (next to the `ida`/`ida64` executable).

So dropping librax either next to the plugin or in the IDA folder just works. No
librax, no problem — viy stays a silent no-op.

## Configuration (environment overrides)

All optional; sensible defaults otherwise. Set these before launching IDA.

| Variable             | Default  | Meaning                                            |
|----------------------|----------|----------------------------------------------------|
| `VIY_ENABLED`        | `1`      | Master switch (`0` disables the sweep).            |
| `VIY_MAX_INSNS`      | `200000` | Per-function instruction cap (bounds loops).       |
| `VIY_TIMEOUT_MS`     | `1000`   | Per-function wall-clock cap.                       |
| `VIY_MAX_FUNCS`      | `0`      | Emulate at most N functions (`0` = all).           |
| `VIY_FUNCS_PER_TICK` | `2`      | Functions per UI timer tick (keeps the UI live).   |
| `VIY_TICK_MS`        | `15`     | Timer cadence in ms.                               |
| `VIY_MAKE_CODE`      | `1`      | Turn discovered code targets into code.            |
| `VIY_WANT_DREFS`     | `1`      | Record data references (needs a recording backend).|
| `VIY_STATIC`         | `1`      | Run the rax static-decode pass (needs rax ≥ 1.2).  |
| `VIY_RAX_PATH`       | —        | Explicit path to librax.                           |

## Scope & limitations

- **Dynamic (emulation) pass** needs a **stepping-capable** rax backend (code
  hooks): x86-64, AArch64, RISC-V today. Data references additionally need a
  **recording** backend (x86-64 today); elsewhere viy still recovers code refs
  and simply skips drefs. Emulation is unattended and starts with unknown
  arguments, so it explores the paths reachable from a plausible entry state — a
  *recall booster*, not a proof.
- **Static (decode) pass** needs rax ≥ 1.2 (the `rax_decode` export). It covers
  x86-32/64, AArch64, and AArch32 (ARM + Thumb, taking the Thumb state from IDA
  per address; Cortex-M included). With an older, emulation-only librax the
  static pass is simply skipped.
- viy only ever *adds* references — always inside the loaded image, into an
  executable segment at an instruction head, and only after confirming the ref
  is not already present. It never removes or rewrites what the main analysis
  produced.
