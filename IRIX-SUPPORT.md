# IRIX / SGI MIPS support

This branch (`irix-ultimate`) is the accumulation branch for the IRIX/SGI MIPS work in
this fork.  It is pinned to Ghidra 12.1.2 for project-format compatibility and currently
stacks on the reviewable feature branches:

```
ghidra-12.1.2 (tag Ghidra_12.1.2_build)
  └── feature/sgi-dwarf-parser   (PR #1)  MIPSpro .debug_abbrev quirks
        └── feature/sgi-elf-symbols  (PR #2)  SHN_MIPS_SCOMMON / SHN_MIPS_SUNDEFINED
              └── irix-ultimate             DWARF function bodies + this roadmap
```

## Status

| Area | Status | Where |
| --- | --- | --- |
| MIPSpro `.debug_abbrev`: omitted final terminator, concatenated per-CU blocks with codes restarting at 1 | **Done** | `DWARFAbbreviation.java`, `DWARFAbbreviationTest` |
| SGI `SHN_MIPS_*` symbols: small-undefined (0xff04) was dropped, small-common (0xff03) unhandled | **Done** | `MIPS_ElfExtension.java`, `MIPS_ElfExtensionTest` |
| Hand-asm function bodies: DWARF `low_pc`/`high_pc` now applied to Ghidra bodies; nested non-DWARF entries demoted including strictly nested thunks; re-applied late so other analyzers cannot clip | **Done** | `DWARFFunctionImporter.java`, `DWARFFunctionBodyFixupAnalyzer.java`, `DWARFImportOptions` |
| `.msym` / `.MIPS.symlib` | **Not needed** | They are per-`.dynsym` hash/flag tables; see `DWARF-SGI-NOTES.md`.  Stock Ghidra already applies all `SHN_MIPS_TEXT` symbols |
| Jump tables / `UNRECOVERED_JUMPTABLE` (`jr t4`, gp-relative tables) | **Done** | `MipsInlineDispatchAnalyzer` recovers inline code tables and PC-relative pointer tables inside a function; `MipsIndirectTailCallAnalyzer` types bare `jr a1`/`jr a2` stubs as `CALL_RETURN` (minimal harvest of upstream PR #8547) |
| SGI prelinked DSO `R_MIPS_REL32`: the in-place addend is already the resolved absolute address | **Done** | `MIPS_ElfRelocationHandler` no longer re-adds the symbol value for SGI prelinked objects (`.MIPS.symlib` / `DT_MIPS_SYMBOL_LIB`); this recovers code-pointer dispatch tables in libgl (`__*_zspan_*_asm`) that previously decompiled as `halt_baddata` |
| Delay-slot function entries (entry is the previous function's `jr` delay slot) | **Done** for disassembly/bodies; conditional-slot block flow still open | `EntryPointAnalyzer`+`Disassembler` resume at the slot fall-through so the entry's body decodes to its DWARF range (`restartxthread` 4 → 92 bytes); `MipsDelaySlotFlowTest`. A branch whose *target* is a delay slot previously crashed the native decompiler; fixed (see Design notes) |
| Non-returning IRIX asm (`panic`, `sppanic`, `_r4600_2_0_cacheop_eret`) | **Done** | `MipsFunctionsThatDoNotReturn` + `noReturnFunctionConstraints.xml`; ECOFF import re-runs the known no-return pass on its own entries |
| DWARF asm signature locking (`void f(void)` committed as definite for asm subprograms) | **Done** | `NO_PARAMS` commit mode leaves unknown signatures recoverable; upstream #9476 |
| `.mdebug` / ECOFF for objects without DWARF | **Done** | `EcoffDebug.java` + `EcoffAnalyzer.java` (32-bit MIPS ELF `.mdebug`); late body fixup re-applies ranges; upstream #1379 never merged; #356 still open |
| GP-relative (CPIC) model: `gp`/`t9` seeded at function entries so gp-relative GOT and small-data references resolve | **Done** | `MipsGpAnalyzer` seeds `gp` = `_mips_gp_value` and `t9` = function entry (PIC ABI); `MipsGotAnalyzer` renames GOT slots `__got_<target>`; measured on libGLcore: `unaff_gp` 7→0 and `(**(code **)` call spam 78→0 in a 121-function sample |
| `.MIPS.stubs` / PLT as named thunks | **Done** | `MipsStubsAnalyzer` decodes the `ori t8,zero,symidx` delay slot and creates `name@plt` thunks to the imported functions |
| `.mdebug` / ECOFF for objects without DWARF | **Done** | `EcoffDebug.java` + `EcoffAnalyzer.java` (32-bit MIPS ELF `.mdebug`); parameter/local records parsed and parameter names applied; remaining MIPS storage classes mapped for EXEC statics; nested non-ECOFF entries inside an authoritative procedure range are demoted to labels (like the DWARF fixup) so parents keep their complete body. Validated on unstripped Foundation-era media: `usr/lib/debug/libdmedia.so` 733/764 parameterised, `usr/lib/abi/libc.so` 592/1,310 (C-standard-exact prototypes); upstream #1379 never merged; #356 still open |
| N32 ABI conventions (struct returns, varargs, paired f/GPR argument slots) | **Done** | `mips64_32_n32.cspec` rewritten to the SGI MIPSpro N32 ABI (007-2816-005), cross-checked against clang 21 `-mabi=n32 -EB` codegen; `N32CallingConventionTest` |
| Corpus regression harness | **Done** | `work/inventory/` — per-object inventory dumps, baseline + corpus TSV diffing; see AGENTS.md |
| Native `ld` `.compact_rel` emission (o32) | **Researched** | `docs/irix/native-ld-compact-relocs.md` reverse-engineers the 7.3 linker's record format, sizing, and tags from an oracle link; fix direction is binutils-side. Ghidra-side needs nothing beyond the existing `DT_MIPS_COMPACT_SIZE` constant |
| IRIX `libc.so.1` loader parse (#1527, `.MIPS.options`) | **Untested** | our fixtures parse; libc.so.1 should be added to the smoke matrix |

## Harvest list (unmerged upstream work worth porting)

| Ref | What | Why |
| --- | --- | --- |
| [PR #8547](https://github.com/NationalSecurityAgency/ghidra/pull/8547) | `MipsSwitchTableAnalyzer`, `MipsDecompIndirectCallAnalyzer`, signature/function-pointer analyzers | MIPS switch tables and `jr/jalr $t9` tail calls; directly targets `UNRECOVERED_JUMPTABLE` |
| [#9476](https://github.com/NationalSecurityAgency/ghidra/issues/9476) | DWARF importer locks `void(void)` onto asm functions | MIPSpro asm subprograms have no parameters; avoid committing definite signatures |
| [#4675](https://github.com/NationalSecurityAgency/ghidra/issues/4675), [#4325](https://github.com/NationalSecurityAgency/ghidra/issues/4325), [#4241](https://github.com/NationalSecurityAgency/ghidra/discussions/4241) | Branch/flow inside delay slots | LOCORE puts real work and jumps in delay slots; blocked upstream as a known limitation |
| [#2030](https://github.com/NationalSecurityAgency/ghidra/issues/2030), [#729](https://github.com/NationalSecurityAgency/ghidra/issues/729) | MIPS32 disassembly stops at `jr v0`; switch detection | same class as jump tables |
| [#2551](https://github.com/NationalSecurityAgency/ghidra/issues/2551) | `lw t9,off(gp); jalr t9` decompiled as `_gp`-relative indirect call | PIC/DSO call recovery |
| [#1379](https://github.com/NationalSecurityAgency/ghidra/issues/1379), [#356](https://github.com/NationalSecurityAgency/ghidra/issues/356) | `.mdebug`/ECOFF support never merged | IRIX objects without `.debug_*` (and pre-DWARF toolchains) |
| [#6025](https://github.com/NationalSecurityAgency/ghidra/issues/6025) | Symbol-driven functions mangling loaded data | related to nested-entry clipping, now handled for DWARF bodies |
| [#1527](https://github.com/NationalSecurityAgency/ghidra/issues/1527) | IRIX `libc.so.1` parse failure (`.MIPS.options`, `.msym`) | loader coverage |
| [chaoticgd/ccc](https://github.com/chaoticgd/ccc), [N64Recomp](https://github.com/N64Recomp/N64Recomp), [spimdisasm](https://github.com/Decompollaborate/spimdisasm) | mdebug parsers; STABS `text_end`; `farthestBranch` function-end rules | proven extraction/insertion techniques for the `.mdebug` and stripped-binary paths |
| [ghidra-emotionengine-reloaded](https://github.com/chaoticgd/ghidra-emotionengine-reloaded) | `StabsImporter` creates functions with explicit `[low, high)` bodies | the same pattern now implemented in the DWARF importer |
| [bb33bad196](https://github.com/NationalSecurityAgency/ghidra/commit/bb33bad196) | GP-7136 join-space dead-Varnode guard in `Heritage::processJoins` | **Ported** — fixes the `ProcChangeHosts` native decompiler crash |
| [6740b89926](https://github.com/NationalSecurityAgency/ghidra/commit/6740b89926) | GP-7063 new symbol-conflict detection | **Partly ported** — only the `buildDynamicSymbol` locked-Varnode guard deletion (fixes `ProcXineramaShapeMask..NBE`); the conflict-model rework is not in 12.1.2 |

Prior-art tooling (`spimdisasm`, `m2c`, `print-mdebug`, N64Recomp, `ccc`, `fsn`, the
Ghidra mdebug/PS2 extensions) was empirically tested on 7 October 2026 — see
`docs/irix/prior-art-irix-ghidra.md` §7.  None is adoptable wholesale; three independently
confirm our ECOFF numbers (3,218 PDRs / 3,184 unique addresses), and N64Recomp's mdebug
parser is the one component worth a small port as an independent range oracle.

SGI reference documentation (ABI handbooks, MIPSpro, dynamic linking) lives in the
private `irix7/reference` repo (techpub archive, never published).

## Upstream version policy

The fork stays pinned to Ghidra 12.1.2 (project-format compatibility) and backports
specific upstream fixes as they are needed, tracked in the harvest list above.  12.1.2
predates the recent decompiler join/conflict reworks (GP-7063, GP-7136, ...), and those
land on upstream `master` — not in the 12.1.3/12.1.4 patch releases (the DWARF package is
byte-identical across 12.1.2..12.1.4 and the decompiler churn there is ~100 lines).  So
"upgrade to the latest release" would not pick up the fixes we actually need, while
jumping to `master` is a very large, un-released rebase (8k+ lines of decompiler churn,
project-format risk) for a fixed IRIX corpus.  Reassess a version move only when a needed
fix ships in a release and cannot be backported cleanly; do it as a dedicated branch with
a full corpus re-verification and project migration.

The native toolchain paths (`/nix/store/...`) are ephemeral and may be garbage-collected
mid-session; resolve `g++`/`make`/`bison`/`flex` through `nix-shell -p` or re-query
`/nix/store` at build time rather than pinning the store paths.

## Design notes

* **DWARF ranges are authoritative.**  `Set Function Bodies From DWARF` (default on) sets
  function bodies from `DW_TAG_subprogram` `low_pc`/`high_pc`, matching what the compiler
  emitted for both C and hand-written assembly (`.ent`/`.end` ranges).  Turn it off to
  restore pure flow-derived bodies.
* **Nested entries are demoted, not deleted.**  A function entry inside a DWARF range
  that is not itself a DWARF subprogram (assembler `EXPORT`/`XLEAF` labels emitted as
  `STT_FUNC` symbols, internal dispatch stubs, shared return sequences, strictly nested
  thunks such as the `locore_eret_*` jumps inside `kmiss`) becomes an
  `IMPORTED` label.  Names and address-taken function pointers keep working; the parent
  body stays complete.
* **A low-priority one-time analyzer re-applies the bodies.**  Shared-return analysis,
  subroutine-reference and constant-propagation analyzers create function entries after
  the DWARF import (priority 101) and would otherwise clip the bodies again.  ECOFF
  uses the same pattern: `EcoffAnalyzer` records authoritative procedure ranges and a
  nested one-time fixup re-applies them, demoting strictly-inside non-ECOFF entries to
  labels (label-preserving, like the DWARF fixup) without carving user-owned functions
  or changing signatures.
* **Authoritative ranges cover, but do not re-disassemble.**  Restored ECOFF bodies may
  cover addresses left without instructions by later analysis; the fixup does not decode
  them late because that could clobber intentional data.
* **Known limitation:** delay-slot block flow.  Unconditional-slot entries disassemble
  and decompile; conditional-predecessor slots can inherit incorrect block flow and
  functions reaching both a delayed branch and its slot may emit overlap diagnostics.
  Authoritative body ranges do not resolve these flow-model limits
  (`MipsDelaySlotFlowTest`, upstream #4675).
* **Resolved:** a branch whose target is *inside* another branch's delay slot used to
  crash the native decompiler (`Decompiler process died`).  Smallest case: `Xsgi` 6.5.7m
  `ProcChangeHosts @0x100e1298`, where `b 0x100e131c` targets the delay slot of the `beq`
  at `0x100e1318` (retargeting it to `0x100e1318` completes the decompile).  The branch
  into the slot perturbs return-value inference so each `jr ra` is modelled returning a
  16-byte `v0:v1` join; by heritage pass 5 that join-space Varnode can be dead (no
  readers), and `Heritage::splitJoinRead` dereferenced its null `loneDescend()`.
  `Heritage::processJoins` now skips a reader-less join Varnode — the one-line guard from
  upstream `bb33bad196` (GP-7136), which this 12.1.2-based fork was missing.  A full
  Xsgi-657m decompile sweep is now 7,140/7,140 (was 7,139/7,140).

## Verification workflow

Fixtures are proprietary and must never be committed.  Local fixtures used:

* 6.5.7m kernel objects: `gfx.o`, `ng1.a`, `gr2.a`, `mgras.a`
  (`/mnt/europa/sgi-mame/irix-drivers/6.5.7m-gfx-kernel/IP22boot/`)
* `libGLcore.so` 6.5.7m / 6.5.22
* `unix` 6.5.22 kernel (`/mnt/europa/sgi-mame/irix-drivers/unix`)
* `Xsgi` IP22NG1, plus a GCC 15 x86-64 DWARF 5 object as the standard-DWARF regression
* Unstripped Foundation-era debug libraries (`.mdebug` stParam validation), from the
  `IRIX 6.5 Development Libraries (June 1998)` CD's dist archives (extract with the
  `irix7/project` `scripts/irix-media/dumpz.py` tooling): `usr/lib/debug/libdmedia.so`,
  `usr/lib/abi/libc.so`

Scripts live in `work/scripts/` on the development host (not committed):
`Classify.java` (compare hand-asm bodies to DWARF ranges), `VerifyDwarf.java`,
`CheckAsmFlow.java`, `DumpBody.java`, `CallTargetLabels.java`, and the unit tests
`DWARFAbbreviationTest` / `MIPS_ElfExtensionTest` under the modules' `src/test`.
Curated copies of the verification utilities live in the `irix6` repo under
`decompiled/scripts/`; the research snapshots behind this work are committed here
under `docs/irix/`.

Current results on the 6.5.22 `unix` kernel:

* 631 CUs / 34,812 DIEs imported; 10,188 functions, all named (nested non-DWARF
  entries are labels); 12,763 DWARF types (868 structs, 572 typedefs).
* Hand-asm functions: **366/366 exactly match their DWARF body ranges** (baseline 285/366,
  with 52 clipped at nested entries and 24 disassembly gaps; `kmiss` now keeps its full
  range with nested `locore_eret_*` thunks as labels).
* ECOFF: no-DWARF O32 `libGLcore.so` imports 3,218/3,218 exact procedure ranges after
  the full pipeline (3,210 functions; import-only smoke was 3,259 functions).
* No-return: `panic` and `_r4600_2_0_cacheop_eret` marked non-returning; ECOFF-only
  `sppanic` covered by the re-run; asm subprograms use `NO_PARAMS` so signatures stay
  recoverable.
* Inline dispatch plus indirect tails: the `emulate_lwc1/ldc1/swc1/sdc1` and
  `fpunit_fp*load/store_{s,d}` families now decompile as switches, and bare
  `jr a1`/`jr a2` stubs are typed `CALL_RETURN` without touching shared tails.
* Standard DWARF 5 `std.o` regression: identical before/after (`int foo(S * s, int x)`,
  1 struct, 11 DIEs).
* Delay-slot entries: `restartxthread` (6.5.22 `unix`) now decodes its full 92-byte DWARF
  range (was 4 bytes); `CheckAsmFlow` stays 366/366 and the corpus inventory is unchanged.
* ECOFF nested entries: O32 `libc.so.1` `_nsproc` restored to its full range
  (3,084/3,084 exact, 0 mismatched, 0 missing bytes); the O32 `libGLcore` smoke stays
  3,218/3,218.  `libgl.so`'s 67 mismatches are ECOFF-vs-ECOFF `stEnd` overlaps (fall-through
  stub families) and are left alone.
* Native decompiler: `ProcChangeHosts` (Xsgi 6.5.7m) now decompiles; a full Xsgi-657m sweep
  is 7,140/7,140 (was 7,139/7,140, the single failure being `ProcChangeHosts`).
* SGI prelinked `R_MIPS_REL32`: libgl N32's 2,316 in-place addends now all resolve inside
  the image (previously 0 did); the ~20 `__do_zspan_*_asm`/`__pat_zspan_*_asm` dispatchers
  decompile on N32 and o32 (no `halt_baddata`, no unresolved jump).  The change is gated on
  SGI markers and is a no-op for the `unix` kernel (ET_EXEC, zero relocations) and non-SGI
  MIPS ELF; the libGLcore-657m inventory and the rest of libgl are otherwise unchanged.
* IRIX 6.5.22 ABI: the driver-CD `IP22NG1/Xsgi` is a **6.5.22m** build despite the path
  (it embeds `IRIX 6.5:...built .../6.5.22m/...`), and it is **N32** — `e_flags
  0x20000024` (`EF_MIPS_ABI2`), language `MIPS:BE:64:64-32addr`, unlike the 6.5.7m IP22NG1
  o32 objects.  Its `ProcXineramaShapeMask..NBE @0x103733d0` was a *different* failure
  class: a recoverable decompiler error ("Trying to build dynamic symbol on locked
  varnode", `funcdata_varnode.cc`).  Dropping that guard (upstream GP-7063) makes it
  decompile; a full Xsgi (6.5.22) re-sweep is 3,895/3,896 with every previously-succeeding
  function byte-identical, the one remaining failure being an unrelated `wchar_t`
  low-level error (`bdfReadProperties..KO`).

Build note: run `bash build-irix-patch.sh <writable-ghidra-12.1.2-directory>` to compile
this fork's Java changes into `$DIST/Ghidra/patch` and copy the MIPS no-return data
files.  A normal `gradle buildGhidra` is the upstream build path (the source checkout
has no Gradle wrapper, so a system Gradle 8.x is required).

The native decompiler is **not** rebuilt by `build-irix-patch.sh`; the fork also carries a
`decompile/cpp` change (the GP-7136 join-Varnode guard), so after touching native sources
rebuild it and install the binary into the distribution:

```bash
cd Ghidra/Features/Decompiler/src/decompile/cpp
make CXX='g++ -std=c++11' ghidra_opt
cp ghidra_opt <DIST>/Ghidra/Features/Decompiler/os/linux_x86_64/decompile
```

(The generated parser sources are committed, so bison/flex are not required.)
