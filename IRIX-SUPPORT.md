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
| Hand-asm function bodies: DWARF `low_pc`/`high_pc` now applied to Ghidra bodies; nested non-DWARF entries demoted; re-applied late so other analyzers cannot clip | **Done** | `DWARFFunctionImporter.java`, `DWARFFunctionBodyFixupAnalyzer.java`, `DWARFImportOptions` |
| `.msym` / `.MIPS.symlib` | **Not needed** | They are per-`.dynsym` hash/flag tables; see `DWARF-SGI-NOTES.md`.  Stock Ghidra already applies all `SHN_MIPS_TEXT` symbols |
| Jump tables / `UNRECOVERED_JUMPTABLE` (`jr t4`, gp-relative tables) | **Partly done** | `MipsInlineDispatchAnalyzer` recovers inline code tables and PC-relative pointer tables inside a function; remaining warnings are register-argument stubs/shared tails.  Harvest PR #8547 for indirect tail-call typing (`jr a2`/`jr a1`) |
| Delay-slot function entries (entry is the previous function's `jr` delay slot) | **Mostly covered** by body ranges; full flow fix upstream #4675 | `Disassembler` `AddressSet` overload skips already-defined entries |
| Non-returning IRIX asm (`panic`, `sppanic`, `_r4600_2_0_cacheop_eret`) | **Open** | add names to the MIPS no-return data list; consider disabling `FindNoReturnFunctionsAnalyzer` flow repair for kernel projects (#1981 churn) |
| DWARF asm signature locking (`void f(void)` committed as definite for asm subprograms) | **Open** | upstream #9476; MIPSpro emits no parameters, so signatures are currently declared `void(void)` |
| `.mdebug` / ECOFF for objects without DWARF | **Open** | port `astrelsky/ghidra_mdebug`/`chaoticgd/ccc` parsers; upstream #1379 never merged; #356 still open |
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

## Design notes

* **DWARF ranges are authoritative.**  `Set Function Bodies From DWARF` (default on) sets
  function bodies from `DW_TAG_subprogram` `low_pc`/`high_pc`, matching what the compiler
  emitted for both C and hand-written assembly (`.ent`/`.end` ranges).  Turn it off to
  restore pure flow-derived bodies.
* **Nested entries are demoted, not deleted.**  A function entry inside a DWARF range
  that is not itself a DWARF subprogram (assembler `EXPORT`/`XLEAF` labels emitted as
  `STT_FUNC` symbols, internal dispatch stubs, shared return sequences) becomes an
  `IMPORTED` label.  Names and address-taken function pointers keep working; the parent
  body stays complete.
* **A low-priority one-time analyzer re-applies the bodies.**  Shared-return analysis,
  subroutine-reference and constant-propagation analyzers create function entries after
  the DWARF import (priority 101) and would otherwise clip the bodies again.
* **Known limitation:** `kmiss` in the 6.5.22 kernel keeps two `locore_eret_*` shared
  return thunks inside its range (16 bytes), because thunks are deliberately not
  demoted.  All other 365 hand-asm functions in the kernel exactly match their DWARF
  ranges.

## Verification workflow

Fixtures are proprietary and must never be committed.  Local fixtures used:

* 6.5.7m kernel objects: `gfx.o`, `ng1.a`, `gr2.a`, `mgras.a`
  (`/mnt/europa/sgi-mame/irix-drivers/6.5.7m-gfx-kernel/IP22boot/`)
* `libGLcore.so` 6.5.7m / 6.5.22
* `unix` 6.5.22 kernel (`/mnt/europa/sgi-mame/irix-drivers/unix`)
* `Xsgi` IP22NG1, plus a GCC 15 x86-64 DWARF 5 object as the standard-DWARF regression

Scripts live in `work/scripts/` on the development host (not committed):
`Classify.java` (compare hand-asm bodies to DWARF ranges), `VerifyDwarf.java`,
`CheckAsmFlow.java`, `DumpBody.java`, `CallTargetLabels.java`, and the unit tests
`DWARFAbbreviationTest` / `MIPS_ElfExtensionTest` under the modules' `src/test`.

Current results on the 6.5.22 `unix` kernel:

* 631 CUs / 34,812 DIEs imported; 10,188 functions, all named (nested non-DWARF
  entries are labels); 12,763 DWARF types (868 structs, 572 typedefs).
* Hand-asm functions: **365/366 exactly match their DWARF body ranges** (baseline 285/366,
  with 52 clipped at nested entries and 24 disassembly gaps).
* Inline dispatch: the `emulate_lwc1/ldc1/swc1/sdc1` and `fpunit_fp*load/store_{s,d}`
  families now decompile as switches; "Could not recover jumptable" dropped from 16 to 9
  in the 366-function sample (the remainder are register-argument jump stubs and shared
  tails, not tables).
* Standard DWARF 5 `std.o` regression: identical before/after (`int foo(S * s, int x)`,
  1 struct, 11 DIEs).

Build note: this environment applies changes with a `support/patch`-style classpath
override against the 12.1.2 distribution; a normal `gradle buildGhidra` is the upstream
build path (the source checkout has no Gradle wrapper, so a system Gradle 8.x is
required).
