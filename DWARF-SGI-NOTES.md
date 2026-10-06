# SGI MIPSpro DWARF 2 parser notes

Notes from adding support for the DWARF dialect emitted by the SGI MIPSpro compiler
chain (IRIX 6.5.7m .. 6.5.22, `cc` 7.2-7.4) to Ghidra's DWARF analyzer
(`Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/dwarf`), pinned to
Ghidra 12.1.2 (`Ghidra_12.1.2_build`, commit `c0f584bf229f`).

## Symptom

Importing any MIPSpro object aborted the DWARF analyzer during compilation-unit
bootstrap:

```
java.io.EOFException
  at ghidra.program.model.data.LEB128.read(LEB128.java:93)
  at ...DWARFAbbreviation.read(DWARFAbbreviation.java:53)
  at ...DWARFAbbreviation.readAbbreviations(DWARFAbbreviation.java:106)
  at ...DIEContainer.getAbbrevs(DIEContainer.java:580)
  at ...DWARFCompilationUnit.readV4(DWARFCompilationUnit.java:73)
  at ...DWARFUnitHeader.read(DWARFUnitHeader.java:59)
  at ...DIEContainer.bootstrapCompilationUnits(DIEContainer.java:264)
```

The `.debug_info` CU header itself is standard DWARF 2; the EOF happens while reading
the `.debug_abbrev` table referenced by the CU.

## Section container

* Debug sections use `SHT_MIPS_DWARF` (`0x7000001e`), not `SHT_PROGBITS`. This type is
  already registered by `MIPS_ElfExtension` and the ELF loader imports non-allocated
  debug sections as overlay blocks by default (`Import Non-Loaded Data` = true), so no
  loader change was required. Section contents in program memory are byte-identical to
  the file (relocations only touch the usual address-bearing fields).
* All observed fixtures are ELF32 big-endian with `e_flags` `EF_MIPS_ABI2` (N32) plus
  `mips3`, i.e. 4-byte addresses in a 64-bit-register ABI. The matching Ghidra language
  is `MIPS:BE:64:64-32addr` (O32 objects would use `MIPS:BE:32:default`).

## `.debug_abbrev` quirks (the actual bug)

MIPSpro emits an abbreviation section with two non-standard properties:

1. **No end-of-table marker.** A standard table ends with an abbreviation code of 0.
   MIPSpro ends the section immediately after the last entry's `(attr=0, form=0)`
   attribute-list terminator. A reader that loops until it sees code 0 reads past EOF.

2. **Per-CU blocks are concatenated, codes restart at 1.** For multi-CU binaries
   (e.g. `libGLcore.so`, the `unix` kernel) each compilation unit's abbreviation set is
   stored in a contiguous block; there is no separator between blocks. Abbreviation
   codes restart at 1 in every block. Reading from one CU's `debug_abbrev_offset` to
   EOF would absorb later blocks and `Map.put` would overwrite the earlier definitions
   of codes 1..N.

Both behaviours are visible in SGI's own libdwarf (`osprey/libdwarf/libdwarf/dwarf_abbrev.c`),
whose parse loop is guarded by

```c
} while (abbrev_ptr < abbrev_section_end && (attr != 0 || attr_form != 0));
```

i.e. it treats end-of-section as end-of-table and reads `(attribute, form)` pairs,
matching Ghidra's existing `DWARFAttributeDef.read` semantics.

### Fix

`DWARFAbbreviation.readAbbreviations()` now stops when the reader is exhausted and
stops when it encounters an abbreviation code that has already been defined (the start
of the next concatenated block). No dialect switch is needed: both rules are
no-ops for well-formed standard tables, where codes are unique and the final code-0
marker is present. The parser remains DWARF 2-5 compliant; this is why the change is
unconditional rather than gated on `DW_AT_producer`/`.debug_funcnames`.

`DWARF/Features/Base/src/test/java/.../DWARFAbbreviationTest.java` covers:
standard terminated table, missing terminator, unknown vendor attribute id, and
concatenated per-CU blocks (including reading a later block from its own offset).

## What did *not* need changing

* **CU header framing.** `unit_length`, `version=2`, `debug_abbrev_offset`,
  `address_size=4`, root `DW_TAG_compile_unit`. Multi-CU sections chain normally.
* **DIE attribute forms.** Only standard forms occur: `DW_FORM_string`, `data1`,
  `data2`, `data4`, `flag`, `block`, `addr`, `ref4`, `strp`. Every DIE in every fixture
  decoded to exactly the declared CU end offset.
* **Vendor attributes.** `DW_AT_MIPS_fde (0x2001)` and `DW_AT_MIPS_has_inlines
  (0x200b)` occur frequently; `DW_AT_MIPS_linkage_name (0x2007)` is already known to
  Ghidra. Unknown ids (including SGI's `0x42` on compile units) map to a null
  `DWARFAttributeId` and are skipped by the importer without aborting.
* **Vendor tags.** No `DW_TAG_MIPS_loop (0x4081)` was observed. Standard
  `DW_TAG_volatile_type (0x35)` and `DW_TAG_enumeration_type (0x04)` are already known
  to Ghidra.
* **Line tables.** All observed `.debug_line` programs are DWARF 2 standard, version 2,
  `opcode_base=10`, standard opcode lengths, and only standard opcodes (special
  opcodes plus `DW_LNE_set_address`/`DW_LNE_end_sequence`). No MIPSpro vendor line
  opcodes appeared, so the line state machine was left untouched.
* **`.debug_aranges`.** Ghidra's importer never reads it (the DWARF package contains no
  reference to aranges); the "pairs start at header+16" observation is in fact the
  standard `2*address_size` alignment for 4-byte addresses (12 -> 16), so there was no
  deviation to accommodate.
* **SGI-proprietary sections.** `.debug_funcnames`, `.debug_pubnames`,
  `.debug_typenames` are not read by Ghidra; names/lines come from `.debug_info` and
  `.debug_line`.

## Residual diagnostics (not failures)

* `DW_OP_breg29` frame-base expressions are reported as "un-recoverable" because the
  static evaluator has no value for MIPS `$sp` at function entry
  (`DWARFExpressionEvaluator.withStaticStackRegisterValues(null, ...)` leaves the stack
  register unmapped). Import completes and line/type/name data is unaffected. Recovering
  `$sp`-relative locals would need a static entry stack offset fed into the evaluator;
  `mips.dwarf` maps DWARF reg 29 to `sp` and reg 30 to `s8` (no `stackframe` marker).
* MIPSpro emits no `DW_TAG_formal_parameter` DIEs in the sampled kernel objects; they
  carry names/lines/types but not parameter lists, so parameter recovery is limited by
  what the compiler emitted, not by the parser.

## Verification

Fixtures (not committed, proprietary):

| fixture | result |
| --- | --- |
| `gfx.o`, `ng1.a` (6 objs), `gr2.a` (7), `mgras.a` (15) | import clean; 1 CU each; all functions DWARF-named; line info present |
| `libGLcore.so` 6.5.22 (151 CUs) and 6.5.7m (147 CUs) | import clean; ~3.1k functions, >3.0k DWARF-named |
| `unix` 6.5.22 kernel (631 CUs, 34,812 DIEs) | import clean; 10,282/10,286 functions named; 12,763 DWARF data types (868 structs, 572 typedefs, 95 unions, 37 enums); 10,199 functions carry source info |
| GCC 15 x86-64 `std.o` (DWARF 5) | before/after: identical (1 CU, 11 DIEs, 3 types, `int foo(S * s, int x)`) |

`DWARFAbbreviationTest` fails on unpatched 12.1.2 (2 of 4 tests, EOFException) and
passes with the patch.

## Adjacent IRIX gaps (separate from DWARF)

`Xsgi` (IP22NG1, 6.5.7m) has no `.debug_info` (only `.debug_frame`), so DWARF cannot
supply its names. Investigation of its symbol handling:

* `Xsgi` is an `EXEC` whose `.symtab` is stripped; all names come from `.dynsym`
  (8,763 entries). 3,852 `FUNC` symbols use `st_shndx = PRC[0xff01]` (`SHN_MIPS_TEXT`),
  928 `OBJECT` use `PRC[0xff02]`, 4 use `PRC[0xff00]`, and the remaining 3,969 are
  undefined. There is no symbol aliasing (all 3,852 function addresses are unique,
  none zero-sized).
* Stock Ghidra 12.1.2 **already applies all of them** via
  `MIPS_ElfExtension.calculateSymbolAddress`, which handles `SHN_MIPS_ACOMMON`,
  `SHN_MIPS_TEXT` and `SHN_MIPS_DATA`. A headless import yields 4,054/4,054 named
  functions; full auto-analysis adds only 40 `FUN_*` (4,094 total), so the earlier
  "only 2,391 defined FUNCs / mostly FUN_*" observation is not reproducible with this
  binary and build. The `FUN_*` seen in a directory-wide sweep are most likely local
  (non-exported) functions: global symbols live in `.dynsym`, but static functions
  would only ever be in the stripped `.symtab`, and no `.msym`/`.symlib` data can
  recover them.
* `.msym` (`SHT_MIPS_MSYM`) is 8,763 x 8 bytes: per-`.dynsym`-entry hash metadata
  (word 0 is a name hash; word 1 is a constant/version), i.e. a dynamic-linker lookup
  accelerator with no independent names or addresses. `.MIPS.symlib`
  (`SHT_MIPS_SYMBOL_LIB`) is exactly one byte per `.dynsym` entry (values 0/1/2), a
  per-symbol flag table. Neither needs to be parsed to recover symbols.
* The real gap found by sweeping the 6.5.7m objects: `SHN_MIPS_SUNDEFINED`
  (`0xff04`, small undefined) and `SHN_MIPS_SCOMMON` (`0xff03`, small common) were
  not defined or handled. 45 small-undefined symbols (eg. `GfxDevLimit`, `lbolt`,
  `shmiq_lock`) were dropped as "Unable to place symbol"; `MIPS_ElfExtension` now maps
  `SHN_MIPS_SUNDEFINED` to `Address.NO_ADDRESS` (allocated to the EXTERNAL block) and
  treats `SHN_MIPS_SCOMMON` like `SHN_MIPS_ACOMMON`, per the MIPS ABI. Verified:
  `GfxDevLimit` is now imported into the EXTERNAL block, and the Xsgi/libGLcore/unix
  and GCC DWARF 5 imports are unchanged.

## Hand-written assembly function bodies

MIPSpro emits real `low_pc`/`high_pc` ranges for hand-written assembly too (the IRIX
`LEAF`/`VECTOR`/`NESTED` macros emit `.ent`/`.end`), but the DWARF importer only used
the range for comments and created 1-byte function stubs.  Analysis then expanded the
stubs by flow following, which truncates exactly the constructs LOCORE relies on:

* `j`/`jal` to internal labels (`elocore_exl_N`, `kpreemption`, `exception_leave`);
* computed jumps into dispatch tables (`__glDTP_*` / `__glDTS_*` stubs inside
  `__glDepthTestLine_asm`, `bcopy`/`ovbcopy` inside `memcpy`);
* entries scheduled into the previous function's `jr` delay slot
  (`restartxthread`, `cache_sync` - upstream issue #4675);
* nested `STT_FUNC` symbols from assembler `EXPORT` macros, which become functions
  and clip the parent at their entry (`CreateFunctionCmd.subtractBodyFromExisting`).

Fix (all behind the new `Set Function Bodies From DWARF` import option, default on):

1. Imported subprograms are recorded with their DWARF body ranges.
2. Function entries inside a DWARF range that are not themselves DWARF subprograms are
   demoted to `IMPORTED` labels (names retained; address-taken dispatch tables keep
   working).
3. Each function body is set from its DWARF range (intersected with loaded memory).
4. A one-time low-priority `DWARFFunctionBodyFixupAnalyzer` re-applies the bodies after
   the analyzers that create function entries (shared-return, constant-propagation
   call targets) have run, since those would otherwise clip the bodies again.

Result on the 6.5.22 `unix` kernel: **365/366 hand-asm functions exactly match their
DWARF body ranges** (baseline 285/366), with zero remaining disassembly gaps.  The one
exception, `kmiss`, keeps two `locore_eret_*` shared-return thunks (16 bytes of its
range) because thunks are deliberately not demoted, so shared-return callers still
decompile.  libGLcore's 47 `__glDTP_*`/`__glDTS_*` dispatch stubs are demoted into their
parent `_asm` blob (they remain addressable labels).

Standard DWARF 5 `std.o` is unchanged by the option; the option restores the old
flow-derived behaviour when disabled.

### Inline dispatch tables

A second hand-asm idiom survives the body fixup as a decompiler warning: a computed jump
into handlers that follow the dispatcher inside the same function.

```
lui   t4,0x8800
addiu t4,t4,0x6db8      ; handler table base
sll   t5,a0,0x3         ; index * 8
addu  t4,t4,t5
jr    t4                ; "Could not recover jumptable ... Too many branches"
_nop
```

The table is code, and the index is an unbounded parameter, so neither flow following
nor the decompiler's jump-table model recovery can bound it.  `MipsInlineDispatchAnalyzer`
(MIPS module) recognises the address computation by backtracking over register views
(`t4_lo` vs `t4`), disassembles the handler entries, and writes a `JumpTable` override
plus `COMPUTED_JUMP` references so the decompiler renders a switch.  A second form loads
the target from a PC-relative pointer table (`sll/addiu/addu/lw/jr`); those entries are
also followed, but only when the loaded pointers land inside the containing function.

Results on the 6.5.22 `unix` kernel: the `emulate_lwc1/ldc1/swc1/sdc1` and
`fpunit_fp*load/store_{s,d}` families decompile as switches; "Could not recover
jumptable" in the 366-function hand-asm sample dropped from 16 to 9.  The remaining
cases are not tables: register-argument jump stubs (`jr a2`, `jr a1`), return
trampolines computed from `ra` (`jr ra - 0x20000000` in `runcached`/`uncached`), and
shared tails (`resumeidle`, `exception`).

## Changed files

* `Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFAbbreviation.java`
* `Ghidra/Features/Base/src/test/java/ghidra/app/util/bin/format/dwarf/DWARFAbbreviationTest.java`
* `Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFImportOptions.java`
* `Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFFunctionImporter.java`
* `Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFFunctionBodyFixupAnalyzer.java`
* `Ghidra/Processors/MIPS/src/main/java/ghidra/app/util/bin/format/elf/extend/MIPS_ElfExtension.java`
* `Ghidra/Processors/MIPS/src/test/java/ghidra/app/util/bin/format/elf/extend/MIPS_ElfExtensionTest.java`
* `IRIX-SUPPORT.md` (umbrella roadmap for the fork)
