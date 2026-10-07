# Prior art: decompiling IRIX 6.5.x MIPSpro binaries with Ghidra

Research report (agent A, external prior-art sweep), 2026-10-06.
Base: local Ghidra `12.1.2` (`Ghidra_12.1.2_build-6-gd6719e8f59`, upstream base
`c0f584bf229f`), fork already carrying MIPSpro `.debug_abbrev` and
`SHN_MIPS_SUNDEFINED` fixes.

Scope: IRIX/SGI MIPS reverse engineering with Ghidra, with emphasis on the current
gap - hand-written assembly control flow (DWARF `low_pc`/`high_pc` present, but
Ghidra bodies truncated; `eret`-terminated handlers; branch-in-delay-slot;
"Could not recover jumptable"). Methods: local scratch mining, `gh search
repos/code/issues/prs`, GitHub API, DuckDuckGo; no large clones.

---

## 0. Executive summary (most actionable)

1. **No existing project solves this wholesale.** Nothing found parses SGI/MIPSpro
   DWARF or mdebug and *repairs Ghidra function bodies* for hand-written asm.
2. The closest working precedent is the PS2 extension
   `chaoticgd/ghidra-emotionengine-reloaded`: its `StabsImporter` builds the
   function with an **explicit address range** from debug data
   (`CreateFunctionCmd(name, low, new AddressSet(low, high-1), ...)`,
   `src/main/java/ghidra/emotionengine/symboltable/StabsImporter.java:344-427`).
   That is exactly the technique we need, minus IRIX/SGI ELF support.
3. `.mdebug` PDRs and STABS `ST_END`/`text_end` records carry **exact function
   sizes**: `N64Recomp/src/mdebug.cpp:75-93` (ST_END value = size),
   `ccc/src/ccc/mdebug_analysis.cpp:136-141` (`text_end(name, function_size)`),
   `N64Recomp/src/mdebug.h:137-180` (PDR `sym_bounds`).
4. In stock Ghidra 12.1.2 the DWARF importer **parses** the debug body range
   (`DWARFFunction.java:355-364`, `DW_AT_low_pc`/`high_pc`/`DW_AT_ranges`) but only
   uses it for comments; the Ghidra function is created as **1 byte**
   (`DWARFFunction.java:426`) and its body is later invented by disassembly flow.
   That is the root cause of `VEC_int` body=16 vs `hi-lo=0x1d4` in our
   `work/asmflow.tsv`.
5. Ghidra cannot follow **branching inside a delay slot**; upstream says so
   explicitly (issues #4675, #4325). IRIX LOCORE does this (e.g. `vec_int.s`
   `beq ...; j tfp_special_int` in the delay slot), so flow-based bodies are
   untrustworthy for LOCORE - bodies must be pinned from debug ranges.
6. `eret` is already modelled as a return in 12.1.2
   (`mips32Instructions.sinc:193` `return[EPC]`; `:159` `deret` `return[DEPC]`).
   No SLEIGH change needed for `eret` itself; the truncation is a body-discovery
   problem, not an `eret`-decoding problem.
7. Recommended fix: a small post-DWARF **body-repair analyzer/script** that (a)
   disassembles the whole `[low_pc, high_pc)` range, (b) calls
   `Function.setBody(AddressSet)`, (c) demotes interior alternate-entry symbols
   (`EXPORT`/`XLEAF`/`.aent` like `locore_exl_N`) to labels so they cannot chop
   the parent. Precedent for `setBody` on a created function:
   `CreateFunctionCmd.java:311`.
8. No fork handles SGI ELF symbols (`SHN_MIPS_*`), `.debug_funcnames`, or IRIX
   kernel asm. `SHN_MIPS_SUNDEFINED` appears in the wild only as an ELF constant
   copy (`wisk/medusa`, `allkern/iris`); upstream only handles
   `ACOMMON/TEXT/DATA` (`MIPS_ElfExtension.java:315-319`, ours patched at
   `:371-376`).
9. Best non-Ghidra boundary heuristics: `spimdisasm`
   (`spimdisasm/mips/sections/MipsSectionText.py:127-193`): user-declared size >
   "another known function starts here" > `jr $ra` only if no branch escaped
   (`farthestBranch == 0`) > tail jump to a known function. Its `farthestBranch`
   accumulator is a good model for keeping mid-function branch targets inside the
   body.
10. Jump-table recovery for MIPS is weak upstream (#2030 open; `MipsSwitchTableAnalyzer`
    does **not** exist in 12.1.2 - it is added by open PR #8547). Portable ideas:
    N64Recomp's explicit `JumpTable` struct/scanner
    (`N64Recomp/include/recompiler/context.h:43`) and spimdisasm's
    `isJumptableJump` handling.

---

## 1. Projects and artefacts (summary table)

### 1.1 Ghidra extensions and forks

| Project / URL | What it is | Solves | Gap for us |
| --- | --- | --- | --- |
| https://github.com/astrelsky/ghidra_mdebug | Extension: ECOFF `.mdebug` parser + analyzer | Names/local symbols, file names, line numbers, stack frame size; creates functions at `stProc`/PDR addresses; demangles | **No function body logic** (`MdebugAnalyzer.java:169-233` sets name + `frame.setLocalSize(pdr.getFrameoffset())` only). Targets Ghidra 9.2-10.0, last commit 2022-07-14. No DWARF, no SGI ELF symbols. Forks `VelocityRa` (2021) and `wagrenier` (2022) are no newer |
| https://github.com/chaoticgd/ghidra-emotionengine-reloaded | PS2 Ghidra extension; STABS analyzer for `.mdebug` | Recovers functions, types, globals from PS2 `.mdebug` STABS; **creates functions with explicit low/high ranges**; MIPS-R5900 analyzers | PS2-specific loader/analyzer; no IRIX/SGI ELF, no MIPSpro DWARF. Its range technique is directly reusable |
| https://github.com/kotcrab/ghidra-allegrex | PSP Allegrex processor module | Allegrex ISA, `Allegrex_ElfExtension`, address/pre analyzers | PSP only; `PpssppImportSymFile.py` creates **labels only**, ignores symbol sizes |
| https://github.com/pspdev/psp-ghidra-scripts | PSP helper scripts | NID resolution, hardware registers | No function bodies |
| (upstream PR) https://github.com/NationalSecurityAgency/ghidra/pull/8547 | Open PR, Oct 2025: MIPS indirect tail calls + signature analyzers | Adds `MipsDecompIndirectCallAnalyzer`, `MipsFunctionSignatureAnalyzer`, `MipsFunctionPointerAnalyzer`, `MipsInlineCodeAnalyzer`, `MipsDriverAnalyzer`, `MipsSwitchTableAnalyzer`, `FixFunctionSignatures.java`; types the `UNRECOVERED_JUMPTABLE` target at `jr/jalr` sites | Open/unmerged; not in 12.1.2. Useful source of ideas for `jalr $t9`/`jr $t9`; does not fix bodies |

### 1.2 Debug-format parsers (mdebug / STABS / ECOFF)

| Project / URL | What it is | Solves | Notes |
| --- | --- | --- | --- |
| https://github.com/chaoticgd/ccc | "Chaos Compiler Collection", C++ PS2 `.mdebug` STABS parser | `stdump` JSON/C++ export of functions, types, globals; function **size from STABS `text_end`** (`src/ccc/mdebug_analysis.cpp:136-141`) | The `address_range` (`low`/`high`) it emits is what the PS2 Ghidra importer consumes. Mirrors SGI's `Mdebug.ps` and STABS docs in `docs/mirror/` |
| https://github.com/N64Recomp/N64Recomp | N64 static recompiler | Ships a full big-endian mdebug parser (`src/mdebug.cpp`, `src/mdebug.h`): HDRR/FDR/PDR/SYMR/AUX, `MAGIC=0x7009`, file-relative→section-relative relocation; `ST_PROC`/`ST_STATICPROC` + `ST_END` value = function **size**; PDR `sym_bounds()`; ELF `STT_FUNC` `st_size` bounds function words (`src/elf.cpp:107-115`) | Its recompiler consumes ELF symbol sizes, not mdebug sizes, for code; but the parser is a clean reference implementation |
| https://github.com/felinis/CodeMatcher | PS2 MDEBUG symbol extraction + code function matcher | Finds function code from mdebug symbols | Python; small |
| https://github.com/Rozelette/libultra-mdebug, https://github.com/Rozelette/print-mdebug | mdebug printers (libultra context) | Symbol/procedure dump | Reference only |
| https://github.com/ReGlacier/XeXe | ".mdebug explorer" | GUI inspection | Few stars, reference only |

### 1.3 N64 / PSX / PS2 ecosystems (delay slots, boundaries)

| Project / URL | Techniques worth stealing |
| --- | --- |
| https://github.com/Decompollaborate/spimdisasm | `MipsSectionText._findFunctions_checkFunctionEnded()` (`spimdisasm/mips/sections/MipsSectionText.py:127-193`): end at user-declared size; end when another trustable function symbol begins at `current+8`; end at `jr $ra` **only if `farthestBranch == 0`** (no branch escaped the current range); treat non-linking jump to a known function as tail-call/end; special-case redundant `jr $ra; nop; jr $ra; nop`; `isLikelyHandwritten` override. `farthestBranch` is accumulated in `_findFunctions_branchChecker` (`:69-113`) |
| https://github.com/N64Recomp/N64Recomp | Delay-slot-aware code generation (`src/recompilation.cpp:209-262` `process_delay_slot`, `print_return_with_delay_slot`, `print_goto_with_delay_slot`); "likely" branch tracking `in_likely_delay_slot` (`:825-863`); explicit `JumpTable` struct (`include/recompiler/context.h:43`) with `lw`/`addu`/`jr` addresses and GOT offset |
| https://github.com/vitorpy/fsn | Full IRIX MIPS Ghidra decompile of `fsn` ("File System Navigator"), 78k LOC, restored. Evidence of IRIX+Ghidra pain points and workarounds: function end = `jr ra` (+8 for delay slot) or next `addiu sp,sp,-N` prologue (`docs/DECOMPILATION_PROCEDURE.md:70-78`, `analysis/disassemble_function.py:464-509`); `jalr t9` annotated with target symbol; GP offset resolution (`resolve_got.py`); `unaff_gp`, `CONCAT44`, `extraout_*` corruption catalogue | This is a concrete, published IRIX-specific Ghidra workflow we can mine for our own fixtures |
| https://github.com/chaoticgd/ghidra-emotionengine-reloaded | See above; also `MipsR5900PreAnalyzer` for instruction re-parsing in `INSTRUCTION_ANALYZER` at very high priority | Shows how to fix instruction pairing before flow analysis |
| https://github.com/allkern/iris | PS2 emulator | Dead end for IRIX; only defines `SHN_MIPS_SUNDEFINED` in `src/elf.h` |

### 1.4 IRIX sources and IRIX-specific decompilation

| Project / URL | What it is | Relevance |
| --- | --- | --- |
| https://github.com/calmsacibis995/irix-657m-src | Complete IRIX 6.5.7m source release (also `irix-655-src`) | Published ground truth for LOCORE asm, `asm.h` macros, PDR-bearing `.ent/.end`, `ERET_PATCH`, `VECTOR()`; the same tree our scratch clone (`irix7/irix6`, sparse `irix/kern/ml|sys`) is based on |
| https://github.com/irix7/irix6 (our in-house fork) | Source + `decompiled/` sweep (kernel graphics/dmedia objects, scripts `ForceFuncsJava.java`, `FixAndRedumpJava.java`) | Our own prior art: confirms this exact problem space; `decompiled/docs/REGISTER-MAP.md` etc. are about drivers, not LOCORE |
| Local IRIX source (scratch) `irix6/irix/kern/sys/asm.h:55-103` | `LEAF`, `XLEAF`, `VECTOR`, `NESTED`, `XNESTED`, `END` macros | `LEAF`/`VECTOR`/`NESTED` emit `.ent name,0`, `.frame`, `.mask`; `END` emits `.end`. These produce the mdebug PDR extents (and hence DWARF `low_pc`/`high_pc`) even for hand-written asm |
| `irix6/irix/kern/ml/LOCORE/vec_int.s:29` + `:484` | `VECTOR(VEC_int, M_EXCEPT)` ... `END(VEC_int)` | Exact debug range 0x88004200-0x880043d4; our `work/asmflow.tsv` shows Ghidra body = 16 |
| `irix6/irix/kern/ml/ml.h:370-374`, `:424` | `ERET_PATCH(xx)` -> `j _r4600_2_0_cacheop_eret; nop` or bare `eret` | Why many LOCORE "returns" are `eret` or an indirect jump to a patched eret trampoline, and why some functions have no `jr ra` at all |
| `irix6/irix/kern/ml/LOCORE/exception_exit.s:232-235` | `NOP_0_4 # LDSLOT to set EPC before eret` then `ERET_PATCH(...)`; delay-slot load idiom throughout (`lreg ra,EF_RA(k1) # LDSLOT`) | `eret` after branch delay slots; LOCORE deliberately puts real work in delay slots |
| `irix6/irix/kern/ml/LOCORE/vec_int.s:36-40` | `beq s1,zero,1f` / `j tfp_special_int` in the delay slot (TFP config) | A concrete branch-in-delay-slot instance Ghidra cannot follow (#4325/#4675) |
| `irix6/irix/kern/ml/LOCORE/exc_vec.s:34-45` | `nop; nop; j exception; nop # BDSLOT` | Jump-only stubs; body is shorter than any "return" heuristic expects |

---

## 2. Ghidra upstream issues and PRs

State as fetched on 2026-10-06. `S/R` = state/reason.

### 2.1 Delay slots, delay-slot branching

| # | S/R | Title / key content |
| --- | --- | --- |
| [#4325](https://github.com/NationalSecurityAgency/ghidra/issues/4325) | closed/COMPLETED | "Branch flow in delay slot not followed in disassembly". Ghidra1: flow flags of a delayed instruction do not account for flow *inside* the delay slot. Closed as a known limitation (points to discussion #4241) |
| [#4675](https://github.com/NationalSecurityAgency/ghidra/issues/4675) | open | MIPS BE function misidentified because a `jr`'s delay slot is the *first instruction of the next function*. Emteere: "Ghidra doesn't currently support branching into the delay-slot" |
| [#862](https://github.com/NationalSecurityAgency/ghidra/issues/862) | closed/COMPLETED | MIPS16e PC-relative `LW` in `JAL/JALX/JR` delay slots; context of resurrected delay-slot instruction is wrong. Closed 2025; comment says proposed fix was "not the correct fix" |
| [#4259](https://github.com/NationalSecurityAgency/ghidra/issues/4259) | closed/COMPLETED | Context propagation to delay-slot instructions; Ghidra1 explains resurrected-prototype caching; closed as design limitation |
| [#1314](https://github.com/NationalSecurityAgency/ghidra/issues/1314) | closed/COMPLETED | `delayslot(n>1)` silently becomes 1; pointed at `sleigh.xml` docs |
| [#3840](https://github.com/NationalSecurityAgency/ghidra/issues/3840) | closed/COMPLETED | Overlay address spaces break disassembly of the last delayed instruction |
| [#2816](https://github.com/NationalSecurityAgency/ghidra/issues/2816) | closed/COMPLETED | `jr $ra` missed when the *next* word is not disassembled yet (delay-slot parse ordering); user cleared/re-disassembled; no code fix |

### 2.2 Function bodies, truncation, DWARF/asm

| # | S/R | Title / key content |
| --- | --- | --- |
| [#1645](https://github.com/NationalSecurityAgency/ghidra/issues/1645) | open | "Numerous truncated functions after analysis - painful to fix by hand" (x86 Delphi, but the same generic body-truncation class). Workarounds: delete unreferenced bogus functions, re-create; root cause is over-permissive function start patterns |
| [#9476](https://github.com/NationalSecurityAgency/ghidra/issues/9476) | open (Aug 2026) | "DWARF importer locks a void(void) signature onto functions defined in assembly". `DW_AT_prototyped` is never consulted; asm `DW_TAG_subprogram` (name + low/high pc, no params) is committed as definite `void f(void)` `SourceType.IMPORTED`, locking parameter storage. Directly analogous to MIPSpro asm functions |
| [#3223](https://github.com/NationalSecurityAgency/ghidra/issues/3223) | closed/COMPLETED | "Invalid length 0 for DWARF Compilation Unit at 0x0 with MIPSPro binaries" (64-bit MIPSpro uses a 64-bit initial-length field non-standardly); Ghidra fixed the DWARF64 length special case. Our 32-bit/N32 fixtures pass with the `.debug_abbrev` patch |
| [#1379](https://github.com/NationalSecurityAgency/ghidra/issues/1379) | closed (2020) | ".mdebug support (MIPS Debug Format)". Never merged; astrelsky built the external extension. Ghidra 12.1.2 still has no `mdebug` in `Features/Base` (grep: no hits) |
| [#1389](https://github.com/NationalSecurityAgency/ghidra/issues/1389) | closed | File-offset-to-address API guidance used by the mdebug extension |

### 2.3 Non-returning functions

| # | S/R | Title / key content |
| --- | --- | --- |
| [#1981](https://github.com/NationalSecurityAgency/ghidra/issues/1981), [#889](https://github.com/NationalSecurityAgency/ghidra/issues/889) | closed/COMPLETED | The non-returning-function analyzer can wrongly mark functions no-return, add flow overrides after every call, then re-apply after manual fixes. Recommended workaround: `FixupNoReturnFunctionsScript`, or disable the analyzer. Relevant to LOCORE where a truncated body has no visible terminator |
| `NoReturnFunctionAnalyzer.java` (known names list) | in-tree | Only marks names from data files (e.g. `exit`, `abort`); IRIX `panic`/`SPPANIC` will need entries in MIPS data files or a custom analyzer |
| `FindNoReturnFunctionsAnalyzer.java:41-62` | in-tree | Evidence-threshold based discovery, optional flow repair and bookmarks |

### 2.4 Jump tables and `jalr $t9`

| # | S/R | Title / key content |
| --- | --- | --- |
| [#2030](https://github.com/NationalSecurityAgency/ghidra/issues/2030) | open | MIPS32 disassembly stops at `jr v0`; decompiler "Could not recover jumptable ... Too many branches". Ghidra1: switch-table recovery depends on the decompiler recognising the guard; gp/t9 values were known but it still missed it |
| [#729](https://github.com/NationalSecurityAgency/ghidra/issues/729) | closed/COMPLETED | MIPS switch detection with `sltiu/bne/sll/lwx/addu/jr`; resolved after GregoryMorse's switch work (#850) |
| [#2551](https://github.com/NationalSecurityAgency/ghidra/issues/2551) | closed (2025-06) | MIPS local GOT call `lw t9,off(gp); jalr t9` decompiled as `_gp`-relative indirect call; cause is `lw gp,0x10(s8)` reload. No fix; workaround is `nop` the gp restore |
| [PR #8547](https://github.com/NationalSecurityAgency/ghidra/pull/8547) | open | Directly targets `UNRECOVERED_JUMPTABLE` at MIPS indirect tail calls; adds post-decompiler typing of the call target, plus the signature/inline/switch analyzers listed in section 1.1 |

### 2.5 Loader / SGI ELF symbols

| # | S/R | Title / key content |
| --- | --- | --- |
| [#1527](https://github.com/NationalSecurityAgency/ghidra/issues/1527) | open | IRIX 32-bit big-endian `libc.so.1` cannot be parsed (`.MIPS.options`, `.msym`); no fix |
| [#6025](https://github.com/NationalSecurityAgency/ghidra/issues/6025) | closed/COMPLETED | MIPS loader mangles binaries whose symbols claim large areas; Ghidra1: clear the undefined arrays (`Windows->Defined Data`) and re-analyse; no loader change |
| [#356](https://github.com/NationalSecurityAgency/ghidra/issues/356) | open (reopened) | `ecoff-bigmips` not recognised by COFF loader; unresolved since 2019. We do not need it (SGI ELF path), but it confirms ECOFF support is absent upstream |
| [#1959](https://github.com/NationalSecurityAgency/ghidra/issues/1959) | open | MIPS `B:32` ELF parsing issue; see also [#1531], not IRIX-specific |

---

## 3. Reusable techniques with code pointers

### 3.1 Authoritative function extents from debug data

**Ghidra + STABS ranges (closest precedent).**
`ghidra-emotionengine-reloaded/src/main/java/ghidra/emotionengine/symboltable/StabsImporter.java`:

```java
// lines 344-361
if(def.addressRange.valid()) {
    Address low = toAddr(def.addressRange.low);
    Address high = toAddr(def.addressRange.high - 1);
    AddressSet range = new AddressSet(low, high);
    Function function = findOrCreateFunction(def, low, high, range);
```
```java
// lines 411-427
if(high.getOffset() < low.getOffset()) {
    cmd = new CreateFunctionCmd(new AddressSet(low), SourceType.ANALYSIS);
} else {
    cmd = new CreateFunctionCmd(def.name, low, range, SourceType.ANALYSIS);
}
```

The `high` comes from ccc `stdump`'s `address_range`, i.e. mdebug-derived function size.
This is the pattern to copy: **create the function with the full address range**.

**mdebug sizes without DWARF.**
- `N64Recomp/src/mdebug.cpp:75-93`: `ST_PROC` starts a pending symbol; the following
  `ST_END` sets `pending_sym.size = symr.value` (the value field is the size).
- `N64Recomp/src/mdebug.h:137-180`: `PDR` layout plus `sym_bounds()` (first `ST_PROC`
  symbol's AUX `isym` points at the `ST_END` marker) - a way to bound a procedure
  even if you only trust PDRs.
- `ccc/src/ccc/mdebug_analysis.cpp:136-141`:
  ```cpp
  Result<void> LocalSymbolTableAnalyser::text_end(const char* name, s32 function_size)
  {
      if (m_state == IN_FUNCTION_BEGINNING) {
          m_current_function->set_size(function_size);
  ```
- `N64Recomp/src/elf.cpp:107-115`: when only ELF symbols exist,
  `uint32_t num_instructions = type == STT_FUNC ? size / 4 : 0;` - i.e. bound the
  function to `st_size`.

**Our data.** `irix6-tree.txt` and `work/asm_func_names.txt` already show the exact
DWARF `[lo, hi)` pairs for 365 asm functions; `work/asmflow.tsv` compares them with
Ghidra bodies.

### 3.2 Ghidra 12.1.2 parses DWARF body ranges but never applies them

Exact evidence in our tree:
- `Ghidra/Features/Base/src/main/java/ghidra/app/util/bin/format/dwarf/DWARFFunction.java:355-364`:
  ```java
  public static DWARFRangeList getFuncBodyRanges(DIEAggregate diea) throws IOException {
      DWARFRange body = diea.getPCRange();
      if (!body.isEmpty()) { return new DWARFRangeList(body); }
      if (diea.hasAttribute(DW_AT_ranges)) { return diea.getRangeList(DW_AT_ranges); }
  ```
- The same class creates a 1-byte function when none exists (`:424-427`):
  ```java
  // create 1-byte function if one does not exist - primary label will become function names
  function = currentProgram.getFunctionManager()
      .createFunction(null, address, new AddressSet(address), SourceType.IMPORTED);
  ```
- `grep -rn 'setBody' .../format/dwarf/` returns nothing - the DWARF body range is
  used for plate comments, EOL comments and inline-function children, not for
  `Function.getBody()`.
- The same 1-byte pattern exists in `ExternalDebugFileSymbolImporter.java:115`.
- Setting a body later is supported and proven: `CreateFunctionCmd.java:311`
  `func.setBody(origBody); // trigger analysis`; the public API is
  `Function.setBody(AddressSetView)`.

Conclusion: a body-repair pass is not fighting the design; it is simply supplying
the body the importer already knows but discards.

### 3.3 Delay-slot-aware boundary heuristics (what to do when debug data is absent)

`spimdisasm/mips/sections/MipsSectionText.py:127-193` is the best written-down
algorithm found:

```python
# lines 133-136 - user-declared size wins
if currentFunctionSym is not None and currentFunctionSym.userDeclaredSize is not None:
    if instructionOffset + 8 == currentInstructionStart + currentFunctionSym.getSize():
        functionEnded = True
# lines 143-146 - next known function starts at +8
funcSymbol = self.getSymbol(currentVram + 8, ...)
if funcSymbol is not None and funcSymbol.isTrustableFunction(...):
    if funcSymbol.vromAddress is None or currentVrom + 8 == funcSymbol.vromAddress:
        functionEnded = True
# lines 148-166 - jr $ra only ends if nothing branched outside
if not functionEnded and not (farthestBranch > 0) and instr.isJump():
    if instr.isReturn():
        ...
        functionEnded = True
    elif instr.isJumptableJump():
        pass                      # leave to jump-table recovery
    elif not instr.doesLink():
        if isLikelyHandwritten or ...: functionEnded = True
        elif instr.isJumpWithAddress():
            # tail call to a known function ends the body
```

`farthestBranch` is updated at `:69-113`: any branch target beyond the current
instruction extends the candidate function body, so a mid-body `jr $ra` (shared
epilogue) does not terminate scanning. That is directly applicable to LOCORE,
where many blocks end in `j exception_leave` or a shared `eret` path.

N64Recomp is the other end of the spectrum: it requires explicit function symbols
and does not guess (`src/elf.cpp:107-115`), but it handles every delay-slot case
correctly when emitting code (`src/recompilation.cpp:209-262`).

### 3.4 Non-returning asm stubs and `eret`

- Ghidra 12.1.2 already compiles `eret` to `JXWritePC(EPC); return[EPC]`
  (`Ghidra/Processors/MIPS/data/languages/mips32Instructions.sinc:193`) and
  `deret` to `return[DEPC]` (`:159`). A function whose last parsed instruction is
  `eret` therefore *does* have a return terminator; our `CheckAsmFlow.java` simply
  lists `eret` as a terminator too.
- The failure mode is bodies never reaching the `eret` (branch-in-delay-slot,
  shared exits, or an alternate entry chopping the range) - i.e. §3.2/§3.3 again.
- For genuine no-return stubs (`PANIC`/`SPPANIC` call sites, `_r4600_2_0_cacheop_eret`
  trampoline, `tlbdropin`-style code with no return path), use
  `Function.setNoReturn(true)` or the known-names path
  (`NoReturnFunctionAnalyzer.java`, `FindNoReturnFunctionsAnalyzer.java:41-62`).
  Note upstream warnings (#1981/#889) about the discovery analyzer adding incorrect
  flow overrides; prefer a curated name list for IRIX (`panic`, `sppanic`,
  `_r4600_2_0_cacheop_eret`, `backtouser_rsa`, ...).

### 3.5 Jump table hints

- N64Recomp's `JumpTable` (`include/recompiler/context.h:43-54`) records
  `lw_vram`, `addu_vram`, `jr_vram`, `addend_reg`, `got_offset`, `entries` - a
  concrete scanner result we could mirror to add references/labels at table sites
  so the decompiler's guard analysis has data references to work with.
- spimdisasm distinguishes `isJumptableJump()` from ordinary `jr` in both boundary
  detection and output (`spimdisasm/mips/sections/MipsSectionText.py:167`,
  `spimdisasm/mips/symbols/analysis/InstrAnalyzer.py:478-487`).
- Ghidra upstream still fails on MIPS guards (#2030) and `MipsSwitchTableAnalyzer`
  is only in open PR #8547. If our kernel jump tables use the classic
  `sltiu/bne; sll; lw/addiu; addu; jr` PIC sequence (issue #729), the decompiler
  can sometimes recover them; when it cannot, the warning is "Could not recover
  jumptable ... Too many branches" and the fallback is setting a manual switch
  override or porting the PR's analyzer.

### 3.6 IRIX LOCORE specifics (why debug ranges are the only reliable authority)

- `VECTOR(x, regmask)` (`irix/kern/sys/asm.h:72-79`) expands to
  `.globl x; .ent x,0; x:; .frame sp,EF_SIZE,$0; .mask ...`; `END(proc)` is
  `.end proc` (`:100-102`). Assembler turns `.ent`/`.end` into PDR records; with
  `-g`, MIPSpro emits DWARF `DW_TAG_subprogram` with `low_pc`/`high_pc` from the
  same data. So the DWARF range is *the* function extent, including for asm.
- Many LOCORE functions contain alternate exports: `EXL_EXPORT(locore_exl_N)` /
  `XLEAF` / `.aent` labels inside the parent body (`vec_int.s`, `exception_exit.s`,
  `backtouser.s`). These become `SHN_MIPS_TEXT` symbols and are prime suspects for
  Ghidra creating an interior function that chops the parent body to 16 bytes.
  The fix is to treat interior alternate entries as labels (or alias/thunk
  entries with the same body), not as separate functions.
- Branch-in-delay-slot is endemic and intentional:
  - `vec_int.s:36-40` (`beq` + `j` delay slot, TFP path),
  - `exc_vec.s:34-45` (`j exception` with `nop` BDSLOT; a 4-instruction stub whose
    "body" is still delimited by `.ent/.end`),
  - `exception_exit.s:232-235` (`NOP_0_4 # LDSLOT to set EPC before eret`).
  Ghidra explicitly cannot represent the flow of a branch in a delay slot
  (#4325, #4675), so `VEC_int`-style truncation at the first such pair is expected.
- `ERET_PATCH` (`ml.h:370-374`, `:424`) means an "eret" may be a `j` to a patched
  trampoline (`_r4600_2_0_cacheop_eret`) followed by `nop`; a body ending there has
  no local `eret` at all.

---

## 4. Recommended approach for our fork

The following is ordered by leverage and is based only on techniques already
proven elsewhere.

### Step 0 - keep the language/loader fixes separate
DWARF `.debug_abbrev` and `SHN_MIPS_SUNDEFINED` fixes stay as-is. Do not add
`.debug_funcnames` reading: no existing parser uses it; local notes confirm names
come from `.debug_info`.

### Step 1 - add a post-import "debug range body repair" analyzer/script
Input per function: `[low_pc, high_pc)` from `DWARFFunction.getFuncBodyRanges()`
(already parsed) or, for objects without DWARF, mdebug PDR/ST_END
(`N64Recomp/src/mdebug.cpp:75-93` shows the exact field semantics; PDR table base
is already read by our loader/`ghidra_mdebug` for other purposes).
Algorithm:
1. Run after the DWARF analyzer, before decompiler-dependent analyzers
   (`AnalysisPriority` after `FORMAT_ANALYSIS`, or a one-shot script).
2. For each DWARF function start with a valid range:
   `Disassembler.getDisassembler(program, monitor, null).disassemble(lo, new AddressSet(lo, hi.subtract(1)))`
   so the *entire* range is decoded, including delay slots, even if flow cannot
   reach them.
3. `Function f = getFunctionAt(lo); f.setBody(new AddressSet(lo, hi.subtract(1)))`
   (API used by `CreateFunctionCmd.java:311`; creation-with-range precedent:
   `StabsImporter.java:411-427`).
4. Record plate comments with the debug range so later passes can distinguish
   pinned bodies from flow-derived ones (mirror `DWARFFunctionImporter.java:315`
   style "DWARF func body range[...]").

### Step 2 - stop alternate entries from chopping parent bodies
Before Step 1 (or in the same pass), for each `STT_FUNC`/`SHN_MIPS_TEXT` symbol
whose address lies strictly inside another function's debug range and which is an
alternate entry (owner `EXPORT`/`XLEAF`/`EXL_EXPORT`, or simply no DWARF
`DW_TAG_subprogram` of its own):
- demote it to a `SourceType.IMPORTED` label (or create it as a thunk whose body
  unions with the parent), and
- do not create a separate `Function` there.
This is the likely mechanism behind `VEC_int` body=16. `StabsImporter.importFunctions`
shows the opposite choice (trust debug ranges over ELF symbol starts); emulate
that precedence: **DWARF/mdebug range > ELF symbol**.

### Step 3 - delay-slot handling
No SLEIGH change is needed: MIPS delay slots are already inlined (`delayslot(1)`
in the MIPS language), and `eret` is already a return. The only delay-slot work
left is body discovery, which Step 1 bypasses. If we later need flow for functions
*without* debug ranges (e.g. stripped userland), port the spimdisasm
`farthestBranch`/`jr $ra` rules (`MipsSectionText.py:127-193`); do not attempt to
model branches inside delay slots - upstream does not (#4325).

### Step 4 - non-returning asm
Add an IRIX no-return name list through the existing known-names mechanism
(`NoReturnFunctionAnalyzer.java`) for `panic`, `sppanic`, `_r4600_2_0_cacheop_eret`,
etc. Optionally disable `FindNoReturnFunctionsAnalyzer` for kernel projects to
avoid the #1981 override churn. Do not force no-return merely because a body lacks
a terminator; Step 1 makes terminators unnecessary.

### Step 5 - jump tables
Keep the current warning measure in `CheckAsmFlow.java`, but add a jump-table
scanner modelled on N64Recomp's `JumpTable` (pattern `lw`/`addiu` + `addu` + `jr`,
GOT-relative addend) that creates data labels at table entries before decompiling.
For stubborn cases, evaluate porting PR #8547's `MipsSwitchTableAnalyzer` and
`MipsDecompIndirectCallAnalyzer` (the latter also addresses `jr/jalr $t9` tail
calls and `UNRECOVERED_JUMPTABLE` call sites). Both are self-contained and
MIPS-specific.

### Step 6 - verification
Re-run `work/scripts/CheckAsmFlow.java` over `work/asm_func_names.txt` after the
repair pass and assert:
- `body == hi - lo` for 366/366 (currently `VEC_int 16 vs 0x1d4`),
- no decompile with "Could not recover jumptable" where a table is known,
- `term` is informational only; `eret` bodies may legitimately have no `jr`.
Fixtures: the `unix` 6.5.7m kernel object(s) and `libGLcore.so` already used for
the DWARF work (per `ghidra/DWARF-SGI-NOTES.md`).

---

## 5. Explicit dead ends

- **No existing extension/loader parses SGI ELF symbols beyond upstream.**
  `SHN_MIPS_SUNDEFINED` appears only as an ELF constant in `wisk/medusa`
  (`src/ldr/elf/elf.h`) and `allkern/iris` (`src/elf.h`); neither processes it.
  Our local patch (`MIPS_ElfExtension.java:371-376`) is ahead of the ecosystem.
- **`astrelsky/ghidra_mdebug` cannot be the fix.** It is a names/frame/lines
  analyzer for standalone ECOFF `.mdebug`, Ghidra <=10.0, unmaintained since
  2022-07; its forks are older. It has no body or DWARF logic.
- **`.debug_funcnames`, `.debug_pubnames`, `.debug_typenames`**: `gh search code`
  finds no parser; Ghidra never reads them (confirmed in `DWARF-SGI-NOTES.md`);
  do not spend time there.
- **ECOFF loader work**: Ghidra #356 (open since 2019, reopened) is a dead end for
  us; SGI ELF import is the working path.
- **`wisk/medusa`**: no MIPS ECOFF/mdebug support; only an `elf.h` constant.
  (Scratch clone deleted to reclaim ~21 MB.)
- **`Dwarf1Functions.java`** (scratch): a JSON-model signature/type applier copied
  for reference; it has no control-flow or body logic.
- **`kotcrab/ghidra-allegrex` / `pspdev/psp-ghidra-scripts`**: label/NID import
  only; symbol sizes in PPSSPP `.sym` files are explicitly discarded
  (`PpssppImportSymFile.py` strips `,size`).
- **Generic Ghidra "truncated function" cure**: #1645 has no accepted fix; the
  advice (delete/re-create, fix patterns) does not apply to debug-range-pinned
  bodies - ours must come from the debug data, not from pattern heuristics.
- **`eret` SLEIGH work**: unnecessary; `return[EPC]` is already in 12.1.2.

---

## 6. Evidence log

Search commands used (all GitHub results via `gh`, plus DuckDuckGo):

```
gh search repos "ghidra mdebug" | "ghidra irix" | "ghidra sgi" | "sgi mips"
gh search repos "irix kernel" | "irix reverse engineering" | "mipspro"
gh search code  "debug_funcnames" | "SHN_MIPS_SUNDEFINED" | "mdebug ghidra"
gh search code  "locore_exl" | "ERET_PATCH" | "VEC_int"
gh search issues --repo NationalSecurityAgency/ghidra "delay slot"
gh search issues ... "eret" | "non-returning" | "jalr" | "jumptable" | "ECOFF"
gh search issues ... "truncated function" | "DWARF assembly function" | "IRIX" | "MIPSpro"
gh search prs    ... "MIPS delay" | "MIPS function" | "ECOFF" | "function body" | "DWARF function"
gh search prs    ... "delay-slot"
```

Local artefacts inspected (scratch, unchanged unless noted):
`ghidra-issues-detail.txt`, `ghidra-mips-issues.json`, `ghidra_mdebug/`
(astrelsky, full source), `irix6/` (sparse IRIX 6.5.7m source, LOCORE + asm.h +
ml.h), `irix6-tree.txt` (`decompiled/` sweep listing), `ccc/`, `N64Recomp/`,
`spimdisasm/`, `ghidra-emotionengine-reloaded/`, `fsn/`, `medusa/` (deleted),
`sgi_mcp_scripts/`, `Dwarf1Functions.java`, `libdwarf.sgifixes.patch`,
`sgi-forum-libdisk.html` (Ghidra mention on an IRIX user forum - anecdotal only).
Local Ghidra source cited at `/home/matt/projects/ghidra-irix/ghidra` under
`Features/Base`, `Processors/MIPS`.

Top-level takeaway: the ecosystem gives us proven *extraction* (mdebug/STABS
sizes and DWARF ranges) and proven *Ghidra insertion* (`CreateFunctionCmd` with
explicit range / `setBody`), but nobody has joined them for SGI/MIPSpro. The
missing piece is ours to build and is small.

---

## 7. Empirical test of the prior art (7 October 2026)

Every runnable tool above was installed and run against our IRIX 6.5.7m fixtures
(N32 `libgl-657m-n32.so`, o32 `libGLcore.so` / `libGLcore-657m-o32.so`, the N32 `unix`
kernel). Clones/builds under a scratch `/dev/shm` tree; nothing adopted without evidence.

| tool | ran? | result on IRIX | verdict |
| --- | --- | --- | --- |
| spimdisasm 1.42.4 | yes | SGI **ELF** OK, but **no `.mdebug`/`.symlib`** support (reads `.dynsym`/`.symtab` `st_size`).  o32 `libGLcore`: function **set 3184/3184** and sizes **3046/3047** match our `EcoffDebug`.  **Stock fails catastrophically on the `unix` kernel** (307 of 366): a size‑4 `nop` stub (`assbuffer`) makes `_findFunctions_checkFunctionEnded`'s `offset+8 == start+size` unsatisfiable, so it swallows the remaining 2.7 MB; a `size<=4` guard fixes it (→ 9,734 functions).  With ELF `st_size`: 351/366 exact; pure `farthestBranch`/`jr $ra` heuristics only **158/366 (43%)**. | adopt as oracle; confirms trusting debug/`st_size` over flow |
| m2c (matt-kempster) | yes | o32 straight-line and GP-relative-table functions decompile well (`arcs_write` clean; `__glNptAntiAliasLineRGBA` full once the `.gpword` table is supplied).  **N32 PIC fails**: the `__do_zspan_*_asm` dispatchers use a **GOT-loaded absolute** jump table and m2c asserts (`jtbl list must not be empty`); it also needs a context header and has no SGI/N32 `$t4`/`$t9` model. | partial / mine-for-ideas |
| print-mdebug (Rozelette) | yes | parses SGI `.mdebug` with **0 errors**, 3,218 PDRs / 216 FDs.  Confirms the PDR `adr` is **file-descriptor-relative** (`fd.adr + pdr.adr`) — the quirk our `EcoffDebug` already applies. | adopt as verifier |
| N64Recomp mdebug parser | yes | magic `0x7009` matches; gated out only by `vstamp != 0` (IRIX 0x728/0x715).  Relaxed, and tolerating `ST_LABEL`/`ST_STATIC` between `ST_PROC` and `ST_END`, it recovers **3,184/3,184 exact** procedure ranges — an independent cross-check of `EcoffDebug`. | adopt as a 2-line port for cross-checking |
| ccc `stdump` | built | dead-end: `src/ccc/elf.cpp` has no `e_ident[EI_DATA]` handling (reads our BE headers as LE) and its mdebug check is LE-only (`fBigEndian` rejected). | dead-end |
| fsn (vitorpy) | yes | not Ghidra scripts (standalone Python + `objdump`); hardcodes fsn's GP so it is wrong on our binaries; first-`jr ra` end rule is strictly weaker than spimdisasm's; no `CONCAT44` fixer. | mine the prose checklist only |
| ghidra-emotionengine-reloaded | builds on 12.1.2 | its explicit-range `StabsImporter` is exactly the technique our `DWARFFunctionBodyFixupAnalyzer`/`EcoffAnalyzer` now implement. | superseded (reference only) |
| ghidra_mdebug (astrelsky) | fails | targets Ghidra 9.2; two `dwarf4.next` imports removed in 12.1.2; no body logic. | dead-end (confirmed) |
| CodeMatcher, XeXe, libultra-mdebug, ghidra-allegrex, psp-ghidra-scripts, iris, medusa | — | LE/PS2-only, labels-only, or a lone `SHN_MIPS_SUNDEFINED` constant. | dead-end |

Net: **no tool is adoptable wholesale for IRIX** — our fork already equals or beats each
(spimdisasm/N64Recomp/print-mdebug independently confirm our 3,218 PDR / 3,184 unique
numbers, and our DWARF-pinned bodies beat every flow heuristic).  Two ideas are worth
keeping: N64Recomp's mdebug parser as an independent range oracle, and the GOT-loaded
absolute jump-table shape m2c cannot read (moot in Ghidra now that the SGI-prelinked
`R_MIPS_REL32` fix recovers the `__*_zspan_*_asm` dispatchers).

**Cross-check (oracle vs `EcoffDebug`, 8 o32 fixtures).**  The N64Recomp-derived oracle
(`work/prior/mdump-iri/`) matches `EcoffDebug` on every common procedure.  Every
disagreement is a case where the linear oracle is provably weaker: it reads an inner
`ST_END` for `libdmedia.so` (all 700 sizes short), and it cannot bind grouped
`PROC,PROC,PROC,END,END,END` records in `libgl` (40 procedures lost).  `EcoffDebug` is
PDR/AUX-driven, and already tolerates a non-zero `vstamp` (0x715/0x728) and interleaved
`ST_LABEL`/`ST_STATIC` between `ST_PROC` and `ST_END`, so **no production change was
needed**; three regressions were pinned instead (`EcoffDebugTest`, 23 tests).  The oracle
is kept as an independent second opinion for the ECOFF path.
