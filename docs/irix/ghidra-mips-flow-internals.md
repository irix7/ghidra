# How Ghidra truncates hand-written MIPS function bodies

Research report for the IRIX 6.5.22 `unix` kernel (MIPS III, N32, big-endian) imported into
Ghidra 12.1.2 (`MIPS:BE:64:64-32addr`).  Read-only investigation of the checkout at
`/home/matt/projects/ghidra-irix/ghidra` plus read-only probes against the existing
`work/proj7` program.  No repository files were modified; the probe scripts live in
`work/scripts/` and all measurements are reproducible with `-readOnly -noanalysis`.

**Symptom being explained:** DWARF `DW_TAG_subprogram` DIEs carry `low_pc`/`high_pc`
ranges for hand-asm functions, but the Ghidra function bodies are much smaller (and often
end on a non-terminator).  Of the 366 asm functions catalogued in
`work/asm_func_names.txt`, the probe classifier (`work/scripts/Classify.java`) found:

| verdict | count | meaning |
| --- | --- | --- |
| body == DWARF size | 285 | correct |
| `CLIPPED_AT_NEXT_ENTRY` | 52 | body's last byte + 1 is another function's entry point |
| `DISASM_GAP` | 24 | first byte after the body is undefined; code resumes later |
| `OTHER_MISMATCH` | 5 | disjoint body / other clipping |
| entry is a delay-slot instruction | 3 | `restartxthread`, `cache_sync`, `mrlock` |

Ghidra's model forbids overlapping function bodies, so the 52 "clipped" functions are not
flow failures at all: their DWARF range is intact code, but another function entry sits
inside it.

---

## 1. Call path: from DWARF range to Ghidra body

### 1.1 ELF import creates 1-byte function stubs for every `STT_FUNC` symbol

`Ghidra/Features/Base/src/main/java/ghidra/app/util/opinion/ElfProgramBuilder.java:2136`

```java
if (elfSymbol.getType() == ElfSymbol.STT_FUNC) {
    Function existingFunction = program.getFunctionManager().getFunctionAt(address);
    if (existingFunction == null) {
        Function f = createOneByteFunction(null, address, false);
```

and `ElfProgramBuilder.java:2214`:

```java
public Function createOneByteFunction(String name, Address address, boolean isEntry) {
    ...
    function = functionMgr.createFunction(name, address, new AddressSet(address),
        SourceType.IMPORTED);
```

`st_size` is ignored; every `STT_FUNC` symbol becomes a 1-byte function regardless of
size.  This matters because the kernel assembler exports mid-function labels
(`EXL_EXPORT(elocore_exl_1)`, `kpreemption`, ...).  In `irix/kern/ml/ml.h`:

```c
#define EXL_EXPORT(sym)	EXPORT(sym)      /* when R4000 && ! _NO_R4000 */
```

and the `EXPORT` macro emits a `.globl` label whose only purpose is for `error.c` to
track EXL transitions.  They are *not* function entries, but they arrive as global
`STT_FUNC` symbols.

### 1.2 DWARF import reads the range but never applies it to the body

`DWARFFunction.read` (`DWARFFunction.java:80`) stores the DIE's PC range:

```java
DWARFRangeList bodyRanges = getFuncBodyRanges(diea);
```

`getFuncBodyRanges` (`DWARFFunction.java:355`) uses `diea.getPCRange()`, which handles
DWARF 2 `high_pc` as an address and DWARF 4+ as an offset
(`DIEAggregate.java:742`).  `getBody()` (`DWARFFunction.java:157`) converts the ranges
into an `AddressSet`.

But that body is only used for:

* the DWARF program-tree fragments — `DWARFFunctionImporter.java:254`
  `moveIntoFragment(dfunc.function.getName(), dfunc.getBody(), ...)`, and
* plate comments about disjoint ranges — `DWARFFunctionImporter.java:307-324`.

Function creation discards it (`DWARFFunction.java:424`):

```java
// create 1-byte function if one does not exist - primary label will become function names
function = currentProgram.getFunctionManager()
        .createFunction(null, address, new AddressSet(address),
                SourceType.IMPORTED);
```

`syncWithExistingGhidraFunction` (`DWARFFunction.java:366`) never calls `setBody`, and a
grep of the whole DWARF package shows only that one `createFunction` call and no
`setBody` at all.  **The DWARF range is metadata, not body data.**  Older/other loaders
behave differently (PDB calls `CreateFunctionCmd.fixupFunctionBody`,
`DefaultPdbApplicator.java:475`), so this is DWARF-importer-specific.

### 1.3 `Disassemble Entry Points` expands every 1-byte stub by flow

`EntryPointAnalyzer` runs at `AnalysisPriority.BLOCK_ANALYSIS` (=200,
`EntryPointAnalyzer.java:60`).  DWARF runs at `FORMAT_ANALYSIS.after()` (=101,
`DWARFAnalyzer.java:58`), so the stubs exist first.

* `findDummyFunctions` (`EntryPointAnalyzer.java:418`) puts every function with
  `body.getNumAddresses() == 1` into `redoFunctionSet`.
* `doDisassembly` (`EntryPointAnalyzer.java:467`) first disassembles those addresses via
  `dis.disassemble(disSet, null, true)` (`EntryPointAnalyzer.java:483`).
* `fixDummyFunctionBodies` (`EntryPointAnalyzer.java:195`) then calls, for every dummy
  entry (`EntryPointAnalyzer.java:258`):

```java
CreateFunctionCmd.fixupFunctionBody(program, function, monitor);
```

`FunctionAnalyzer` ("Subroutine References", priority 399, `FunctionAnalyzer.java:40`)
and `SharedReturnAnalyzer` ("Shared Return Calls", priority 398,
`SharedReturnAnalyzer.java:70`) also schedule `CreateFunctionCmd`s that funnel into the
same body computation.

### 1.4 The body is recomputed by flow following

`CreateFunctionCmd.fixupFunctionBody` (`CreateFunctionCmd.java:660`):

```java
AddressSetView newBody = getFunctionBody(program, entry, false, monitor);
...
func.setBody(newBody); // trigger analysis
```

`getFunctionBody(program, entry, includeOtherFunctions=false, monitor)`
(`CreateFunctionCmd.java:613`) does not follow calls
(`RefType.COMPUTED_CALL/CONDITIONAL_CALL/UNCONDITIONAL_CALL/INDIRECTION`,
line 622) and delegates to `FollowFlow.getFlowAddressSet` (`FollowFlow.java:942`).

`FollowFlow.followInstruction` (`FollowFlow.java:557`) additionally refuses fallthrough
into a function symbol when `followIntoFunction == false`:

```java
if (!followIntoFunction) {
    nextSymbolAddr = getNextSymbolAddress(nextAddress, nextSymbolAddr);
    if (nextSymbolAddr != null && nextSymbolAddr.equals(nextAddress)) {
        Symbol symbol = program.getSymbolTable().getPrimarySymbol(nextAddress);
        if (symbol.getSymbolType() == SymbolType.FUNCTION) {
            nextAddress = null;
        }
    }
}
```

So the body can only contain bytes that were both *disassembled* and *reachable by flow*;
no decoded-but-unreachable code (computed jumps, tables) is included.

### 1.5 Overlap clipping is the last write to the body

`FunctionDB.setBody` (`FunctionDB.java:347`) → `FunctionManagerDB.setFunctionBody`
(`FunctionManagerDB.java:979`) → `NamespaceManager.setBody` (`NamespaceManager.java:131`),
which throws `OverlappingNamespaceException` at `NamespaceManager.java:142`.
`fixupFunctionBody` catches it (`CreateFunctionCmd.java:688-694`) and calls
`subtractBodyFromExisting` (`CreateFunctionCmd.java:407`):

```java
if (overlapFuncBody.getNumAddresses() == 1) {
    overlapFuncBody = getFunctionBody(program, overlapEntryPoint, false, monitor);
    ...
}
...
if (overlapEntryPoint.compareTo(entry) < 0) {
    overlapEndAddr = newFuncBody.getMaxAddress();
}
else {
    // overlap function is after, subtract from entry to entry of overlapping function
    overlapEndAddr = overlapEntryPoint.previous();
}
AddressSet overlapAddrsShouldBeInNewFunction = new AddressSet(entry, overlapEndAddr);
AddressSetView newOverlapFuncBody =
    overlapFuncBody.subtract(overlapAddrsShouldBeInNewFunction);
```

This is exactly the `CLIPPED_AT_NEXT_ENTRY` verdict: any function entry inside the flow
body carves the parent at that entry.  `fixDummyFunctionBodies` iterates a `HashSet`
(`EntryPointAnalyzer.java:196`), so the final fragmentation can be order-dependent: a
parent expanded *after* a nested placeholder loses everything from the nested entry
onward, whereas one expanded *before* is carved around it.  Observed in the probe:

```
88004200 VEC_int               body=16  [88004200..8800420f]
88004210 elocore_exl_1         body=48  [88004210..8800423f]
88004240 tfp_special_int_exit  body=348 [88004240..43d3] (hole around kpreemption)
88004384 kpreemption           body=56  [88004384..43bb]
880043d4 arcs_write            body=64  [880043d4..88004413]   <-- VEC_int DWARF ends here
```

### 1.6 No automatic recomputation exists in the function database

`FunctionDB` has no `ProgramChangeListener`; bodies change only via explicit
`setBody`/`createFunction`.  There is no `FunctionBody` algorithm class; the canonical
"recompute" is `CreateFunctionCmd.getFunctionBody` + `FollowFlow`.  `FunctionDB.getBody`
simply reads the namespace address set (`FunctionDB.java:330-345`).

---

## 2. MIPS flow model and delay slots

All definitions are shared by the 32/64-bit big-endian specs via
`Ghidra/Processors/MIPS/data/languages/mips32Instructions.sinc`.

* **`break` is NOT a terminator.**  `mips32Instructions.sinc:96` emits only the
  `trap(tmp)` `define pcodeop` (`mips.sinc:984`), a `CALLOTHER`; `walkTemplates`
  (`SleighInstructionPrototype.java:200`) sets no `NO_FALLTHRU` for `CALLOTHER`, so
  control falls through.  `sstepbp`'s 4-byte body is simply its DWARF size; it is not a
  truncation example.
* **`syscall` likewise falls through** (`mips32Instructions.sinc:703`, `mips.sinc:986`).
* **`eret` IS a terminator:** `mips32Instructions.sinc:193`:

  ```
  :eret  is ... {
      JXWritePC(EPC);
      return[EPC];
  }
  ```

  `PcodeOp.RETURN` sets `RETURN | NO_FALLTHRU`
  (`SleighInstructionPrototype.java:263-265`).  `deret` is the same
  (`mips32Instructions.sinc:159`).  Nothing else in the MIPS analysers stops flow at
  `eret`; the spec does.
* **Branch delay slots** are declared with `delayslot(1)` (`j` 225-228, `jr` 306-320,
  `jr ra` 342-350, `jalr` 237-264, all branches 52-92).
* **The leading `_` is a display artefact**, not an instruction name.
  `SleighInstructionPrototype.getMnemonic` (`SleighInstructionPrototype.java:1334`):

  ```java
  if (this.isindelayslot) {
      mnemonic = "_" + mnemonic;
  }
  ```

  `isindelayslot` is set from the `inDelaySlot` flag at construction (line 108).
  The   `Disassembler` parses the instruction after a branching instruction with
  `language.parse(..., true)` in `parseDelaySlots` (`Disassembler.java:1376`).
  `getFallThroughOffset` (`SleighInstructionPrototype.java:575-596`) makes a delay-slot
  instruction's own fallthrough be the byte after *its* delay slots (0 here, so `+4`).

### 2.1 Delay slots straddle function boundaries

The kernel idiom (6.5.7m source, `irix/kern/ml/process.s`; same shape in 6.5.22) is:

```
END(resumethread)
LEAF(restartxthread)
	.set	noreorder
	MFC0(v0,C0_SR)
```

The assembler schedules the first instruction of `restartxthread` into the delay slot of
the previous function's `jr ra`.  Probe output:

```
88005490  li v0
88005494  jr ra
88005498  _mfc0 v0      dslot=true owner=jr@88005494   <-- restartxthread entry
8800549c  <undefined>
```

`cache_sync` shows the same shape (`_sd t4` at 0x88011f2c under `jr@88011f28`).
This is a known unsupported case, GitHub issue #4675 ("ghidra failed to identify the
function when analysing files for the MIPS:BE:32 architecture", emteere: *"Ghidra doesn't
currently support branching into the delay-slot, so it messes with analysis"*).

Why the tail never gets disassembled:

* `EntryPointAnalyzer.doDisassembly` uses the `AddressSet` overload,
  `Disassembler.java:487`:

  ```java
  Data data = listing.getUndefinedDataAt(nextAddr);
  if (data == null) {
      ...
      undefinedRanges = program.getListing().getUndefinedRanges(todoSubset, true, monitor);
      todoSubset = new AddressSet(undefinedRanges);
  }
  ```

  An entry that is already an instruction (the delay-slot `mfc0`) is dropped, so 0x8800549c
  is never decoded.

* The single-address overload would also skip it (`Disassembler.java:615`):
  `if (cu instanceof Instruction) { continue; }` before the delay-slot resume logic at
  `Disassembler.java:988-1005`.
* Consequently `FollowFlow` stops at the first undefined instruction and the body is the
  4-byte delay slot.

---

## 3. MIPS analysers

`Ghidra/Processors/MIPS/src/main/java/ghidra/app/plugin/core/analysis/`:

* `MipsPreAnalyzer` ("MIPS UnAlligned Instruction Fix", priority 201) only merges
  `lwl/lwr`, `ldl/ldr`-style pairs; it does not touch bodies.
* `MipsAddressAnalyzer` (extends `ConstantPropagationAnalyzer`, priority 596) can call
  `CreateFunctionCmd.fixupFunctionBody` (`MipsAddressAnalyzer.java:285`) after detecting a
  pseudo-call via a constant `ra`, and after jump-table recovery.  Any fixup re-runs the
  flow/overlap body computation above.
* `MipsSymbolAnalyzer` (priority 96) only relocates MIPS16 odd-address symbols; no effect
  on N32 even addresses.
* `MIPS_ElfExtension.creatingFunction` (`MIPS_ElfExtension.java:339`) only adjusts the
  ISA mode bit; it does not set bodies.

---

## 4. Ranked candidate root causes

### C1 — DWARF ranges are never applied to bodies (design gap; affects all 366)

*Where:* `DWARFFunction.java:424-427` (`createFunction(..., new AddressSet(address), ...)`),
and the absence of any `setBody(dfunc.getBody())` in `DWARFFunction.syncWithExistingGhidraFunction`
(`DWARFFunction.java:366-440`).

*Fix:* create the function with `dfunc.getBody()` and, when a function already exists,
`function.setBody(dfunc.getBody())`.  Intersect the range with
`getLoadedAndInitializedAddressSet()` (see the guard already at line 408) and fall back to
the current 1-byte stub on `OverlappingFunctionException`.  This is only safe together
with C2, otherwise nested ELF stubs immediately re-carve the body.

### C2 — Mid-function ELF `STT_FUNC` labels become functions and clip their parent (dominant for 52/81)

*Where:* `ElfProgramBuilder.java:2136` + `ElfProgramBuilder.java:2214`;
`EntryPointAnalyzer` expansion (`EntryPointAnalyzer.java:418`, `:195-260`);
clipping in `CreateFunctionCmd.subtractBodyFromExisting` (`CreateFunctionCmd.java:436-443`).

*Evidence:* the 366 DWARF asm ranges are pairwise disjoint (checked with a script); the
nested entries are therefore not DWARF subprograms.  `VEC_int` body is exactly
`[0x88004200,0x8800420f]` because `elocore_exl_1@0x88004210` is a function.  Removing the
three nested functions and re-running `fixupFunctionBody` yields the full 468-byte DWARF
range (experiment E1 below).

*Fix:* in `DWARFFunctionImporter.importFunctions` (or immediately after the subprogram
pass), demote to a plain label any function whose entry lies strictly inside a DWARF
subprogram range and is not itself a DWARF subprogram start (e.g.
`functionManager.removeFunction(addr)` while keeping/creating the symbol).  These export
labels are referenced by data, not called, so demotion loses nothing.  Doing it in the
DWARF importer is safe because DWARF (101) runs before `EntryPointAnalyzer` (200).  A
narrower variant is to only demote entries whose `Function.getSignatureSource()` is
`DEFAULT` (i.e. no DWARF signature).

### C3 — A function entry that is a delay-slot instruction is never disassembled (24 gap cases, 2 confirmed)

*Where:* `Disassembler.disassemble(AddressSetView,...)` early skip
(`Disassembler.java:487-497`), single-address skip (`Disassembler.java:615-617`), and the
resume logic that exists but is unreachable (`Disassembler.java:988-1005`,
`DisassemblerQueue.queueDelaySlotFallthrough`, `DisassemblerQueue.java:285`).

*Evidence:* `restartxthread` and `cache_sync` entries are delay-slot instructions.  After
clearing the entry instruction and re-disassembling, `restartxthread` reaches the full
92-byte DWARF range (experiment E2).

*Fix:* in `EntryPointAnalyzer.doDisassembly` (or the `AddressSet` overload), when the
start address is an existing instruction with `isInDelaySlot()`, queue
`instr.getMaxAddress().next()` as a disassembly start instead of silently skipping it
(basically surface the `queueDelaySlotFallthrough` path).  `FollowFlow` then walks the
straight-line code.  A belt-and-braces fix in `CreateFunctionCmd.getFunctionBody` is to
follow `instr.getFallThrough()` when the entry is in a delay slot, but the bytes must be
disassembled first, so the `Disassembler` change is the real one.

### C4 — Computed jump tables are not followed and are not part of the flow body

*Where:* `FollowFlow` only traverses existing flow references; `getFunctionBody` does not
follow calls/indirection (`CreateFunctionCmd.java:622`).  `emulate_lwc1` body is 24 bytes
ending at `jr t4`; the branch targets at 0x88006db8 are only reachable via that computed
jump, so `FollowFlow` never sees them even after they are disassembled (experiment E3).

*Fix options:* (a) rely on C1 to set the DWARF body (the range contains the stub table);
(b) extend `MipsAddressAnalyzer` switch-table recovery to emit references from the
`jr t4` base+index pattern to each stub; (c) accept a body that contains undefined bytes
(interspersed data).  This is the same class as open Ghidra issue #2030
("MIPS32 disassembling stops").

### C5 — Later heuristics can clear flow or add entries

* "Shared Return Calls" (`SharedReturnAnalyzer.java:37`) is **enabled by default for
  MIPS** (language property default true,
  `GhidraLanguagePropertyKeys.java:135`; `getDefaultEnablement` at
  `SharedReturnAnalyzer.java:82`).  With "Assume Contiguous Functions Only" defaulting to
  `true` (`SharedReturnAnalyzer.java:54`), unconditional jumps across other functions are
  converted to call-return and `SharedReturnAnalysisCmd.createFunction`
  (`SharedReturnAnalysisCmd.java:259-272`) creates new nested entries → more C2 clipping.
* "Non-Returning Functions - Discovered" (`FindNoReturnFunctionsAnalyzer.java:43`,
  priority 302) with "Repair Flow Damage" default `true`
  (`FindNoReturnFunctionsAnalyzer.java:66-70`) can clear instructions after calls it
  judges non-returning (`:139-145`, `:169-190`), which converts body tails into the
  `DISASM_GAP` shape.  `break`/`syscall` fall through in the spec, so this can misfire on
  kernel trap stubs.

These are second-order, but they explain why some gaps exist beyond C1–C4 and are the only
user-tunable mitigations today.

---

## 5. Existing options and hooks

| Option / hook | file:line | default | relevance |
| --- | --- | --- | --- |
| `DWARFImportOptions`: Import Functions, Import Data Types, Create Function Signatures, Import Local Variable Info, Output DIE Info, ... | `DWARFImportOptions.java:29-160`, fields `122-143` | mostly `true` | **No option controls function bodies.**  Even "Import Functions" off leaves ELF stubs. |
| "Shared Return Calls" (enable/disable) | `SharedReturnAnalyzer.java:37`, `:82-100` | enabled | can create nested function entries |
| "Assume Contiguous Functions Only" | `SharedReturnAnalyzer.java:44`, `:54` | `true` | cross-function jumps become call-return |
| "Allow Conditional Jumps" | `SharedReturnAnalyzer.java:47`, `:55` | `false` | as above |
| "Non-Returning Functions - Discovered" | `FindNoReturnFunctionsAnalyzer.java:43` | enabled | marks stubs non-returning |
| "Repair Flow Damage" | `FindNoReturnFunctionsAnalyzer.java:60-70` | `true` | clears flow after non-returning calls |
| "Function Non-return Threshold" | `FindNoReturnFunctionsAnalyzer.java:49-52` | `3` | evidence threshold |
| "Non-Returning Functions - Known" | `NoReturnFunctionAnalyzer.java:36` | enabled | data-driven only |
| "Disassemble Entry Points" → "Respect Execute Flag" | `EntryPointAnalyzer.java:39-43` | `true` | only memory gating |
| MIPS "Attempt to recover switch tables", "Assume T9 set to Function entry", "Recover global GP register writes", "Mark Dual Instruction" | `MipsAddressAnalyzer.java:44-57`, `:728-757` | mostly `true` | switch recovery can call `fixupFunctionBody` |
| ELF loader options | `ElfLoaderOptionsFactory.java:34-110` | — | no symbol→function control; stubs are unconditional |

There is **no option, extension point, or `DWARFFunctionFixup`** that applies DWARF
ranges to bodies.  `DWARFFunctionFixup` implementations
(`dwarf/funcfixup/*.java`) only touch signatures/storage.

---

## 6. Minimal experiments to confirm each hypothesis

All scripts are in `work/scripts/`; run under
`work/run-headless.sh <proj> sgi -process unix -noanalysis -readOnly -scriptPath work/scripts -postScript <script>`
(changes are in-memory only).

* **E1 – C2 (clipping).**  `Classify.java` maps the population; `Experiments.java` removes
  the nested functions inside `VEC_int`'s DWARF range, then calls
  `CreateFunctionCmd.fixupFunctionBody`.  Result observed:
  `E1 VEC_int body now 468 [[88004200, 880043d3]]` — exact DWARF size.  Confirms the
  16-byte body is caused solely by nested entries.
* **E2 – C3 (delay-slot entry).**  `Experiments.java` clears the delay-slot instruction at
  0x88005498, re-disassembles from the entry, then fixes up.  Result observed:
  `E2 disassembled [[88005498, 880054f3]]`, `E2 restartxthread body now 92` — exact DWARF
  size.  Confirms the skip in `Disassembler.disassemble(AddressSetView,...)`.
* **E3 – C4 (computed jump).**  Disassembling the stub table at 0x88006db8 succeeds
  (`[[88006db8,88006dbf]]`) but `emulate_lwc1`'s body stays 24 bytes because `jr t4`
  creates no flow to the table.  Confirms reachability, not decoding, is the limiter.
* **E4 – C5 (options).**  On a throwaway copy of the project, disable "Shared Return Calls"
  and "Non-Returning Functions - Discovered" (and set "Repair Flow Damage" off), re-run
  auto-analysis, then re-run `Classify.java`.  Expect the flat-clip counts to be
  unchanged, and only `OTHER`/gap counts to move.  This isolates heuristic damage from
  C1–C4.
* **E5 – C1+C2 (proposed fix).**  A post-import script (or the C1/C2 patch): demote
  non-DWARF function entries inside DWARF ranges, disassemble each DWARF range, then set
  each function's body from its DWARF range.  Re-run `Classify.java`; expect 366/366
  matches, with `DISASM_GAP` only where the range genuinely contains undecodable bytes.
* **E6 – C3 patch.**  After changing the `Disassembler` skip logic, re-run `E2` without
  the manual `clearListing`: body should reach 92 bytes straight away.

---

## 7. Prior art (collected in `work/research/scratch/ghidra-mips-issues.json`)

* **#4675** "ghidra failed to identify the function when analysing files for the
  MIPS:BE:32 architecture" — delay slot of the previous function's `jr` holds the next
  function's first instruction; *"Ghidra doesn't currently support branching into the
  delay-slot, so it messes with analysis a bit"*.  Exactly `restartxthread`/`cache_sync`.
* **#2030** "MIPS32 disassembling stops" — computed switch/jump tables not recovered;
  same class as C4.
* **#2422** "MIPS disassembly stop with a Bad Instruction" and **#8262** "PIE-enabled MIPS
  binaries have incomplete disassembly" — adjacent MIPS flow-coverage gaps.
* **#6025** "MIPS binaries with debug symbols incorrectly loaded" — labels/functions
  created in the middle of real function bodies by symbol-driven stubs (the C2 family).

## 8. Code-comment sweep (delay slots / boundaries / asm)

* `FollowFlow.java:352` — *"Delay adding instructions in delay slots to the functions body
  until the end.  This allows for branches into the delay slot to be handled correctly."*
  (Only true for the *initial* address set; it does not help an entry that is itself a
  delay slot, because `pushInstruction` requires the address to already be an
  instruction.)
* `FollowFlow.java:557-569` — fallthrough deliberately stops at function symbols when
  `followIntoFunction` is false.
* `Disassembler.java:933`, `:996`, `:1050` — special handling for flow into existing delay
  slots, but only inside `disassembleInstructionBlock`, which the `AddressSet` overload
  never reaches for an already-defined entry.
* `CreateThunkFunctionCmd.java:628-629` — *"any instruction with a delay slot is actually a
  branching instruction.  only do this for instructions that aren't delay slot
  instructions"*; thunk detection has the same blind spot.
* TODOs at `DWARFFunction.java:344` (`dw_at_entry_pc` unused) and
  `DWARFFunction.java:407` (external placement) document adjacent gaps in the same file.

---

### Summary of the answer to "where/why do bodies get truncated?"

1. The DWARF range is never copied into the Ghidra body — the importer creates 1-byte
   stubs (`DWARFFunction.java:424-427`).
2. The body is later recomputed by flow (`EntryPointAnalyzer.java:258` →
   `CreateFunctionCmd.fixupFunctionBody` → `FollowFlow`).
3. Anything not decodable-and-reachable is dropped; entries that are delay-slot
   instructions are never even disassembled (`Disassembler.java:487-497`).
4. If the flow body overlaps a mid-function ELF label stub, the non-overlap rule clips it
   at that entry (`CreateFunctionCmd.java:436-443`).
5. Nothing puts the DWARF range back afterwards, so the truncation is permanent.
