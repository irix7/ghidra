# Native IRIX `ld` compact relocations (`.compact_rel`) — reverse-engineering notes

Research note, 2026-10-06 (committed to the IRIX fork docs; no SGI code or binaries included). Compiled with Ghidra 12.1.2
headless (own project `nativeld`), read-only reuse of the sister session's
helper scripts, plus static ELF inspection.

**Binary under test:** `/tmp/irix-sync/nativeld/usr/lib/ld`, ELF32 BE MIPS
"Executable", 804356 bytes, MD5 `fc6d8808c2a1be5823a22d011fd246f6`. This is
byte-identical to `/mnt/europa/sgi-mame/toolchain73/usr/lib/ld` — the MIPSpro
7.3 linker (same file). It is dynamically linked, stripped of `.symtab`, but
its `.dynsym` exports the internal function names used below.

**Oracle:** `hello.o32` built with the native `ld` itself
(`/usr/lib/ld -o32 -mips2 -call_shared -KPIC … crt1.o hello.o -lm -lc crtn.o`),
`.compact_rel` = 48 bytes, `DT_MIPS_COMPACT_SIZE` = 48.

**Corpus cross-check:** all MIPS big-endian ELFs under the oracle sysroot and
`/mnt/europa/sgi-mame/{toolchain73, toolchain73-o32, irix-drivers}` (2136 files
scanned; 20 have a compact section and/or tag).

---

## 0. Answers in brief

1. **When is an entry emitted?** Only for **o32** links (internal ABI field
   `option+0xbf8`, bits 16–22, value 0). Entries are emitted **per input
   relocation** by `rel_mips_compact_rel_pass2()` (0x10036aa0), driven by
   `relocate_pass2()` (0x1004045c); plus, when input objects carry
   `.MIPS.events.*` sections, by `mips_code_fixup()` → `mips_code_cr()`
   (0x10039300 / 0x10038770). The dominant case for PIC code is a
   **`R_MIPS_HI16` + `R_MIPS_LO16` pair against `_gp_disp`** (the `.cpload`
   `lui gp,%hi(_gp_disp); addiu gp,gp,%lo(_gp_disp); addu gp,gp,$t9`
   prologue). `need_compact_reloc_o32()` (0x10035400) additionally admits
   `R_MIPS_REL32` (3) against symbols with a flag bit, and `R_MIPS_32` (2) in
   PIC mode, for REL32/WORD/GOTHI_LO entries. It is **not** conditional on
   `__rld_obj_head`; that symbol only feeds `DT_MIPS_RLD_MAP`.
2. **Sizing / tag:** `o32_compact_rel_estimate` is accumulated in
   `rel_mips_compact_rel_pass1()` (0x100161a0) and `mips_code_cr_estimate()`
   (0x10052540); the section is created with size `estimate + 0x18` in
   `create_misc_non_alloc_sections()` (0x10074790). `fix_up_dynamic()`
   (0x10044230) writes `DT_MIPS_COMPACT_SIZE = .compact_rel sh_size`, and only
   when that section exists and the ABI is o32. Zero entries are absolutely
   possible — the 7.3 `ld` itself has no `.compact_rel` and no
   `DT_MIPS_COMPACT_SIZE`. A zero-entry section is only meaningless/harmful if
   it is emitted for a PIC object that needs GP fixups.
3. **GP / `_gp_disp` / GOT:** GPHI_LO `konst` is `gp_group_value - vaddr`
   (verified numerically against the oracle: `0x400b1c + 0x0fc0b504 =
   0x1000c020 = gp`). `del_lo` is 1 (the paired `addiu` is 4 bytes after the
   `lui`). GP per group is computed by `set_gp_value()` (0x10070300) /
   `mgot_get_gpvalue()` (0x100465f0) and exported as `DT_MIPS_GP_VALUE`
   (0x70000030) plus `.reginfo`/`.MIPS.options` (`ri_gp_value`).
   `DT_MIPS_RLD_MAP` (0x70000016) is emitted only when
   `(option+4 & 0x7f0000)>>0x13 == 4`, and points at the linker-predefined
   `__rld_obj_head`. **The 7.3 linker does not know `DT_MIPS_RLD_MAP_REL`
   (0x70000035) at all** — no `ori …,0x35` paired with `lui 0x7000`, and the
   4-byte constant does not occur anywhere in the file. No binary in the
   corpus uses tag 0x35 either.
4. **Entry format:** see §4. The native writer always emits 8-byte
   (`addend=1`, konst present) or 12-byte (`addend=3`, konst + absolute base)
   records; bfd's `Elf32_crinfo` naming is misleading (its `rtype` 4-bit field
   is really a 1-bit addend bit plus a **3-bit type**, and `dist2to`/`relvaddr`
   are `del_lo`/`del_vaddr`).

---

## 1. Where the code lives (addresses)

| Address | Name | Role |
| --- | --- | --- |
| `0x100161a0` | `rel_mips_compact_rel_pass1` | o32 estimate, called from `relocate_pass1` (0x10017978) when ABI==0 |
| `0x10036aa0` | `rel_mips_compact_rel_pass2` | o32 emit, called from `relocate_pass2` (0x1004045c) when ABI==0 |
| `0x10038400` | `enter_compact_o32` | the actual record writer (header + 8/12-byte records) |
| `0x10035400` | `need_compact_reloc_o32..BJB` | per-reloc filter for non-GP cases |
| `0x10038770` | `mips_code_cr..CO` | event type 1→GPHI_LO, type 2→GOTHI_LO |
| `0x10039300` | `mips_code_fixup` | decodes `.MIPS.events` and calls `mips_code_cr` |
| `0x10052540` | `mips_code_cr_estimate` | adds event-derived entries to the estimate |
| `0x10074790` | `create_misc_non_alloc_sections` | creates `.compact_rel` with `estimate+0x18` |
| `0x10044230` | `fix_up_dynamic` | writes DT_MIPS_COMPACT_SIZE / GP_VALUE / RLD_MAP |
| `0x100423a0` | `mips_fix_up_dynamic..ID` | DT_MIPS_LOCAL_GOTIDX … DT_MIPS_RLD_TEXT_RESOLVE_ADDR |
| `0x10035070` | `enter_compact` | *different* (non-o32 / IRIX5-style) stream writer |
| `0x100366b0` | `compact_rel_pass2..IJB` | caller of `enter_compact` (n32/64 path) |
| `0x1003e770` | `fill_compact_reloc` | zero-fills tail of the IRIX5 per-object buffers (called from `pass2`) |
| `0x10070300` | `set_gp_value` | per-GOT-group gp calculation |
| `0x100465f0` | `mgot_get_gpvalue` | `gp = post_group_table[group*0xac + 8]` |
| `0x100470b0` | `mips_odk_set_gpvalue` | stores gp into ODK_REGINFO / `.MIPS.options` |

`mips_code_cr` (whole function; note the two compact types):

```c
void mips_code_cr__CO(longlong param_1,undefined8 param_2,undefined8 param_3)
{
  if (param_1 == 1) {
    enter_compact_o32(4,param_2,param_3,4);   /* CM_R_TYPE_GPHI_LO */
  }
  else if (param_1 == 2) {
    enter_compact_o32(5,param_2,param_3,4);   /* CM_R_TYPE_GOTHI_LO */
  }
  return;
}
```

The event GPHI_LO value is `gp - vaddr` (`mips_code_fixup`, around the
`uVar31 = iVar25 - iVar14` computation; `iVar25` comes from
`post_group_table[group*0xac+8]`, i.e. `mgot_get_gpvalue`):

```c
iVar14 = *(int *)(iVar16 + 0x2c);                       /* vaddr       */
iVar25 = mgot_get_gpvalue(...);                         /* gp for group */
uVar31 = iVar25 - iVar14;                               /* konst        */
...
case 1:
  mips_code_cr__CO(1, iVar14, uVar31);                  /* GPHI_LO hi   */
case 2:
  mips_code_cr__CO(2, iVar14 + iStack_1dc*4, ...);       /* GOTHI_LO     */
```

---

## 2. When an o32 compact entry is emitted

`relocate_pass2` selects the writer by the packed ABI field
(`(option+0xbf8 & 0x7f0000) >> 0x13`):

```c
/* 0x1004045c region */
if (bVar15) {
  if ((*(uint *)(puVar16 + 0xbf8) & 0x7f0000) >> 0x13 == 0) {
    rel_mips_compact_rel_pass2(...);   /* o32   */
  } else {
    compact_rel_pass2__IJB(...);       /* other */
  }
}
```

`relocate_pass1` likewise calls `rel_mips_compact_rel_pass1` only when the ABI
field is 0. The ABI field == 0 is the same condition that gates the section
creation and `DT_MIPS_COMPACT_SIZE`.

`rel_mips_compact_rel_pass2` (decompiled, abbreviated) decides per relocation
(`*(int *)(param_2 + 0x18)` is the internal relocation kind; `param_9` is the
input ELF reloc whose `r_type` is the low nibble at +0xc, symbol index at +0xe):

```c
if (kind == 1) {                        /* GP / _gp_disp prologue case */
    if (DAT_100b49f0 == 0) {
        /* pattern-match the preceding relocations / instruction marker */
        if (... *(char *)((int)param_4 + 7) == 5 &&
               *(char *)((int)param_4 - 5) == 0x18 &&
               *(char *)((int)param_4 - 0x11) == 7 ...) {
            enter_compact_o32(4, *param_4 + param_3, DAT_100b49d0 + param_12, 4);
            return;
        }
        /* otherwise emit type 7 (HI_LO) after finding the target symbol */
        enter_compact_o32(7, sym_value + ..., DAT_100b49d0 + param_12);
    } else {
        enter_compact_o32(4, *param_4 + param_3, param_12, 4);
    }
} else if (need_compact_reloc_o32(param_9, param_1, &rel_stat)) {
    if ((DAT_100b49e4 & 4) == 0) {
        if (kind == 3)      enter_compact_o32(3, ..., DAT_100b49d0 + param_12, 0); /* WORD   */
        else if (kind == 4) enter_compact_o32(2, ..., DAT_100b49d0 + param_12, 0); /* REL32  */
    } else {                 /* PIC / dynamic variant */
        ...                  /* emits type 5 (GOTHI_LO) or type 6            */
        enter_compact_o32(5, sym_value + ..., DAT_100b49ec);
    }
}
```

`need_compact_reloc_o32` itself is narrow:

```c
r_type = rel[0xc] & 0xf;
sym    = obj->symtab + rel[0xe]*0x28;
if (r_type == 3 /* REL32 */ && (sym->flags & 4))            return 1;
if (r_type == 2 /* 32 */    && pic_object && (… >> 3 == 2)) return 1;
return 0;
```

So the concrete triggers:

* **GPHI_LO (type 4)** — the `_gp_disp` `.cpload` prologue. In the oracle
  input object `hello.o32.o` this is exactly:
  `off 0x0 R_MIPS_HI16 sym _gp_disp` + `off 0x4 R_MIPS_LO16 sym _gp_disp`
  (plus the same pair inside `crt1.o` for `__start`). The linker already
  resolves these to the final gp value in `.text`, but it *also* records the
  compact entry so rld can re-apply them if the object is loaded elsewhere.
* **GOTHI_LO (type 5)** — event type 2 / GOT-relative HI-LO pairs.
* **REL32 (type 2) / WORD (type 3)** — `R_MIPS_REL32`/`R_MIPS_32` data
  relocations that need load-bias adjustment (typically addend present).
* **HI_LO (type 7)** — HI16/LO16 pairs to runtime-resolved symbols.

`__rld_obj_head` presence is irrelevant to compact relocations; it only feeds
`DT_MIPS_RLD_MAP`.

---

## 3. Section size, `DT_MIPS_COMPACT_SIZE`, zero entries

Estimate (`rel_mips_compact_rel_pass1`; 0x100161a0):

```c
bVar1 = *(char *)((int)param_3 + 7) == 5;         /* GP-prologue marker */
if (bVar1) o32_compact_rel_estimate += 8;
if (need_compact_reloc_o32(...)) {
    uVar3 = param_3[1] & 0xff;
    if ((DAT_100b49e4 & 4) == 0) { if (uVar3==2 || uVar3==0xc) { bVar1=true; estimate += 8; } }
    else                         { if (uVar3==9 || uVar3==0x14) { bVar1=true; estimate += 8; } }
}
if (bVar1) {
    delta = (*param_3 - param_5) >> 2;            /* prev vaddr tracked in/out */
    if (param_5 == -1 || delta < -0x40000 || 0x3fffe < delta)
        o32_compact_rel_estimate += 4;            /* long form */
    return *param_3;
}
return param_5;
```

Section creation (`create_misc_non_alloc_sections`; 0x10074c60–0x10074cd8):

```c
uVar8 = *(uint *)(option + 0xbf8);
if (((uVar8 & 0x7f0000) >> 0x13 == 0) &&                     /* O32 */
    ((*(uint *)(option + 4) & 0x7f0000) >> 0x13 != 1) &&
    (o32_compact_rel_estimate != 0)) {
    if (DAT_100b2964 != 0) mips_code_cr_estimate(0);  /* event extras   */
    if (DAT_100b2958 != 0) mips_code_cr_estimate(1);  /* event extras   */
    if (dummy_obj._264_2_ == 0)                              /* section index */
        new_ld_section(<name ".compact_rel">, 0, 1,
                       o32_compact_rel_estimate + 0x18, 4, 0, 0x42, 0);
}
/* then malloc(sh_size) and attach as the section contents */
```

Tag emission (`fix_up_dynamic`; `lui 0x7000 / ori 0x2f` at 0x10044e60–68):

```c
if ((*(uint *)(option + 0xbf8) & 0x7f0000) >> 0x13 == 0) {    /* O32 */
    puVar5[i] = 0x7000002f;                                    /* DT_MIPS_COMPACT_SIZE */
    puVar5[i+1] = shdr[dummy_obj._264_2_].sh_size;             /* +0x14 in the 0x28-byte shdr */
}
```

Observations:

* Estimate is allocated *before* the final pass, so it can over- or under-count
  relative to the bytes actually written. `hello.o32` is 48 bytes with 44 bytes
  of records and a trailing zero word: pass1 counted both entries as long
  (+4 each = 24), pass2 wrote the second as short (8), leaving 4 bytes slack.
* Tail bytes are **not necessarily zero**: `libm.so` (1000-byte section, 95
  entries, records end at offset 788) has an uninitialised 212-byte alternating
  `0x00000001 / 0x00000000` pattern after the last record. The loader must
  therefore iterate the header's `num` records, not walk to `sh_size`.
* `DT_MIPS_COMPACT_SIZE` does not always equal `sh_size` in older IRIX
  libraries (`libc.so.1`: size 62704, tag 61360; `libGL.so`: 28772 vs 27856).
  The 7.3 linker writes the current `sh_size`; the older value is best read as
  the pass-1 estimate. Presence of the tag without a section is also seen:
  stripped 7.3-o32 tools (`as1`, `ujoin`, …) keep the tag but have no
  `.compact_rel` section header.
* Zero entries are normal: the 7.3 `ld` itself has no `.compact_rel` and no
  `DT_MIPS_COMPACT_SIZE`; so do the n32/64 binaries. What matters is that a
  PIC o32 object that relies on `_gp_disp` must advertise its GPHI_LO sites.

---

## 4. True entry format (IRIX `<compact_reloc.h>`, o32)

The sysroot ships the authoritative header
`/usr/include/compact_reloc.h` (comments included). The record word is:

```c
struct COMPACT_RELOC {
    unsigned addend:  2;   /* 0 NOCONST, 1 CONST, 2 BASE; writer uses 1 and 3 */
    unsigned type:    3;   /* CM_R_TYPE_*                                        */
    unsigned del_lo:  8;   /* delta to ref_lo from ref_hi, shifted 2 (i.e. /4)   */
    signed del_vaddr: 19;  /* (vaddr - previous base) >> 2, signed               */
};
#define CM_R_TYPE_NULL      0
#define CM_R_TYPE_ABS       1
#define CM_R_TYPE_REL32     2
#define CM_R_TYPE_WORD      3
#define CM_R_TYPE_GPHI_LO   4
#define CM_R_TYPE_GOTHI_LO  5   /* JMPADDR is an obsolete alias of 5 */
#define CM_R_TYPE_GPHI_LO2  6
#define CM_R_TYPE_HI_LO     7
```

Record lengths (union `cm_rlc`): `addend&1` adds a `konst` word, `addend&2`
adds a `base` word → 4/8/12 bytes. `enter_compact_o32` always sets
`addend = 1` (short: `0x40000000`) or `addend = 3` (long: `0xc0000000`), so the
native writer emits only 8-byte and 12-byte records.

Bit packing as emitted (`enter_compact_o32`, 0x100384b0–0x1003855c):

```c
/* short form (addend=1, bit30 set), 8 bytes: info, konst                    */
*info = (delta>>2 & 0x7ffff)               /* del_vaddr  */
      | ((param_4>>2 & 0xff) << 19)        /* del_lo     */
      | ((type & 7) << 27)                 /* type       */
      | 0x40000000;                        /* addend=1   */
konst = value;                             /* GP-vaddr etc. */

/* long form (addend=3, bits31+30 set), 12 bytes: info, konst, base          */
*info = (type<<27) | ((param_4>>2 & 0xff)<<19) | 0xc0000000;
konst = value;
base  = vaddr;                             /* absolute */
```

Short vs long choice: if the signed 19-bit `(vaddr - prev_vaddr)/4` fits, short;
otherwise long. The first record is always long (previous vaddr starts at -1).

Header (native init at 0x100386c8–0x100386f0; matches bfd's
`Elf32_External_compact_rel`), 24 bytes:

```
word0 id1      = 1
word1 num      = number of records
word2 id2      = 2
word3 offset   = file offset of first record (= section file offset + 0x18)
word4 reserved = 0
word5 reserved = 0
```

`num` is incremented once per written record in `enter_compact_o32`. The
loader reads `num` records from `offset`; everything after that is slack.

bfd's `Elf32_crinfo` views the same word as
`ctype:1 | rtype:4 | dist2to:8 | relvaddr:19`, which produces
`ctype=1`/`rtype=0xc` for a long GPHI_LO. In the real layout that is
`addend=3` and `type=4`; bfd's bit30 is the low bit of the addend (always set
by this writer), so bfd's `CRT_MIPS_REL32/WORD/GPHI_LO/JMPAD` = 0xa..0xd map to
native types 2..5, and bfd's `ctype` (bit31) is the addend's high bit. bfd has
no representation for addend=0 (NOCONST) or addend=2 (BASE-only) records, but
the native o32 writer never emits them either.

---

## 5. Oracle decode (cross-check)

`hello.o32` `.compact_rel` (section offset 0x5d90, size 48, tag 48):

```
00000001 00000002 00000002 00005da8 00000000 00000000     header
e0080000 0fc0b504 00400b1c                                 record 0 (12 B)
60080049 0fc0b3e0                                          record 1 (8 B)
00000000                                                   slack (4 B)
```

| # | word0 | addend | type | del_lo | del_vaddr | konst | base/vaddr | meaning |
| - | - | - | - | - | - | - | - | - |
| 0 | `0xe0080000` | 3 | 4 GPHI_LO | 1 | 0 | `0x0fc0b504` | `0x00400b1c` | `__start`+0xc |
| 1 | `0x60080049` | 1 | 4 GPHI_LO | 1 | 73 | `0x0fc0b3e0` | `0x400b1c + 73*4 = 0x00400c40` | `main` |

Both satisfy `vaddr + konst = 0x1000c020 = gp` (the value of `_gp_disp` in
the output's `.dynsym`, and `DT_MIPS_GP_VALUE` in its `.dynamic`). `del_lo=1`
matches the `lui gp` at vaddr and `addiu gp,gp,%lo` at vaddr+4; the linked
`.text` already contains `lui 0x0fc1; addiu 0xb504` (i.e. `konst` rounded), so
the loader is expected to re-apply the pair with the actual gp if the object is
displaced.

Corpus facts (same writer, same record rules): every file with a `.compact_rel`
section has `offset = section file offset + 0x18` and header `id1=1, id2=2`;
`num` matches a strict record walk (modulo the uninitialised tail noted above).
Record census (`num` records parsed with the 4/8/12-byte rule):

| file | num | addend=1/3 | type 2 REL32 | 3 WORD | 4 GPHI_LO | 5 GOTHI_LO |
| --- | --- | --- | --- | --- | --- | --- |
| `hello.o32` | 2 | 1/1 | 0 | 0 | 2 | 0 |
| `libm.so` | 95 | 94/1 | 0 | 0 | 85 | 10 |
| `libc.so.1` | 7130 | 5720/1410 | 2470 | 245 | 2584 | 1831 |
| `libpthread.so` | 361 | 360/1 | 34 | 68 | 174 | 85 |
| `libGLcore.so` | 10670 | 10669/1 | 5186 | 2725 | 2056 | 703 |
| `libgl.so` | 6009 | 6008/1 | 918 | 928 | 3039 | 1124 |

`del_lo` is 0 for the REL32/WORD entries, and 1–2 for most GPHI_LO/GOTHI_LO
entries (odd single instances go higher, e.g. 20 in `libGLcore.so`); the
native writer only ever uses addend 1 or 3.

---

## 6. What this means for the binutils fix

Current binutils 2.47 behaviour (verified in
`.scratch/worktrees/21/.scratch/binutils-build/binutils-2.47/bfd/elfxx-mips.c`):

* `mips_elf_create_compact_rel_section` creates `.compact_rel` only for
  `SGI_COMPAT` (irix5), with initial size 24 (the header) — and it is
  populated only by `mips_elf_create_dynamic_relocation` for `R_MIPS_REL32`
  (→ `CRT_MIPS_REL32`) and everything else → `CRT_MIPS_WORD`, always in long
  form (`ctype` set to `CRF_MIPS_LONG`).
* There is **no `DT_MIPS_COMPACT_SIZE` emission anywhere** (the only reference
  is the tag-name printer at elfxx-mips.c:16279), and **no `DT_MIPS_GP_VALUE`
  emission** either.
* Consequently an o32 PIC executable linked by binutils has an empty (or
  absent) `.compact_rel`, no compact tag, and no GP value. The native linker,
  by contrast, always records GPHI_LO sites for `_gp_disp` prologues and always
  emits `DT_MIPS_GP_VALUE`.

Direction for the fix (to be checked against the oracle, not yet implemented):

1. Track `_gp_disp` HI16/LO16 pairs for o32 PIC output and emit a
   `CM_R_TYPE_GPHI_LO` record per prologue: `vaddr` = address of the `lui`,
   `konst` = output gp − vaddr, `del_lo` = 1, long form when the delta to the
   previous record does not fit the 19-bit field.
2. Fix the on-disk field packing to the real `compact_reloc.h` layout
   (2-bit addend, 3-bit type) rather than the `ctype/rtype` view, or at least
   keep emitting only addend=1/3 so the sizes stay 8/12.
3. Emit `DT_MIPS_COMPACT_SIZE` in `.dynamic`, equal to the final `.compact_rel`
   `sh_size`, and set the header `offset` to section file offset + 24.
4. Emit `DT_MIPS_GP_VALUE` (0x70000030) and keep `.reginfo`/`.MIPS.options`
   `ri_gp_value` consistent.

On the reported crash: the linker code confirms these records are the
loader's mechanism for re-establishing `gp` at load time (type names
GPHI_LO/GOTHI_LO, `DT_MIPS_COMPACT_SIZE` documented as "(O32) Size of
.compact_rel"). An empty `.compact_rel` therefore removes the only data the
loader has to fix `gp` when the o32 image is not loaded at its link address
(IRIX supports displaced/non-fixed o32 images); with binutils also omitting
`DT_MIPS_GP_VALUE` and the tag, there is no fallback. Exact loader failure
mode (null compact pointer vs. silently wrong `gp`) needs rld sources, which
are not in the local tree — flagged as inference.

---

## 7. Evidence index (decompiled snippets)

Full Ghidra output retained under `/tmp/irix-sync/decomp/` (not in any repo):
`out/enter_compact_o32.txt`, `out/rel_mips_compact_rel_pass1.txt`,
`out/rel_mips_compact_rel_pass2.txt`, `out/create_misc_non_alloc_sections.txt`,
`out/fix_up_dynamic.txt`, `out/mips_code_cr__CO.txt`,
`out/mips_code_fixup.txt`, `out/need_compact_reloc_o32__BJB.txt`,
`out/relocate_pass1.txt`, `out/relocate_pass2.txt`, `out/set_gp_value.txt`,
`out/mips_fix_up_dynamic__ID.txt`, `out/mips_odk_set_gpvalue.txt`, together
with raw logs `/tmp/irix-sync/ghidra-import.log`, `/tmp/irix-sync/xref*.log`,
`/tmp/irix-sync/scan-*.log`, and the corpus scans
`/tmp/irix-sync/compact-corpus.txt`, `/tmp/irix-sync/compact-global.txt`.

Ghidra project: `/home/matt/projects/ghidra-irix/work/ghidra-projects/nativeld`
(own project; scripts under `ghidra-projects/scripts`, sources mirrored in
`/tmp/irix-sync/scripts`). No sister project or lock file was touched.
