# Ghidra — IRIX fork

This repository is a fork of Ghidra, the software reverse engineering framework by the NSA.

The fork adds support for IRIX and SGI MIPS binaries. Upstream Ghidra cannot analyse them correctly. IRIX uses MIPSpro compilers, SGI ELF extensions and ECOFF debug data.

## What the fork adds

| Area | Change |
| --- | --- |
| DWARF | Reads MIPSpro `.debug_abbrev` blocks and uses DWARF ranges for function bodies |
| ELF | Handles the SGI `SHN_MIPS_*` symbols |
| ECOFF | Imports IRIX `.mdebug` debug data from objects without DWARF |
| MIPS analysis | Recovers inline jump tables and tail calls; seeds the `gp` register |
| No-return routines | Knows IRIX routines that never return (`panic`, `sppanic`) |

The full status table is in `IRIX-SUPPORT.md`. The DWARF findings are in `DWARF-SGI-NOTES.md`.

## Use the fork

The IRIX work is pinned to Ghidra 12.1.2. There are two paths.

**Build from source.** The `irix-ultimate` branch stack carries the work:

- `ghidra-12.1.2` — the pinned release
- `feature/sgi-dwarf-parser` — the DWARF changes
- `feature/sgi-elf-symbols` — the ELF symbol changes

The `master` branch merges the same work against the current upstream.

**Patch a release.** `build-irix-patch.sh` compiles the Java changes into an installed Ghidra 12.1.2 distribution:

```sh
bash build-irix-patch.sh /path/to/ghidra_12.1.2_PUBLIC
```

## Documents

| Document | Topic |
| --- | --- |
| `IRIX-SUPPORT.md` | The status of each IRIX area |
| `DWARF-SGI-NOTES.md` | The SGI DWARF findings |
| `UPSTREAM-README.md` | The original upstream README |

## Upstream

- Project: https://github.com/NationalSecurityAgency/ghidra
- Licence: Apache-2.0
