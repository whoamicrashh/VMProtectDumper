# VMProtect Dumper

Windows security-research tool for unpacking VMProtect-protected PE files (EXE / DLL / OCX / CPL) from memory: it reconstructs OEP and IAT, rebuilds a fresh import directory, harvests dynamically allocated executable regions and packages the artefacts into an archive for safe handling.

[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm%20NC%201.0.0-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%20x86%20%2F%20x64-lightgrey.svg)](#)
[![Language: C](https://img.shields.io/badge/Language-C%20%28WinAPI%29-a42e2b.svg)](#)
[![Status: Research / Educational](https://img.shields.io/badge/Status-Research%20%2F%20Educational-orange.svg)](#)

---

## Table of Contents

1. [Overview](#overview)
2. [What This Tool Actually Does](#what-this-tool-actually-does)
3. [SMT Engine](#smt-engine)
4. [Building](#building)
5. [Usage](#usage)
6. [Command-Line Options](#command-line-options)
7. [Operating Modes](#operating-modes)
8. [Output Files](#output-files)
9. [Memory Harvester](#memory-harvester)
10. [PE-sieve Integration](#pe-sieve-integration)
11. [DLL Targets](#dll-targets)
12. [Anti-Anti-Analysis](#anti-anti-analysis)
13. [Testing](#testing)
14. [Limitations](#limitations)
15. [Repository Layout](#repository-layout)
16. [Legal & Ethical Use](#legal--ethical-use)
17. [License](#license)

---

## Overview

The dumper runs a target under controlled conditions, waits for the protector to decrypt/unpack code sections in memory, then:

- detects OEP via SEH prolog pattern scan, CRT `__security_init_cookie` call patterns and initial thread IP;
- walks the live IAT, resolves every slot against a simulated `GetProcAddress` catalog built from the target's own export tables;
- rebuilds a fresh import directory (IDT + INT + hint/name table, Scylla-style VID) directly inside the dumped file;
- repairs PE headers in the dump (entry point, `SizeOfHeaders`, file alignment, ImageBase, DLL flag);
- runs a built-in SMT engine (mini x86/x64 emulator + bit-blasting CDCL SAT solver) over the dumped image to classify unresolved IAT slots;
- harvests dynamically allocated executable regions while the process keeps running;
- optionally runs pe-sieve against the live process;
- packages everything into a `.dat` file (rename to `.zip`) — plain or ZipCrypto-encrypted with your own password.

## What This Tool Actually Does

Everything below is implemented in code and executed on every run; nothing in this list is aspirational:

| Feature | Where | Status |
|---|---|---|
| OEP detection (SEH prolog / CRT pattern / thread IP) | `hooks.c` | works, heuristics — not guaranteed |
| Simulated `GetProcAddress` catalog | `iat_rebuild.c` | works |
| IAT patching inside the dump | `iat_rebuild.c` | works |
| Fresh import directory rebuild (VID step 4) | `iat_rebuild.c` | works; falls back to IAT-patch-only when no resolved imports |
| PE header repair in dump | `pe_parser.c` | works |
| Inline `GetProcAddress`/`LoadLibraryA/W` hooks (x64 targets only) | `hooks.c` | works on native x64; skipped on WOW64 and wine hosts (honest message) |
| Circular hook ring buffer (8192 entries, counter reset after each read) | `hooks.c` | works |
| SMT engine post-dump pass | `smtengine.c`, `smtdecoder.c`, `smtsolver.c` | works, see section below |
| Memory harvester (region snapshots, behavioral trigger) | `monitor.c` | works |
| Dropped-file capture (documents and PE files) | `monitor.c` | works |
| pe-sieve launch + result collection | `monitor.c` | works when pe-sieve is found |
| ZipCrypto archive with user password | `zip_archive.c` | works; RNG seeded from `SystemFunction036` |
| Anti-debug neutralization (PEB flags, NtGlobalFlag) | `hooks.c` | works |
| WOW64 handling | `hooks.c`, `pe_parser.c` | 32-bit targets supported via `Wow64GetThreadContext`; inline hooks skipped with a printed notice |
| TLS callback enumeration into `dump_metadata.json` | `reports.c` | works |

## SMT Engine

The post-dump engine is a self-contained symbolic analysis stack (no third-party dependencies, no SMT-LIB solver required at runtime):

1. **`smtdecoder.c`** — an x86/x64 length-decoder + mnemonic decoder covering the common subset an unpacking stub needs: ALU ops, MOV/MOVZX/MOVSX/MOVSXD, LEA, PUSH/POP/CALL/RET/LEAVE, JCC/SETCC/CMOVCC, shifts/rotates, BT/BTS/BTR/BTC/BSF/BSR, MUL/IMUL/DIV/IDIV, RDTSC, string ops with REP prefixes (MOVS/STOS), LOOP/LOOPE/LOOPNE/JRCXZ, and an SSE subset (`movups/movss/movsd/movaps/movdqa/movdqu` loads/stores, `pxor`, `xorps/xorpd`). Unsupported encodings abort cleanly with a reason string — never silently guessed.

2. **`smtengine.c`** — a mini emulator with lazy zero-filled memory pages, fake TEB/PEB (`BeingDebugged=0`), fake RDTSC, XMM register file, and a symbolic layer: GPRs are mirrored by SMT bit-vector expressions, ALU results are folded or built as DAG nodes, compare/test operands are stored, and every conditional branch appends a path constraint. Periodically (and at engine end) the engine queries the solver:
   - *divergence check*: is the not-taken direction of this branch feasible under the accumulated path? → prints `divergent` / `forced`;
   - *feasibility check*: is the current path still satisfiable at all?;
   - *final solve*: produces a model for the tracked register values at trace end.
   Real queries are written to `smt_queries.smt2` (QF_BV, check-sat included) so results can be cross-checked with an external solver.

3. **`smtsolver.c`** — a real CDCL SAT solver: Tseitin bit-blasting of the expression DAG (QF_BV subset: ADD/SUB/MUL/AND/OR/XOR/NOT/NEG/SHL/LSHR/ASHR/ROL/ROR/ZEXT/SEXT/EXTRACT/CONCAT/ITE + comparisons), two-watched-literal propagation, VSIDS decision heuristic, 1UIP clause learning, non-chronological backtracking. The engine asks it `SAT`/`UNSAT` questions over the blasted constraints — the answers decide whether an IAT slot's stub actually computes a fixed pointer, falls through with a constant, or is genuinely dynamic.

For every suspicious IAT slot the engine decodes and executes the code the slot points to. Outcomes: **resolved** (stub returns/points to a cataloged API), **already_real** (slot already holds a real VA), **unresolved** (decode abort, cap, or non-catalog address — reported with the exact reason). All traces go to `smt_trace.txt`; per-slot results to `smt_iat.json`.

Honest limits: the emulator covers the unpacking-stub opcode subset, not the whole ISA; AVX, MMX, x87, REP-CMP string ops and a number of SSE arithmetic forms abort with a message; the SAT solver handles thousands of constraints per query, not hundreds of thousands; symbolic tracking degrades to concrete execution (`fast_mode`) when the node budget is exceeded — the degradation is logged, not hidden.

## Building

```bat
x86_64-w64-mingw32-gcc-posix -O2 -s -static -o vmprotect_dumper_x64.exe *.c
```

Any MinGW-w64 (GCC ≥ 12, POSIX threading model) works; a static build is recommended so the tool runs standalone inside a VM. A 32-bit host build (`i686-w64-mingw32-gcc`) compiles the same sources but can only attach to 32-bit targets.

## Usage

```
vmprotect_dumper_x64.exe target.exe [options]
```

Drag & drop a protected PE onto the exe, or run from a console. The output folder `vmp_dump_{sample_name}` is created next to the sample.

## Command-Line Options

| Option | Effect |
|---|---|
| `--dll-export=Name` | For DLL targets: export to call (default `DllRegisterServer`, `#N` for ordinals) |
| `--wait-for=Name` | Wait for a child process with this name, attach and dump it |
| `--dropper-timeout=N` | Dropper-mode timeout in seconds, 5–300 (default 60) |
| `--force-direct` | Skip packer heuristic, use direct monitor mode |
| `--force-dropper` | Force dropper mode (launch + attach) even if target looks unpacked |
| `--kill-vmtools` | Kill VMware/VBox guest tools (breaks shared folders — copy the tool into the VM first) |
| `--no-pause` | Exit without the final "Press Enter" prompt |
| `--no-harvest` | Disable the memory harvester |
| `--no-smt` | Disable the post-dump SMT engine |
| `--no-hooks` | Disable inline API hooks (read-based IAT rebuild and SMT engine stay active) |
| `--no-antidebug` | Do not neutralize anti-debug checks |
| `--pesieve-path=PATH` | Explicit pe-sieve path (default: auto-detect next to the dumper, in CWD and `%PATH%`) |
| `--zip-password=PW` | ZipCrypto-encrypt the output archive; **without it the archive is plain** |

## Operating Modes

- **Direct monitor mode** (default for unpacked-looking EXEs): attach, monitor section fingerprints, dump when sections turn plausible (density + entropy band), then rebuild IAT/VID.
- **Dropper mode** (packed-looking EXE): copy itself next to the target, launch the target suspended via `CreateProcessA` (path is quoted), assess on attach, dump when decrypted.
- **DLL mode**: load the DLL into a sacrificial host process, invoke the chosen export, monitor, dump.
- **`--wait-for` mode**: poll the process list, attach the named child, dump.

The active mode and its decision path are written to `dropper_mode_info.txt` on every dump path.

## Output Files

```
vmp_dump_target\
  target_dumped.bin        full PE dump with repaired headers (rename to .exe for IDA)
  target_0x*.bin           per-section dumps
  resolved_imports.txt     IAT reconstruction + slot RVAs
  dump_metadata.json       PE structure, sections, data directories, TLS callbacks, IAT slots
  repair_summary.json      OEP + IAT repair results (written before archiving, included in the ZIP)
  extracted_strings.txt    raw strings from process memory
  harvest_report.txt       memory harvester timeline (T+ seconds relative to harvester start)
  region_*.bin             dynamically allocated executable regions
  dropper_mode_info.txt    which mode ran and why
  pesieve_out\             pe-sieve scan results (when found)
  smt_trace.txt            SMT engine instruction trace (capped)
  smt_iat.json             per-slot SMT verdicts
  smt_queries.smt2         real SMT2 queries emitted during the run
  smt_handlers.txt         suspected VM dispatcher handler extraction
target.dat                 output archive (rename to .zip)
```

## Memory Harvester

Snapshots the PE image region every 10 seconds (fingerprints of executable regions), logs NEW / CHANGED / DISAPPEARED regions to `harvest_report.txt`, and fires a behavioral trigger after new-file activity in watched user directories (Desktop, TEMP, %APPDATA%, %LOCALAPPDATA%, %PROGRAMDATA%). Executable regions that appear at runtime are dumped as `region_*.bin`.

## PE-sieve Integration

The tool looks for a pe-sieve binary next to itself, in the working directory and in `%PATH%` (or takes `--pesieve-path`). When found, it launches a scan against the live target after the dump and copies the results into `pesieve_out\`. Without pe-sieve the rest of the pipeline is unaffected — this is optional augmentation, not a dependency.

## DLL Targets

`vmprotect_dumper_x64.exe target.dll` loads the DLL via `rundll32`-style hosting, calls the configured export (`--dll-export=ServiceMain`, `--dll-export=#1`), monitors the host process and dumps the DLL image. Ordnal exports are supported. `dll_launcher.c` implements the host-side launch; service-DLL/svchost persistence variants exist for research scenarios where the DLL refuses to load outside a service context.

## Anti-Anti-Analysis

- PEB `BeingDebugged` = 0, `NtGlobalFlag` = 0 (both native and WOW64 PEBs);
- fake RDTSC delta inside the SMT engine;
- debug privileges acquired before attach;
- `IsDebuggerPresent`/`CheckRemoteDebuggerPresent` paths neutralized in the target;
- kill-list for known monitor processes (procmon/procexp/wireshark/fiddler/etc.) — only when `--kill-vmtools`, and never touches Python/agent/tooling processes.

## Testing

The repo ships native (Linux) test suites exercising the SMT stack without Windows:

```bash
cd tests
gcc -O2 -I.. -Ishim -o test_engine test_engine.c ../smtengine.c ../smtdecoder.c ../smtsolver.c
gcc -O2 -I.. -o test_smt   test_smt.c   ../smtsolver.c
./test_smt      # 20 solver checks: bop semantics, ITE, zext/sext, rol/ror, model + smt2 checks
./test_engine   # synthetic PE64 dump, 8 IAT slots: stub emulation, lazy-name resolve,
                # SSE load/pxor/store, rep movsq copy, 64-iteration loop, LEAVE epilogue,
                # cmp+jcc branch constraint + final SAT model, smt2/trace/json assertions
```

`tests/shim/` contains a minimal WinAPI shim so the engine and solver compile natively for testing; production builds use real MinGW headers, not the shim.

## Limitations

- x64 build hooks only x64 targets; WOW64 targets still dump via read-based IAT rebuild (stated on console).
- The SMT engine covers an unpacking-stub opcode subset; exotic encodings abort with a reason instead of guessing.
- `resolve_iat_thunks` caps at 512 slots per IAT region (printed when truncated).
- VMProtect ≥ 3.x mutation/virtualization patterns are outside the emulator's coverage; the engine reports suspected VM dispatchers into `smt_handlers.txt` instead of pretending to devirtualize.
- The archive is ZipCrypto (compatibility choice), not AES-256.
- Windows 7+ x64 targets; no arm64.

## Repository Layout

```
VMProtectDumper.c   entry point, modes, orchestration
hooks.c             OEP scan, inline API hooks, hook ring, anti-debug
iat_rebuild.c       export catalog, IAT patch, VID fresh import directory
pe_parser.c         PE parsing, section dumps, full image dump + header repair
monitor.c           harvester, dropped-file capture, pe-sieve, process lists
dropper.c           dropper mode, attach/assess (density+entropy), process wait
dll_launcher.c      DLL host launching, service/svchost variants
reports.c           dump_metadata.json (incl. TLS callbacks), resolved imports
zip_archive.c       ZipCrypto writer (crypto RNG, real dir walk, TOCTOU-safe sizes)
smtsolver.c/h       CDCL SAT solver + Tseitin bit-blaster (new)
smtengine.c/h       mini emulator + symbolic layer + query loop (new)
smtdecoder.c        x86/x64 decoder (new)
vmpd.h              shared declarations
tests/              native test suites + WinAPI shim
```

## Legal & Ethical Use

This tool is for malware analysis, CTF, software-interoperability research and authorized reverse engineering only. You are responsible for complying with the law in your jurisdiction and with the licenses of any software you analyze. Do not use it to violate licensing terms or distribute cracked software.

## License

PolyForm Noncommercial 1.0.0 — see [LICENSE](LICENSE).
[@hackerebanatik](https://t.me/hackerebanatik)

