# Capsule noise check

Date: 2026-11-04. Scope: the capsule file `capsule.bin` of class `bare` (6 291 456 bytes), printed and initiated with the `ksg-capsule` tool of this repository.

**Claim under test.** The capsule is one fixed-size file that looks like random noise: no format header, no code, no readable text, no repeated structure that would let a bystander tell what it is or read its parts.

**Result.** No evidence of structure was found. All statistics are inside the range of a control file of the same size made by the operating system's random generator.

## What was checked

Four files of 6 291 456 bytes each: two initiated bare capsules (A, B, made in separate runs), one unborn bare capsule (U, printed, not initiated) and a control (C, `os.urandom`). The side files (`client.side`, `owner.side`) were not read or printed.

### 1. Statistics

| Metric | A | B | U | C (control) |
|---|---|---|---|---|
| Shannon entropy, whole file (bits/byte) | 7.999971 | 7.999970 | 7.999972 | 7.999969 |
| Entropy per 64 KiB block, min / max | 7.9965 / 7.9977 | same range | same range | same range |
| Chi-square on the byte histogram, p | 0.51 | 0.40 | 0.67 | 0.27 |
| Monobit test, p | 0.61 | 0.11 | 0.03 | 0.59 |
| Runs test, p | 0.78 | 0.93 | 0.83 | 0.40 |
| Serial correlation, lag 1 | -0.0007 | -0.0016 | +0.0006 | +0.0004 |
| Compression ratio, zlib -9 / lzma | 1.0003 / 1.0001 | same | same | same |
| Longest run of equal bytes | 3 | 3 | 3 | 3 |
| Runs of 16 or more zero bytes | 0 | 0 | 0 | 0 |

The unborn capsule (U) does not differ statistically from the initiated ones (A, B). The first and last 4 KiB of each file behave like the body: no header or trailer structure.

### 2. Pattern search

- Signatures of 4 bytes or longer (ELF, WebAssembly `\0asm`, PE, ZIP, xz, PDF, PNG, SQLite): **0 hits** in A, B and U. Signatures of 2-3 bytes (`MZ`, gzip, JPEG) do hit, at the same rate as in the control; they are too short to mean anything and are not counted.
- Printable ASCII runs, base64 or hex-looking runs, the start of a JSON object, and the words `ksg`, `capsule`, `wasm`, `owner`, `client`, `bare`: hit counts match the control's expected false-positive rate.
- Repeated 32-byte blocks inside a file: 0. Duplicate 4096-byte pages: 0.
- Between two capsules: the share of equal bytes at the same offset is 0.00389-0.00391 (random bytes: 1/256 = 0.00391); common 32-byte blocks: 0; common substrings longer than 64 bytes: 0.

### 3. Check of the check

A copy of A was poisoned with 2 KiB of English text, the first 4 KiB of the WebAssembly module and 8 KiB of zeros, at known offsets. The tests turned red for the right reasons: chi-square rose from 253 to 3271, the minimum block entropy fell from 7.996 to 7.721, the longest equal-byte run grew from 3 to 8192, the monobit and runs p-values fell to 0, and the pattern search found the WebAssembly signature and the zero block at their exact offsets.

## What this does and does not show

- Statistical tests show only that no structure was found. They cannot prove indistinguishability. The claim rests on how the capsule is built (the parts are sealed to the parties' keys and the rest is random fill); these tests confirm it for the three files above.
- Three files from one build were examined. Other classes (`light`, `heavy`) were not part of this check.
- Whether a dedicated reader could single out a capsule by some other property than its bytes (for example by size or by how it is stored) is outside this check.
- The existing in-repository noise test of the container, `cargo test --release -p ksg-container-v2 --test capsule -- --ignored`, is a separate check and still applies.
