# Quick start: the capsule controller on Linux, macOS and Windows

The controller `ksg-capsule` opens your capsule, writes pages and exports them. Release files: the [`bare-beta-1` release](https://github.com/GG-QandV/keysingate-capsule/releases/tag/bare-beta-1).

## What you need
Three files from the two e-mails: `capsule.bin` (mail 1), `owner.side` and `client.side` (mail 2), plus the controller `ksg-capsule` for your system.

| System | File | Notes |
|---|---|---|
| Linux x86_64 (glibc 2.34+) | `ksg-capsule-linux-x86_64` | Ubuntu 22.04+, Debian 12+ |
| macOS, Apple Silicon (M1–M4) | `ksg-capsule-macos-arm64` | |
| macOS, Intel | `ksg-capsule-macos-x86_64` | |
| macOS, either | `ksg-capsule-macos-universal` | both architectures in one file |
| Windows 10/11, 64-bit | `ksg-capsule-windows-x86_64.exe` | |
ARM Linux, ARM Windows and Alpine are not covered.

## Linux
```bash
mkdir my-capsule        # put capsule.bin, owner.side, client.side here
curl -L -o ksg-capsule https://github.com/GG-QandV/keysingate-capsule/releases/download/bare-beta-1/ksg-capsule-linux-x86_64
curl -L -O https://github.com/GG-QandV/keysingate-capsule/releases/download/bare-beta-1/SHA256SUMS && sha256sum -c --ignore-missing SHA256SUMS
chmod +x ksg-capsule
./ksg-capsule --home my-capsule status
./ksg-capsule --home my-capsule work "your first page"
./ksg-capsule --home my-capsule export-page 1 --by owner
```

## macOS (Terminal)
```bash
mkdir my-capsule        # put capsule.bin, owner.side, client.side here
curl -L -o ksg-capsule https://github.com/GG-QandV/keysingate-capsule/releases/download/bare-beta-1/ksg-capsule-macos-universal   # downloading with curl does not add the quarantine mark
chmod +x ksg-capsule
./ksg-capsule --home my-capsule status
./ksg-capsule --home my-capsule work "your first page"
./ksg-capsule --home my-capsule export-page 1 --by owner
```
If you downloaded the file in a browser and macOS says it "cannot be opened" or "is damaged": the file is not signed by an Apple developer account. Remove the quarantine mark and run again:
```bash
xattr -d com.apple.quarantine ksg-capsule
```
(Or: System Settings → Privacy & Security → "Open Anyway" after the first blocked start.)

## Windows (PowerShell)
```powershell
mkdir my-capsule        # put capsule.bin, owner.side, client.side here
Invoke-WebRequest -Uri https://github.com/GG-QandV/keysingate-capsule/releases/download/bare-beta-1/ksg-capsule-windows-x86_64.exe -OutFile ksg-capsule.exe
Unblock-File .\ksg-capsule.exe          # removes the "downloaded from the internet" mark
.\ksg-capsule.exe --home my-capsule status
.\ksg-capsule.exe --home my-capsule work "your first page"
.\ksg-capsule.exe --home my-capsule export-page 1 --by owner
```
If SmartScreen shows "Windows protected your PC": the file is not code-signed. "More info" → "Run anyway". Check the file first against `SHA256SUMS`: `Get-FileHash .\ksg-capsule.exe -Algorithm SHA256`.
On Windows the key files do not get the owner-only file mode that Linux and macOS set; keep `owner.side` and `client.side` in a folder only you can read.

## Check the download (all systems)
`SHA256SUMS` lists a SHA-256 for every file. Compare it with `sha256sum` (Linux), `shasum -a 256` (macOS) or `Get-FileHash` (Windows).

## For geeks: build the controller yourself
The source is this repository; the build is reproducible from the tag.
```bash
git clone https://github.com/GG-QandV/keysingate-capsule
cd keysingate-capsule
git checkout bare-beta-1
# Rust 1.94.1 is pinned in rust-toolchain.toml; rustup installs it on the first cargo call
cargo build --release --locked -p ksg-capsule-reader --bin ksg-capsule
# result: target/release/ksg-capsule  (ksg-capsule.exe on Windows)
```
- Dependencies from `keysingate-core` come over git (public); `--locked` keeps the versions of `Cargo.lock`.
- Linux needs `gcc`; macOS needs the Xcode command-line tools (`xcode-select --install`); Windows needs Rust with the MSVC target and "Build Tools for Visual Studio" (C++ workload).
- Cross-build on macOS: `rustup target add x86_64-apple-darwin aarch64-apple-darwin`, build both with `--target`, join with `lipo -create -output ksg-capsule-universal …`.
- To make your own capsule (issuer side): build the module `cargo build -p ksg-capsule-module --target wasm32-unknown-unknown --release` (after `rustup target add wasm32-unknown-unknown`), then `ksg-capsule --home DIR init --class bare --wasm target/wasm32-unknown-unknown/release/ksg_capsule_module.wasm` and `ksg-capsule --home DIR initiate`.
- The CI recipe: `.github/workflows/build-desktop.yml` on branch `ci-builds` of the mirror.

## Tested
Built and smoke-tested on GitHub-hosted runners on 04 Nov 2026 (`status`, `work`, `export-page`, `status` on a throw-away capsule): Windows (x86_64) and macOS on Apple Silicon (the arm64 and the universal binary). The Intel Mac binary is built but was not run on an Intel Mac; Windows 10, ARM Windows and ARM Linux were not tested. The binaries are not code-signed (see the notes above). The CI recipe is `.github/workflows/build-desktop.yml` (run by hand; it builds and smoke-tests on the demo capsule).
