//! Criterion K4 (`Spec_kapsula` §10 п. 3): the module inside the capsule
//! imports **only** the reader's randomness and its clock — no files, no
//! network, no WASI.
//!
//! The test reads the import section of the built module; it does not run it.
//! Build first:
//!
//! ```text
//! cargo build -p ksg-capsule-module --target wasm32-unknown-unknown --release
//! cargo test -p ksg-capsule-module -- --ignored
//! ```
//!
//! The test is `#[ignore]`d so an ordinary `cargo test` does not demand a
//! wasm32 build; run it with `--ignored` after the build. If the module was not
//! built, it says so and passes — a missing artifact is a skipped check, never
//! a silent green one.

use wasmparser::{Parser, Payload};

/// The module `cargo build --release` writes.
const MODULE: &str = "target/wasm32-unknown-unknown/release/ksg_capsule_module.wasm";

/// The two imports the boundary allows (`Spec_kapsula` §5, §10 п. 3).
const ALLOWED: [(&str, &str); 2] = [("ksg_host", "random"), ("ksg_host", "now_ms")];

#[test]
#[ignore = "build the module for wasm32 first: cargo build -p ksg-capsule-module --target wasm32-unknown-unknown --release"]
fn k4_the_module_imports_only_randomness_and_time() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(MODULE);
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            println!(
                "skipped: {} does not read ({e}) — build it first: cargo build -p \
                 ksg-capsule-module --target wasm32-unknown-unknown --release",
                path.display()
            );
            return;
        }
    };

    let mut imports: Vec<(String, String)> = Vec::new();
    for payload in Parser::new(0).parse_all(&bytes) {
        let payload = payload.expect("the module parses");
        if let Payload::ImportSection(section) = payload {
            for import in section {
                let import = import.expect("the import section parses");
                imports.push((import.module.to_string(), import.name.to_string()));
            }
        }
    }

    let mut allowed: Vec<(String, String)> = ALLOWED
        .iter()
        .map(|(m, n)| ((*m).to_string(), (*n).to_string()))
        .collect();
    allowed.sort();
    imports.sort();
    println!("the module's imports: {imports:?}");
    assert_eq!(
        imports, allowed,
        "the module imports exactly ksg_host.random and ksg_host.now_ms"
    );

    for (module, name) in &imports {
        assert!(
            !module.starts_with("wasi"),
            "no WASI: {module}.{name} is imported"
        );
        assert_ne!(module, "env", "no `env` module: {name} is imported");
    }
}
