//! `ksg-capsule-module` — the container's code as it lives **inside** the capsule.
//!
//! The reader finds its own slot and the code part, instantiates this module and
//! drives a session (`[doc:CAPSULE-SPEC]` §10 item 3, §12 L-1):
//!
//! | Export | What it does |
//! |---|---|
//! | `ksg_open` | the capsule, the party's secret file, the anchored commands addressed to the container |
//! | `ksg_call` | one panel-level request: `initiate`, `open_journal`, `work`, `export_page`, `keys`, `status`, `reanchor`, `sign`; an answer, or "the network is needed" / "a party's signature is needed" |
//! | `ksg_close` | the new capsule and the outputs; the module wipes its memory |
//!
//! The module imports **only** `ksg_host.random` and `ksg_host.now_ms`: no
//! files, no network (criterion K4 — tested by `tests/k4_imports.rs`).
//!
//! Skeleton of 26.10; the session and the boundary landed 27.10 (plan v8, K4).

pub mod abi;
pub mod pake;
pub mod secret;
pub mod session;
