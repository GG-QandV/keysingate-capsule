//! The engine that runs the capsule's module — wasmtime, outside the capsule
//! (`Spec_kapsula` §5, §10 п. 3).
//!
//! One engine is one module instance: one session. The boundary is the
//! module's own ([`ksg_capsule_module::abi`]): `[u32 length][bytes]` answers,
//! buffers allocated by `ksg_alloc` and returned through `ksg_free`.
//!
//! # What the module may reach
//!
//! Exactly two imports — `ksg_host.random` (the process's `OsRng`) and
//! `ksg_host.now_ms` (the wall clock). WASI is **not** linked: a module that
//! asks for a file, a socket or a clock of its own does not instantiate
//! (criterion K4 by construction, not by inspection).
//!
//! # Limits
//!
//! Fuel bounds the instructions a press may spend; a store limit bounds the
//! memory the module may grow to. Without them a module from the capsule could
//! loop forever or exhaust the host (Р-1: the reader runs untrusted code).

use std::time::{SystemTime, UNIX_EPOCH};

use ksg_capsule_module::abi::ABI_VERSION;
use rand_core::{OsRng, RngCore};
use wasmtime::{
    Caller, Config, Engine as WtEngine, Linker, Memory, Module, Store, StoreLimits,
    StoreLimitsBuilder, TypedFunc,
};

/// Fuel a whole exchange (allocate, press, free) may spend. Generous for a
/// 6 MiB capsule — the AEAD, the permutation and the FROST round are the
/// heavy parts — and finite, which is the point.
const DEFAULT_FUEL: u64 = 20_000_000_000;

/// The most linear memory the module may grow to: the capsule is 6 MiB, the
/// state and the module's own copies live on top of it.
const MEMORY_LIMIT: usize = 256 << 20;

/// What the reader hands the module between calls: its CSPRNG and its clock.
struct Host {
    rng: OsRng,
    limits: StoreLimits,
}

/// One instantiated module: the boundary's exports, cached.
pub struct Engine {
    store: Store<Host>,
    memory: Memory,
    alloc: TypedFunc<u32, u32>,
    free: TypedFunc<(u32, u32), ()>,
    open: TypedFunc<(u32, u32, u32, u32, u32, u32), u32>,
    call: TypedFunc<(u32, u32), u32>,
    close: TypedFunc<(), u32>,
    fuel: u64,
}

impl Engine {
    /// Instantiates `wasm` with the two host imports and checks the boundary's
    /// version before anything else.
    ///
    /// # Errors
    ///
    /// Not a module; an import beyond the two; no memory export; another
    /// boundary version; fuel or memory refused at instantiation.
    pub fn new(wasm: &[u8]) -> Result<Self, String> {
        Self::with_fuel(wasm, DEFAULT_FUEL)
    }

    /// [`Engine::new`] with an explicit fuel budget (`KSG_CAPSULE_FUEL`).
    ///
    /// # Errors
    ///
    /// As [`Engine::new`].
    pub fn with_fuel(wasm: &[u8], fuel: u64) -> Result<Self, String> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = WtEngine::new(&config).map_err(|e| format!("wasmtime: {e}"))?;
        let module = Module::new(&engine, wasm).map_err(|e| format!("not a module: {e}"))?;

        let mut store = Store::new(
            &engine,
            Host {
                rng: OsRng,
                limits: StoreLimitsBuilder::new().memory_size(MEMORY_LIMIT).build(),
            },
        );
        store.limiter(|host| &mut host.limits);
        store
            .set_fuel(fuel)
            .map_err(|e| format!("fuel: {e}"))?;

        let mut linker = Linker::new(&engine);
        linker
            .func_wrap(
                "ksg_host",
                "random",
                |mut caller: Caller<'_, Host>, ptr: u32, len: u32| -> Result<(), wasmtime::Error> {
                    let memory = caller
                        .get_export("memory")
                        .and_then(wasmtime::Extern::into_memory)
                        .ok_or_else(|| wasmtime::Error::msg("the module exports no memory"))?;
                    let start = ptr as usize;
                    let end = start
                        .checked_add(len as usize)
                        .ok_or_else(|| wasmtime::Error::msg("random: a bad pointer"))?;
                    // The range is checked against the module's own memory
                    // (bounded by MEMORY_LIMIT) before anything is touched,
                    // and the bytes go straight into it: the module's `len`
                    // never sizes a host allocation.
                    let (data, host) = memory.data_and_store_mut(&mut caller);
                    let out = data
                        .get_mut(start..end)
                        .ok_or_else(|| wasmtime::Error::msg("random: out of the memory"))?;
                    host.rng.fill_bytes(out);
                    Ok(())
                },
            )
            .map_err(|e| format!("the random import: {e}"))?;
        linker
            .func_wrap("ksg_host", "now_ms", || -> u64 { now_ms() })
            .map_err(|e| format!("the clock import: {e}"))?;

        let instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| format!("the module does not instantiate: {e}"))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or("the module exports no memory")?;
        let alloc = instance
            .get_typed_func::<u32, u32>(&mut store, "ksg_alloc")
            .map_err(|e| format!("ksg_alloc: {e}"))?;
        let free = instance
            .get_typed_func::<(u32, u32), ()>(&mut store, "ksg_free")
            .map_err(|e| format!("ksg_free: {e}"))?;
        let open = instance
            .get_typed_func::<(u32, u32, u32, u32, u32, u32), u32>(&mut store, "ksg_open")
            .map_err(|e| format!("ksg_open: {e}"))?;
        let call = instance
            .get_typed_func::<(u32, u32), u32>(&mut store, "ksg_call")
            .map_err(|e| format!("ksg_call: {e}"))?;
        let close = instance
            .get_typed_func::<(), u32>(&mut store, "ksg_close")
            .map_err(|e| format!("ksg_close: {e}"))?;

        let version = instance
            .get_typed_func::<(), u32>(&mut store, "ksg_abi_version")
            .map_err(|e| format!("ksg_abi_version: {e}"))?
            .call(&mut store, ())
            .map_err(|e| format!("ksg_abi_version: {e}"))?;
        if version != ABI_VERSION {
            return Err(format!(
                "the module's boundary is {version}, this reader speaks {ABI_VERSION}"
            ));
        }
        Ok(Self {
            store,
            memory,
            alloc,
            free,
            open,
            call,
            close,
            fuel,
        })
    }

    /// `ksg_open`: the capsule, the party's side file, the anchored commands.
    ///
    /// # Errors
    ///
    /// The module trapped, ran out of fuel, or answered `{"error":…}`.
    pub fn open(&mut self, capsule: &[u8], side: &[u8], anchored: &[u8]) -> Result<(), String> {
        self.refuel()?;
        let (c_ptr, c_len) = self.put(capsule)?;
        let (s_ptr, s_len) = self.put(side)?;
        let (a_ptr, a_len) = self.put(anchored)?;
        let answer = self.open.call(
            &mut self.store,
            (c_ptr, c_len, s_ptr, s_len, a_ptr, a_len),
        );
        self.free_input(c_ptr, c_len);
        self.free_input(s_ptr, s_len);
        self.free_input(a_ptr, a_len);
        self.ok(answer)?;
        Ok(())
    }

    /// `ksg_call`: one request, one answer's bytes.
    ///
    /// # Errors
    ///
    /// As [`Engine::open`].
    pub fn call(&mut self, request: &[u8]) -> Result<Vec<u8>, String> {
        self.refuel()?;
        let (ptr, len) = self.put(request)?;
        let answer = self.call.call(&mut self.store, (ptr, len));
        self.free_input(ptr, len);
        self.ok(answer)
    }

    /// `ksg_close`: the new capsule and the outputs, as JSON.
    ///
    /// # Errors
    ///
    /// As [`Engine::open`].
    pub fn close(&mut self) -> Result<Vec<u8>, String> {
        self.refuel()?;
        let answer = self.close.call(&mut self.store, ());
        self.ok(answer)
    }

    fn refuel(&mut self) -> Result<(), String> {
        self.store
            .set_fuel(self.fuel)
            .map_err(|e| format!("fuel: {e}"))
    }

    /// Allocates `len` bytes inside the module and writes them.
    fn put(&mut self, bytes: &[u8]) -> Result<(u32, u32), String> {
        let len = u32::try_from(bytes.len()).map_err(|_| "a request longer than u32")?;
        let ptr = self
            .alloc
            .call(&mut self.store, len)
            .map_err(|e| format!("ksg_alloc: {e}"))?;
        self.memory
            .write(&mut self.store, ptr as usize, bytes)
            .map_err(|e| format!("the request does not fit the module's memory: {e}"))?;
        Ok((ptr, len))
    }

    fn free_input(&mut self, ptr: u32, len: u32) {
        // A failed free cannot be undone and must not hide the answer.
        let _ = self.free.call(&mut self.store, (ptr, len));
    }

    /// Reads the module's answer buffer and returns it to the module.
    fn ok(&mut self, answer: Result<u32, wasmtime::Error>) -> Result<Vec<u8>, String> {
        let ptr = answer.map_err(|e| format!("the module trapped: {e}"))?;
        let mut head = [0u8; 4];
        self.memory
            .read(&self.store, ptr as usize, &mut head)
            .map_err(|e| format!("the answer's length: {e}"))?;
        let len = u32::from_le_bytes(head) as usize;
        // The length comes from the module: check that the whole answer lies
        // inside its memory (bounded by MEMORY_LIMIT) before the host
        // allocates a buffer of that size.
        let end = (ptr as usize)
            .checked_add(4)
            .and_then(|start| start.checked_add(len))
            .ok_or("the answer's length overflows")?;
        if end > self.memory.data_size(&self.store) {
            return Err(format!(
                "the answer's length ({len} bytes) runs past the module's memory"
            ));
        }
        let mut body = vec![0u8; len];
        self.memory
            .read(&self.store, ptr as usize + 4, &mut body)
            .map_err(|e| format!("the answer: {e}"))?;
        let total = u32::try_from(4 + len).map_err(|_| "an answer longer than u32")?;
        let _ = self.free.call(&mut self.store, (ptr, total));
        // A boundary failure is `{"error":…}`, never a trap: the caller reads
        // it as one.
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) {
            if let Some(error) = value.get("error").and_then(serde_json::Value::as_str) {
                return Err(error.to_string());
            }
        }
        Ok(body)
    }
}

/// The reader's clock: milliseconds since the Unix epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
