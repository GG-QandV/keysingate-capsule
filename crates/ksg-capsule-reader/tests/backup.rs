//! The side file's backup copy: the whole JSON sealed by a password
//! (`ksg_web_v2::backup`), the password read only from the file named by
//! `KSG_BACKUP_PASSWORD_FILE`. Lost client file → `restore` → `work` goes
//! through; a wrong password, a copy whose map opens no slot ("stale") and a
//! restore over an existing file are refused.
//!
//! The module must be built for `wasm32` first (as for `k5_offline`):
//!
//! ```text
//! cargo build -p ksg-capsule-module --target wasm32-unknown-unknown --release
//! ```
//!
//! The password lives in the process environment (a path, never the secret),
//! so everything runs in one test: parallel tests would race on it.

use ksg_capsule_reader::flow::{self, default_wasm, Layout, Party, Print, BACKUP_PASSWORD_FILE};
use ksg_core_v2::doc::Class;

fn home(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ksg-backup-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    dir
}

fn print() -> Option<Print> {
    let path = std::env::var("KSG_CAPSULE_WASM").map_or_else(|_| default_wasm(), std::path::PathBuf::from);
    if !path.exists() {
        assert!(
            std::env::var("KSG_SKIP_K5").as_deref() == Ok("1"),
            "{} is missing: build ksg-capsule-module for wasm32 first, or KSG_SKIP_K5=1",
            path.display()
        );
        return None;
    }
    Some(Print { class: Class::Light, wasm: path, ..Print::default() })
}

fn password(dir: &std::path::Path, name: &str, text: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("{text}\n")).expect("a password file");
    path
}

#[test]
fn backup_restores_a_lost_client_file_and_refuses_the_rest() {
    let Some(print) = print() else {
        return;
    };
    let dir = home("a");
    let layout = Layout::new(&dir);
    flow::init(&layout, &print).expect("the capsule prints");
    let good = password(&dir, "pw-good", "correct horse battery staple");
    let bad = password(&dir, "pw-bad", "not the password at all");
    std::env::set_var(BACKUP_PASSWORD_FILE, &good);

    // A copy taken before the initiation, for later.
    let before = dir.join("client-before.bak");
    flow::backup(&layout, Party::Client, &before).expect("a backup before the initiation");

    flow::initiate(&layout).expect("the initiation goes through");
    flow::work(&layout, "first page").expect("work before the loss");
    let after = dir.join("client-after.bak");
    flow::backup(&layout, Party::Client, &after).expect("a backup after the initiation");
    let owner_bak = dir.join("owner.bak");
    flow::backup(&layout, Party::Owner, &owner_bak).expect("the owner's backup");

    // The copy is sealed: the file does not hold the plain JSON.
    let sealed = std::fs::read(&after).expect("the copy reads");
    assert!(!String::from_utf8_lossy(&sealed).contains("\"half\""), "the copy is sealed");

    // Restore over an existing file is refused, the file stays as it was.
    let kept = std::fs::read(layout.client_side()).expect("the client's file");
    let err = flow::restore(&layout, Party::Client, &after).expect_err("never overwrites");
    assert!(err.contains("exists"), "{err}");
    assert_eq!(kept, std::fs::read(layout.client_side()).expect("still there"));

    // The client's file is lost.
    std::fs::remove_file(layout.client_side()).expect("the loss");
    assert!(flow::work(&layout, "no file").is_err(), "no file, no work");

    // A wrong password: an error, nothing is written.
    std::env::set_var(BACKUP_PASSWORD_FILE, &bad);
    let err = flow::restore(&layout, Party::Client, &after).expect_err("a wrong password");
    assert!(err.contains("password"), "{err}");
    assert!(!layout.client_side().exists(), "nothing written on a wrong password");
    std::env::set_var(BACKUP_PASSWORD_FILE, &good);

    // The owner's copy is not the client's.
    let err = flow::restore(&layout, Party::Client, &owner_bak).expect_err("another party's copy");
    assert!(err.contains("another party"), "{err}");
    assert!(!layout.client_side().exists());

    // The copy taken before the initiation is stale: E-4 gave the client
    // its own map, and the holder's map opens no slot any more (§21, §25).
    let err = flow::restore(&layout, Party::Client, &before).expect_err("a pre-initiation copy");
    assert!(err.contains("stale"), "{err}");
    assert!(!layout.client_side().exists(), "a stale copy writes nothing");

    // The right copy and the right password: the work goes on.
    flow::restore(&layout, Party::Client, &after).expect("the restore");
    flow::work(&layout, "second page").expect("work after the restore");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(layout.client_side()).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "the restored file is 0600");
    }

    // The password file is required: no variable, no backup.
    std::env::remove_var(BACKUP_PASSWORD_FILE);
    assert!(flow::backup(&layout, Party::Client, &dir.join("x.bak")).is_err());
    std::env::set_var(BACKUP_PASSWORD_FILE, &good);

    // A copy whose map opens no slot of this capsule is stale. (The copy of
    // an older map stands for it: a file with another map seed, sealed the
    // way `backup` seals.)
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(layout.client_side()).expect("the file")).expect("json");
    json["map"] = serde_json::Value::String(
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [7u8; 32]),
    );
    let pw = std::fs::read(&good).expect("pw");
    let sealed = ksg_web_v2::backup::seal(
        &serde_json::to_vec(&json).expect("encode"),
        pw.strip_suffix(b"\n").unwrap_or(&pw),
        &mut rand_core::OsRng,
    )
    .expect("seal");
    let stale = dir.join("client-stale.bak");
    std::fs::write(&stale, sealed).expect("write");
    std::fs::remove_file(layout.client_side()).expect("the loss again");
    let err = flow::restore(&layout, Party::Client, &stale).expect_err("a stale copy");
    assert!(err.contains("stale"), "{err}");
    assert!(!layout.client_side().exists(), "a stale copy writes nothing");
    flow::restore(&layout, Party::Client, &after).expect("the current copy still restores");
    let _ = before;
    let _ = std::fs::remove_dir_all(&dir);
}
