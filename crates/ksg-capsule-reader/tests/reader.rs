//! The reader's criteria (plan v8): atomic write (Р-6) now; K4 and K5 later.

use ksg_capsule_reader::write_capsule;

#[test]
fn a_capsule_is_replaced_whole() {
    let dir = std::env::temp_dir().join(format!("ksg-reader-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("capsule.bin");
    write_capsule(&path, &[1u8; 4096]).unwrap();
    write_capsule(&path, &[2u8; 4096]).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), vec![2u8; 4096]);
    assert!(!path.with_extension("tmp").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
#[ignore = "capsule skeleton 26.10: the module lands 29.10 (plan v8, K4)"]
fn k4_the_module_imports_randomness_and_time_only() {
    panic!("build the module for wasm32 and list its imports: only ksg_host.random, ksg_host.now_ms");
}

#[test]
#[ignore = "capsule skeleton 26.10: the reader lands 30.10 (plan v8, K5)"]
fn k5_a_pro_page_through_the_capsule_verifies() {
    panic!("initiate → work ×3 → export → ksg-verify-v2 ACCEPTED; a tampered page REJECTED");
}

#[test]
fn a_side_file_round_trips_with_mode_600_and_the_same_map() {
    use ksg_capsule_reader::side::{Role, SideFile};
    let dir = std::env::temp_dir().join(format!("ksg-side-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("client.side");
    let f = SideFile::new(Role::Client, "tmpl", b"half-state", &[7; 32], &[9; 32]);
    let public = f.map().unwrap().seal_to();
    f.write(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let back = SideFile::read(&path).unwrap();
    assert_eq!(back.role, Role::Client);
    assert_eq!(back.map().unwrap().seal_to().public().as_bytes(), public.public().as_bytes());
    std::fs::remove_dir_all(&dir).unwrap();
}
