//! The reader's own criteria: the atomic write (R-6) and the side file.
//! K4 is the module's (`ksg-capsule-module/tests/k4_imports.rs`), K5 is
//! `tests/k5_offline.rs`.

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
