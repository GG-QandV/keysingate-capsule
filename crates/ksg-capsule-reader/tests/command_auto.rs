//! K3 (`Spec_kapsula` §27, «auto-apply», `[decision]` 01.11 «V»): the network's
//! commands are looked for before the holder's action; without the network,
//! at most ten records, then the next one waits.

use ksg_capsule_reader::command::{self, Report, OFFLINE_CHECKS};
use ksg_capsule_reader::flow::{self, default_wasm, Layout, Party, Print};
use ksg_capsule_reader::side::SideFile;
use ksg_core_v2::doc::Class;

fn home(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ksg-cmd-auto-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    dir
}

fn printed(name: &str) -> Option<Layout> {
    let wasm = default_wasm();
    if !wasm.exists() {
        assert!(std::env::var("KSG_SKIP_K5").as_deref() == Ok("1"), "build the module for wasm32 first");
        return None;
    }
    let layout = Layout::new(home(name));
    flow::init(&layout, &Print { class: Class::Light, wasm, ..Print::default() }).expect("prints");
    flow::initiate(&layout).expect("initiates");
    Some(layout)
}

fn offline() -> Result<Report, String> {
    Err("the node does not answer".into())
}

#[test]
fn without_the_network_ten_records_go_and_the_eleventh_waits() {
    let Some(layout) = printed("ten") else { return };
    for _ in 0..OFFLINE_CHECKS {
        command::before_holder_with(&layout, Party::Client, true, offline).expect("within the window");
    }
    let err = command::before_holder_with(&layout, Party::Client, true, offline).expect_err("past the window");
    assert!(err.contains("waits for the network"), "{err}");
    // An action that writes no page is not held up, only warned of.
    command::before_holder_with(&layout, Party::Client, false, offline).expect("an export is not counted");
    // The network answers: the counter starts again.
    command::before_holder_with(&layout, Party::Client, true, || Ok(Report::default())).expect("answered");
    command::before_holder_with(&layout, Party::Client, true, offline).expect("the window is open again");
    std::fs::remove_dir_all(&layout.home).ok();
}

#[test]
fn a_side_file_without_a_command_key_is_not_counted() {
    let Some(layout) = printed("pre-k3") else { return };
    // A file printed before K3: no command key.
    let mut file = SideFile::read(&layout.client_side()).expect("the client's file");
    file.cmd = String::new();
    file.write(&layout.client_side()).expect("written");
    for _ in 0..(OFFLINE_CHECKS + 5) {
        command::before_holder_with(&layout, Party::Client, true, || panic!("the network is not asked"))
            .expect("skipped: nothing to look for");
    }
    std::fs::remove_dir_all(&layout.home).ok();
}

#[test]
fn a_stale_command_is_written_down_for_the_issuer() {
    let Some(layout) = printed("stale") else { return };
    let stale = Report {
        refused: vec!["Finalize: refused: the event's head is not the container's".into()],
        ..Report::default()
    };
    command::before_holder_with(&layout, Party::Client, true, || Ok(stale)).expect("answered");
    let log = std::fs::read_to_string(command::dir(&layout).join("report.log")).expect("the report");
    assert!(log.contains("stale") && log.contains("sign it again"), "{log}");
    std::fs::remove_dir_all(&layout.home).ok();
}
