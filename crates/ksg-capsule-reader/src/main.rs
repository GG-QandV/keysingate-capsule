//! `ksg-capsule` — the capsule's command line, offline half (plan v8, K5).
//!
//! ```text
//! ksg-capsule --home DIR init [--class light|heavy|bare] [--emission ksg:em:test:NNNNNN]
//!                              [--serial N] [--artifact URI] [--anchor solana:CLUSTER
//!                              (--payer KEYFILE | --service URL --holder ID) [--rpc URL]]
//!                              [--wasm PATH] [--base RPC,CONTRACT,KEYFILE]
//! ksg-capsule --home DIR buyer-key
//! ksg-capsule --home DIR initiate [--mobile-web ADDR] [--web-root DIR]
//! ksg-capsule --home DIR work TEXT [--mobile-web ADDR] [--web-root DIR]
//! ksg-capsule --home DIR transfer [--evm-key FILE]
//! ksg-capsule --home DIR export-page N [--by client|owner] [--mobile-web ADDR] [--web-root DIR]
//! ksg-capsule --home DIR keys [--out FILE]
//! ksg-capsule --home DIR status
//! ksg-capsule --home DIR backup --party client|owner --out FILE
//! ksg-capsule --home DIR restore --party client|owner --from FILE
//! ```
//!
//! `backup` and `restore` take the password only from the file named by the
//! environment variable `KSG_BACKUP_PASSWORD_FILE`.
//!
//! Every command after `init` is one session over the capsule and a party's
//! one secret file: open → call → close → the capsule written atomically.
//! `--home DIR` holds `capsule.bin`, `client.side`, `owner.side`, the exported
//! pages and `keys.json`; the printing stand stays in `DIR/stand`.

use std::process::ExitCode;

use ksg_capsule_reader::flow::{self, Layout, Party, Print};
use ksg_core_v2::doc::Class;

const USAGE: &str = "\
ksg-capsule --home DIR init [--class light|heavy|bare] [--emission ksg:em:test:NNNNNN]
                             [--serial N] [--artifact URI] [--anchor solana:CLUSTER
                             (--payer KEYFILE | --service URL --holder ID) [--rpc URL]]
                             [--wasm PATH] [--base RPC,CONTRACT,KEYFILE]
  (--base: a `light` capsule anchors on Base Sepolia; KEYFILE is the path to the
   sender's key file, never the key)
ksg-capsule --home DIR buyer-key
ksg-capsule --home DIR issue-command finalize|succeed|shares-lost [HASH]
                             [LEADER for succeed]
ksg-capsule --home DIR apply-commands [--party client|owner]
ksg-capsule --home DIR pull TRAILER TRAILER_SEAL
ksg-capsule --home DIR initiate [--mobile-web ADDR] [--web-root DIR]
ksg-capsule --home DIR work TEXT [--mobile-web ADDR] [--web-root DIR]
ksg-capsule --home DIR transfer [--evm-key FILE]
  (on a Base capsule: the new owner's EVM key file; else stand/new_owner_evm.key)
ksg-capsule --home DIR export-page N [--by client|owner] [--mobile-web ADDR] [--web-root DIR]
ksg-capsule --home DIR keys [--out FILE]
ksg-capsule --home DIR status
ksg-capsule --home DIR backup --party client|owner --out FILE
ksg-capsule --home DIR restore --party client|owner --from FILE
  (the password: the file named by KSG_BACKUP_PASSWORD_FILE, never an argument)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Problem::Usage(m)) => {
            eprintln!("{m}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Problem::Failed(m)) => {
            eprintln!("{m}");
            ExitCode::FAILURE
        }
    }
}

/// Why the command did not run.
enum Problem {
    /// The arguments do not name a command.
    Usage(String),
    /// The command ran and failed.
    Failed(String),
}

impl From<String> for Problem {
    fn from(m: String) -> Self {
        Self::Failed(m)
    }
}

fn usage(m: impl Into<String>) -> Problem {
    Problem::Usage(m.into())
}

/// The arguments: flags as `--name value`, the rest positional.
struct Args {
    flags: Vec<(String, String)>,
    rest: Vec<String>,
}

impl Args {
    fn parse(args: &[String]) -> Result<Self, Problem> {
        let mut flags = Vec::new();
        let mut rest = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            if let Some(name) = arg.strip_prefix("--") {
                let value = args
                    .get(i + 1)
                    .ok_or_else(|| usage(format!("--{name} needs a value")))?;
                flags.push((name.to_string(), value.clone()));
                i += 2;
            } else {
                rest.push(arg.clone());
                i += 1;
            }
        }
        Ok(Self { flags, rest })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.flags
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn home(&self) -> Result<&str, Problem> {
        self.get("home")
            .ok_or_else(|| usage("--home DIR is required"))
    }
}

fn run(args: &[String]) -> Result<(), Problem> {
    let args = Args::parse(args)?;
    let home = args.home()?;
    let layout = Layout::new(home);
    let command = args
        .rest
        .first()
        .ok_or_else(|| usage("a command is required"))?
        .as_str();
    match command {
        "init" => {
            let print = parse_print(&args)?;
            let id = flow::init(&layout, &print)?;
            println!("capsule  {}", layout.capsule().display());
            println!("container {id}");
            println!("client   {}", layout.client_side().display());
            println!("owner    {}", layout.owner_side().display());
            Ok(())
        }
        "issue-command" => {
            // K3 (§27): the issuer's command, saved in commands/ and, with an
            // anchor config, published as a blind `ksg:cmd:v1` memo.
            let op = args.rest.get(1).ok_or_else(|| usage("issue-command finalize|succeed|shares-lost [HASH|LEADER]"))?;
            let (op, evidence) = match op.as_str() {
                "finalize" => (
                    ksg_container_v2::Operation::Finalize,
                    ksg_capsule_module::session::CommandEvidence::None,
                ),
                "succeed" => {
                    let leader = args
                        .rest
                        .get(2)
                        .map(|s| {
                            ksg_core_v2::crypto::hash::Hash::from_multihash(s)
                                .map_err(|_| usage("issue-command: LEADER is not a multihash"))
                        })
                        .transpose()?;
                    (
                        ksg_container_v2::Operation::Succeed,
                        match leader {
                            Some(leader) => ksg_capsule_module::session::CommandEvidence::AttachedTo { leader },
                            None => ksg_capsule_module::session::CommandEvidence::None,
                        },
                    )
                }
                "shares-lost" => {
                    let hash = args
                        .rest
                        .get(2)
                        .ok_or_else(|| usage("issue-command shares-lost HASH"))?;
                    let hash = ksg_core_v2::crypto::hash::Hash::from_multihash(hash)
                        .map_err(|_| usage("issue-command: HASH is not a multihash"))?;
                    (
                        ksg_container_v2::Operation::DeclareSharesLost,
                        ksg_capsule_module::session::CommandEvidence::SharesLost { hash },
                    )
                }
                _ => return Err(usage("issue-command finalize|succeed|shares-lost [HASH|LEADER]")),
            };
            let file = ksg_capsule_reader::command::issue(&layout, op, evidence)?;
            if flow::anchor_cfg(&layout)?.is_some() {
                let sig = ksg_capsule_reader::command::publish(&layout, &file)?;
                println!("published {sig}");
            } else {
                let (memo, path) = ksg_capsule_reader::command::save(&layout, &file)?;
                println!("saved {} (no anchor config: memo not sent)\nmemo  {memo}", path.display());
            }
            Ok(())
        }
        "apply-commands" => {
            let party = if args.get("party").is_some() { party_flag(&args)? } else { Party::Client };
            let r = ksg_capsule_reader::command::apply(&layout, party)?;
            println!(
                "applied {:?}\nrefused {:?}\nanchored without a file (not applied) {:?}\nnot published {:?}",
                r.applied, r.refused, r.unmatched, r.unpublished
            );
            Ok(())
        }
        "pull" => {
            let trailer = args
                .rest
                .get(1)
                .ok_or_else(|| usage("pull needs a trailer multihash"))?;
            let trailer = ksg_core_v2::crypto::hash::Hash::from_multihash(trailer)
                .map_err(|_| usage("pull: TRAILER is not a multihash"))?;
            let seal = args
                .rest
                .get(2)
                .ok_or_else(|| usage("pull needs the trailer's seal multihash"))?;
            let seal = ksg_core_v2::crypto::hash::Hash::from_multihash(seal)
                .map_err(|_| usage("pull: TRAILER_SEAL is not a multihash"))?;
            let value = flow::pull(&layout, trailer, seal)?;
            println!("{value}");
            Ok(())
        }
        "buyer-key" => {
            let value = flow::buyer_key(&layout)?;
            println!("{value}");
            Ok(())
        }
        "transfer" => {
            let key = args.get("evm-key").map(std::path::Path::new);
            let value = flow::transfer_with_evm_key(&layout, key)?;
            println!("{value}");
            Ok(())
        }
        "initiate" => {
            let web = mobile_web(&args)?;
            let value = match web {
                None => flow::initiate(&layout)?,
                Some(mut web) => flow::initiate_mobile_web(&layout, &mut web)?,
            };
            println!("{value}");
            Ok(())
        }
        "work" => {
            let text = args
                .rest
                .get(1)
                .ok_or_else(|| usage("work needs the text of the page"))?;
            let value = match mobile_web(&args)? {
                None => flow::work(&layout, text)?,
                Some(mut web) => flow::work_mobile_web(&layout, &mut web, text)?,
            };
            println!("{value}");
            Ok(())
        }
        "export-page" => {
            let number: u64 = args
                .rest
                .get(1)
                .ok_or_else(|| usage("export-page needs a page number"))?
                .parse()
                .map_err(|_| usage("export-page: the number is not a number"))?;
            let web = mobile_web(&args)?;
            let party = match (args.get("by").unwrap_or("client"), web.is_some()) {
                (by, true) if by != "client" => {
                    return Err(usage("--mobile-web only exports the client's pages"));
                }
                ("client", _) => Party::Client,
                ("owner", _) => Party::Owner,
                (other, _) => return Err(usage(format!("--by {other}: client or owner"))),
            };
            let page = match web {
                None => flow::export_page(&layout, number, party)?,
                Some(mut web) => flow::export_page_mobile_web(&layout, &mut web, number)?,
            };
            let out = args
                .get("out")
                .map_or_else(|| layout.page(number), std::path::PathBuf::from);
            std::fs::write(&out, &page).map_err(|e| format!("{}: {e}", out.display()))?;
            println!("{}", out.display());
            Ok(())
        }
        "keys" => {
            let keys = flow::keys(&layout)?;
            let out = args
                .get("out")
                .map_or_else(|| layout.keys(), std::path::PathBuf::from);
            std::fs::write(&out, &keys).map_err(|e| format!("{}: {e}", out.display()))?;
            println!("{}", out.display());
            Ok(())
        }
        "status" => {
            let status = flow::status(&layout)?;
            println!("{status}");
            Ok(())
        }
        "backup" => {
            let party = party_flag(&args)?;
            let out = args.get("out").ok_or_else(|| usage("backup needs --out FILE"))?;
            flow::backup(&layout, party, std::path::Path::new(out))?;
            println!("{out}");
            Ok(())
        }
        "restore" => {
            let party = party_flag(&args)?;
            let from = args.get("from").ok_or_else(|| usage("restore needs --from FILE"))?;
            flow::restore(&layout, party, std::path::Path::new(from))?;
            println!("{}", layout.side(party).display());
            Ok(())
        }
        other => Err(usage(format!("no command {other:?}"))),
    }
}

/// `--party client|owner`.
fn party_flag(args: &Args) -> Result<Party, Problem> {
    match args.get("party") {
        Some("client") => Ok(Party::Client),
        Some("owner") => Ok(Party::Owner),
        _ => Err(usage("--party client|owner is required")),
    }
}

/// `init`'s arguments.
fn parse_print(args: &Args) -> Result<Print, Problem> {
    let mut print = Print::default();
    if let Some(class) = args.get("class") {
        print.class = match class {
            "light" => Class::Light,
            "heavy" => Class::Heavy,
            "bare" => Class::Bare,
            other => return Err(usage(format!("--class {other}: light, heavy or bare"))),
        };
    }
    if let Some(emission) = args.get("emission") {
        print.emission = emission.to_string();
    }
    if let Some(serial) = args.get("serial") {
        print.serial = serial
            .parse()
            .map_err(|_| usage("--serial must be a number"))?;
    }
    if let Some(artifact) = args.get("artifact") {
        print.artifact = artifact.to_string();
    }
    if let Some(wasm) = args.get("wasm") {
        print.wasm = std::path::PathBuf::from(wasm);
    }
    if let Some(base) = args.get("base") {
        if print.class != Class::Light {
            return Err(usage("--base goes with a `light` capsule only"));
        }
        let mut parts = base.splitn(3, ',');
        match (parts.next(), parts.next(), parts.next()) {
            (Some(rpc), Some(contract), Some(key))
                if !rpc.is_empty() && !contract.is_empty() && !key.is_empty() =>
            {
                print.base = Some(ksg_capsule_reader::base::BaseSpec {
                    rpc: rpc.to_string(),
                    contract: contract.to_string(),
                    key: std::path::PathBuf::from(key),
                });
            }
            _ => return Err(usage("--base RPC,CONTRACT,KEYFILE")),
        }
    }
    print.anchor = match args.get("anchor") {
        None => {
            if ["payer", "rpc", "service", "holder"]
                .iter()
                .any(|k| args.get(k).is_some())
            {
                return Err(usage("--payer, --service, --holder and --rpc go with --anchor"));
            }
            None
        }
        Some(a) => {
            let cluster = a
                .strip_prefix("solana:")
                .ok_or_else(|| usage("--anchor must be solana:CLUSTER"))?;
            let payer = args.get("payer").map(std::path::PathBuf::from);
            let service = match (args.get("service"), args.get("holder")) {
                (Some(url), Some(holder)) if payer.is_none() => {
                    Some(ksg_cli_v2::anchoring::ServiceRoute {
                        url: url.to_string(),
                        holder: holder.to_string(),
                    })
                }
                (None, None) if payer.is_some() => None,
                _ => {
                    return Err(usage(
                        "--anchor takes --payer KEYFILE, or --service URL --holder ID",
                    ))
                }
            };
            Some(ksg_cli_v2::anchoring::AnchorCfg {
                cluster: cluster.to_string(),
                rpc: args
                    .get("rpc")
                    .map_or_else(|| ksg_cli_v2::anchoring::AnchorCfg::default_rpc(cluster), str::to_string),
                payer,
                service,
                last_signature: None,
                pending: Vec::new(),
                rotate_scan: true,
                scan_periods: Vec::new(),
            })
        }
    };
    Ok(print)
}

/// The browser page as the mobile half for `initiate`: the half is born in
/// the page (`ksg-web-v2`), and the reader only carries public bytes — the
/// hello out, the container's answer back, the share in `FinishBirth` — the
/// same wire the phone's `Keygen` automaton crosses. `None` without
/// `--mobile-web`; `--web-root DIR` serves the page's files.
fn mobile_web(args: &Args) -> Result<Option<Box<ksg_cli_v2::web_mobile::WebMobile>>, Problem> {
    match (args.get("mobile-web"), args.get("web-root")) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(usage("--web-root goes with --mobile-web")),
        (Some(addr), root) => {
            let web = ksg_cli_v2::web_mobile::WebMobile::listen(
                addr,
                root.map(std::path::PathBuf::from),
            )
            .map_err(Problem::Failed)?;
            eprintln!("mobile half: open {}", web.url);
            Ok(Some(Box::new(web)))
        }
    }
}
