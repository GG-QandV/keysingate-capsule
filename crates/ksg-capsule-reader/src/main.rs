//! `ksg-capsule` — the capsule's command line, offline half (plan v8, K5).
//!
//! ```text
//! ksg-capsule --home DIR init [--class light|heavy|bare] [--emission ksg:em:test:NNNNNN]
//!                              [--serial N] [--artifact URI] [--anchor solana:CLUSTER
//!                              (--payer KEYFILE | --service URL --holder ID) [--rpc URL]]
//!                              [--wasm PATH]
//! ksg-capsule --home DIR initiate
//! ksg-capsule --home DIR work TEXT
//! ksg-capsule --home DIR export-page N [--by client|owner] [--out FILE]
//! ksg-capsule --home DIR keys [--out FILE]
//! ksg-capsule --home DIR status
//! ```
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
                             [--wasm PATH]
ksg-capsule --home DIR initiate
ksg-capsule --home DIR work TEXT
ksg-capsule --home DIR export-page N [--by client|owner] [--out FILE]
ksg-capsule --home DIR keys [--out FILE]
ksg-capsule --home DIR status";

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
        "initiate" => {
            let value = flow::initiate(&layout)?;
            println!("{value}");
            Ok(())
        }
        "work" => {
            let text = args
                .rest
                .get(1)
                .ok_or_else(|| usage("work needs the text of the page"))?;
            let value = flow::work(&layout, text)?;
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
            let party = match args.get("by").unwrap_or("client") {
                "client" => Party::Client,
                "owner" => Party::Owner,
                other => return Err(usage(format!("--by {other}: client or owner"))),
            };
            let page = flow::export_page(&layout, number, party)?;
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
        other => Err(usage(format!("no command {other:?}"))),
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
