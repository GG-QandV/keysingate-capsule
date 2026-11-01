#!/usr/bin/env python3
"""MCP server: the demo agent's tools over the stand's reader (hackathon demo, steps 2-8).

Tools
  ksg_get_container  pay for a container number through μ Gate (x402), print it,
                     initiate it and open the journal
  ksg_write_page     record one step of the agent's work as a journal page
  ksg_model_call     ask Muse Spark (Meta Model API) and journal the call itself:
                     model, sha256 of the request, sha256 of the answer, the tool
                     arguments and the time — one page per call
  ksg_mask_damage    ask SAM 3.1 for the damage mask inside a box and journal it:
                     model, sha256 of the picture, the box, sha256 of the mask
  ksg_export_page    export one page (pointwise export) to a file
  ksg_verify         check an exported page offline

Configuration (environment; paths only, no secret values):
  MODEL_API_KEY  the Meta Model API key (never printed; used by ksg_model_call,
                 ksg_mask_damage and the scripts around them)
  KSG_PANEL   path to ksg-remote-panel          (default: on PATH)
  KSG_VERIFY  path to ksg-verify-v2             (default: on PATH)
  KSG_TILL    path to the issuer's till example (ksg-pay-v2 examples/till)
  MU_SMOKE    path to μ Gate's ksg-smoke        (pays a 402 answer)
  KSG_WORK    working directory for containers  (default: ./ksg-work)
  KSG_CLASS   light | heavy                     (default: light; heavy needs real anchors)
  KSG_ISSUER  the issuer's payTo address        (default: the stand's test address)
  KSG_PRICE   price in USDC minor units         (default: 100000 = $0.10)
  KSG_ANCHOR  anchoring for heavy, e.g. solana:localnet (with KSG_PAYER, KSG_RPC)
  KSG_PAYER   path to the anchoring payer's keypair file
  KSG_RPC     the node's RPC URL (default: http://127.0.0.1:8899)

Run: python3 scripts/ksg_mcp.py   (stdio transport)
"""
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:  # mcp 2.x
    from mcp.server.mcpserver import MCPServer as FastMCP
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP

import ksg_model_api as api
import ksg_pages as pages_format

PANEL = os.environ.get("KSG_PANEL", "ksg-remote-panel")
VERIFY = os.environ.get("KSG_VERIFY", "ksg-verify-v2")
TILL = os.environ.get("KSG_TILL", "till")
SMOKE = os.environ.get("MU_SMOKE", "ksg-smoke")
WORK = Path(os.environ.get("KSG_WORK", "ksg-work"))
CLASS = os.environ.get("KSG_CLASS", "light")
ISSUER = os.environ.get("KSG_ISSUER", "0x209693Bc6afc0C5328bA36FaF03C514EF312287C")
PRICE = os.environ.get("KSG_PRICE", "100000")
RESOURCE = "https://issuer.example/container/issue"
ANCHOR = os.environ.get("KSG_ANCHOR", "")
PAYER = os.environ.get("KSG_PAYER", "")
RPC = os.environ.get("KSG_RPC", "http://127.0.0.1:8899")
MODEL = os.environ.get("KSG_MODEL", api.AGENT_MODEL)
MASK_MODEL = os.environ.get("KSG_MASK_MODEL", api.MASK_MODEL)
#: Pictures of the demo (synthetic by design): `demo/damage_4417.png`.
DEMO = Path(__file__).resolve().parent.parent / "demo"

mcp = FastMCP(
    "ksg",
    instructions="""Rules (always on): never print keys or secrets; never touch another container;
never edit container files by hand - only through these tools;
never open the secrets folder, never read key files;
one step = one tool call = one page = one reply line `STEP <n> OK page=<p>`
(or `STEP <n> FAIL <reason>`); never two steps in one answer;
a refused call means stop and report;
before the first work with a container read the skill docs/skills/ksg-container/SKILL.md.""",
)


def now() -> str:
    """The moment of a page, in UTC, one format."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run(args, stdin=None):
    p = subprocess.run(args, input=stdin, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"{Path(args[0]).name} {args[1] if len(args) > 1 else ''}: "
                           f"{(p.stderr or p.stdout).strip()[-400:]}")
    return p.stdout


def container_dir(name):
    d = WORK / name
    if not (d / "h" / "container.json").exists():
        raise RuntimeError(f"no container {name}")
    return d


def panel(d, *cmd, mobile=True):
    args = [PANEL, "--home", str(d / "h")]
    if mobile:
        args += ["--mobile", str(d / "m.json")]
    return run(args + list(cmd))


def pages(name, d=None) -> int:
    """How many pages the journal holds (page 0 is the first, so the last one is `pages-1`)."""
    out = panel(d or container_dir(name), "status", mobile=False)
    for line in out.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == "pages":
            return int(fields[1])
    raise RuntimeError(f"the status names no page count: {out.strip()[-300:]}")


def write_page(name, text) -> dict:
    """Write one journal page here and now; returns the page's number."""
    d = container_dir(name)
    before = pages(name, d)
    panel(d, "work", "--did", text)
    after = pages(name, d)
    if after <= before:
        raise RuntimeError(f"the page was not written: pages {before} -> {after}")
    return {"page": after - 1, "pages": after}


def page_text(name, number) -> str:
    """The text of a written page, read back from an export (the page itself is inside the capsule)."""
    d = container_dir(name)
    out = d / f"page-{number}.json"
    panel(d, "export-page", "--number", str(number), "--by", "owner", "--out", str(out))
    return pages_format.exported_text(json.loads(out.read_text()))


def verify_export(name, file) -> dict:
    """Check one exported page offline with ksg-verify-v2."""
    d = container_dir(name)
    cid = json.loads((d / "h" / "container.json").read_text())["id"]
    args = [VERIFY, "--export", str(file), "--container", cid, "--class", CLASS,
            "--keys", str(d / "keys.json")]
    if ANCHOR:
        args += ["--scan-key", str(d / "scan.key"), "--rpc", RPC,
                 "--cluster", ANCHOR.split(":", 1)[1]]
    p = subprocess.run(args, capture_output=True, text=True)
    report = (p.stdout + p.stderr).strip()
    return {"accepted": report.startswith("ACCEPTED"), "report": report}


@mcp.tool()
def ksg_get_container() -> dict:
    """Pay for a container number through μ Gate (x402), print, initiate and open the journal.
    Returns the container's local name and its identifier.

    Rules (always on): never print keys or secrets; never touch another container;
    never edit container files by hand - only through these tools;
    a refused call means stop and report;
    before the first work with a container read the skill docs/skills/ksg-container/SKILL.md.

    Idempotent within a run: once a container is made, every later call returns
    that same container (its name is kept in KSG_WORK/.current) — no new
    payment, no new print. A fresh run removes KSG_WORK/.current first."""
    current = WORK / ".current"
    if current.is_file():
        name = current.read_text().strip()
        meta = WORK / name / "h" / "container.json"
        if name.startswith("c-") and meta.is_file():
            cid = json.loads(meta.read_text())["id"]
            return {"name": name, "container": cid, "class": CLASS, "payment": "reused"}
    required = run([TILL, "required", ISSUER, PRICE, RESOURCE])
    header = run([SMOKE], stdin=required)
    accepted = run([TILL, "accept", ISSUER, PRICE, RESOURCE], stdin=header).strip()
    name = "c-" + uuid.uuid4().hex[:8]
    d = WORK / name
    d.mkdir(parents=True)
    init = [PANEL, "--home", str(d / "h"), "init", "--class", CLASS]
    if ANCHOR:
        init += ["--anchor", ANCHOR, "--payer", PAYER, "--rpc", RPC]
    run(init)
    panel(d, "packet", mobile=False)
    panel(d, "buyer-key", mobile=False)
    panel(d, "initiate")
    panel(d, "open-journal")
    cid = json.loads((d / "h" / "container.json").read_text())["id"]
    current.write_text(name)
    return {"name": name, "container": cid, "class": CLASS, "payment": accepted}


@mcp.tool()
def ksg_write_page(name: str, text: str) -> dict:
    """Record one step of the agent's work (input, tool call, result) as a journal page.
    Returns the page's number — the number `ksg_export_page` takes."""
    written = write_page(name, text)
    return {"name": name, "written": True, "page": written["page"], "pages": written["pages"]}


@mcp.tool()
def ksg_model_call(name: str, prompt: str, model: str = MODEL, system: str = "",
                   max_tokens: int = 4096, tool_args: dict | None = None) -> dict:
    """Ask Muse Spark through the Meta Model API and journal the call before answering.

    The page carries the model, sha256 of the request (canonical JSON), sha256 of
    the answer, the tool arguments (if any) and the time. `prompt` is synthetic
    demo data only: never repository code, private documents or keys (API Terms § 6.2).
    Returns the model's answer and the number of the page that recorded it."""
    answer = api.messages(model, prompt, system=system or None, max_tokens=max_tokens)
    text = api.answer_text(answer)
    if not text:
        # Muse Spark thinks before it answers: a small `max_tokens` is spent on the
        # thinking alone, and an empty answer is a failed call, not a short one.
        raise api.ModelApiError(
            f"the model returned no text (stop_reason={answer.get('stop_reason')}): "
            f"raise max_tokens (the thinking is counted there too)"
        )
    if tool_args is None:
        calls = [c["input"] for c in api.tool_calls(answer)]
        tool_args = calls[0] if len(calls) == 1 else calls or None
    args = tool_args
    lines = [
        "tool call: ksg_model_call",
        f"model: {model}",
        f"request sha256: {api.sha256_hex(api.canonical_json({'model': model, 'system': system or None, 'max_tokens': max_tokens, 'prompt': prompt}))}",
        f"response sha256: {api.sha256_hex(api.canonical_json(answer))}",
    ]
    if args:
        lines.append(f"tool args: {json.dumps(args, sort_keys=True, separators=(',', ':'), ensure_ascii=False)}")
    lines.append(f"time: {now()}")
    written = write_page(name, "\n".join(lines))
    return {"name": name, "model": model, "text": text, "page": written["page"],
            "pages": written["pages"], "usage": answer.get("usage", {})}


@mcp.tool()
def ksg_mask_damage(name: str, image_path: str, box: list, model: str = MASK_MODEL) -> dict:
    """Ask SAM 3.1 for the damage mask inside `box` = [x1, y1, x2, y2] of the picture.

    The page carries the model, sha256 of the picture, the box and sha256 of the
    mask — the expert re-asks SAM with the same box and compares it byte for byte.
    Pictures are synthetic by design (`demo/damage_4417.png`)."""
    path = Path(image_path)
    if not path.exists():
        path = DEMO / path.name  # `demo/...` written relative to another directory
    image = api.image_bytes(path)
    mask = api.sam_mask(image, box, model=model)
    lines = [
        "tool call: ksg_mask_damage",
        f"model: {mask['model']}",
        f"image: {path.name}",
        f"image sha256: {api.sha256_hex(image)}",
        f"image size: {mask['size'][0]}x{mask['size'][1]}",
        f"box: {','.join(str(v) for v in mask['box'])}",
        f"prompt: {mask['prompt']}",
        f"mask sha256: {mask['mask_sha256']}",
        f"masks: {len(mask['masks'])}",
        f"time: {now()}",
    ]
    written = write_page(name, "\n".join(lines))
    return {"name": name, "page": written["page"], "pages": written["pages"],
            "image": str(path), "image_sha256": api.sha256_hex(image),
            "box": mask["box"], "mask_sha256": mask["mask_sha256"],
            "masks": len(mask["masks"])}


@mcp.tool()
def ksg_export_page(name: str, number: int, by: str = "owner") -> dict:
    """Export one journal page (pointwise export, the container lives on). by: owner | client."""
    d = container_dir(name)
    out = d / f"page-{number}.json"
    panel(d, "export-page", "--number", str(number), "--by", by, "--out", str(out))
    data = json.loads(out.read_text())
    if isinstance(data, list):
        data = data[0]
        out.write_text(json.dumps(data))
    panel(d, "keys", "--out", str(d / "keys.json"), mobile=False)
    if ANCHOR:  # Pro seals are anchored blind: the expert reads them with the holder's scan key
        panel(d, "scan-key", "--out", str(d / "scan.key"), mobile=False)
    return {"file": str(out), "keys": str(d / "keys.json")}


@mcp.tool()
def ksg_verify(name: str, file: str) -> dict:
    """Check an exported page offline: no network, no platform, no issuer."""
    return verify_export(name, file)


if __name__ == "__main__":
    mcp.run()
