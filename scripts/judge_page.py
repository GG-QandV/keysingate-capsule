#!/usr/bin/env python3
# Static judge page (hackathon): no server, EN, opens from file.
# Skeleton (J2): stdlib only, argparse --work/--box/--out,
# reads page-*.json + explanation text + ksg-verify-v2 verdicts,
# writes demo/out/judge.html. Sections (1)-(4) filled in J3-J5.
import argparse
import base64
import html as htmlmod
import json
import re
import subprocess
import sys
from pathlib import Path

CITATION = re.compile(r"\[p:(\d+)\]")


def find_inline(value):
    if isinstance(value, dict):
        if isinstance(value.get("inline"), str):
            return value["inline"]
        for inner in value.values():
            found = find_inline(inner)
            if found is not None:
                return found
    elif isinstance(value, list):
        for inner in value:
            found = find_inline(inner)
            if found is not None:
                return found
    return None


def exported_text(data):
    if isinstance(data, list):
        if not data:
            raise ValueError("export is empty")
        data = data[0]
    inline = find_inline(data)
    if inline is None:
        raise ValueError("export carries no inline content")
    padded = inline + "=" * (-len(inline) % 4)
    return base64.urlsafe_b64decode(padded).decode(errors="replace")


def resolve_box(work, box):
    candidate = Path(box)
    if candidate.exists():
        return candidate
    under = Path(work) / box
    if under.exists():
        return under
    raise SystemExit("--box %r not found (nor under --work %s)" % (box, work))


def find_pages(box_dir):
    out = []
    for path in sorted(Path(box_dir).glob("page-*.json")):
        stem = path.stem
        try:
            number = int(stem.split("-", 1)[1])
        except (IndexError, ValueError):
            continue
        out.append((number, path))
    return sorted(out)


def read_pages(box_dir):
    pages = {}
    for number, path in find_pages(box_dir):
        try:
            data = json.loads(path.read_text())
            pages[number] = {"path": path, "text": exported_text(data)}
        except Exception as exc:
            pages[number] = {"path": path, "text": "", "error": str(exc)}
    return pages


def read_explanation(path):
    if not path:
        return ""
    p = Path(path)
    if not p.exists():
        raise SystemExit("--text %s does not exist" % p)
    text = p.read_text()
    if not text.strip():
        raise SystemExit("--text %s is empty" % p)
    return text


def verify_pages(name, box_dir, pages, verify_bin=None, klass=None):
    verdicts = {}
    binary = Path(verify_bin) if verify_bin else None
    if binary is None:
        for cand in ("target/release/ksg-verify-v2", "target/debug/ksg-verify-v2"):
            root = Path(__file__).resolve().parent.parent / cand
            if root.exists():
                binary = root
                break
    box_dir = Path(box_dir)
    container_file = box_dir / "h" / "container.json"
    keys_file = box_dir / "keys.json"
    can_verify = (
        binary is not None and binary.exists()
        and container_file.exists() and keys_file.exists()
    )
    container_id = None
    if can_verify:
        try:
            container_id = json.loads(container_file.read_text())["id"]
        except Exception:
            can_verify = False
    for number, info in sorted(pages.items()):
        if not can_verify:
            verdicts[number] = {"accepted": None, "report": "not checked (no binary/keys)"}
            continue
        args = [str(binary), "--export", str(info["path"]),
                "--container", str(container_id), "--keys", str(keys_file)]
        if klass:
            args += ["--class", klass]
        try:
            proc = subprocess.run(args, capture_output=True, text=True, timeout=120)
            report = (proc.stdout + proc.stderr).strip()
            verdicts[number] = {"accepted": report.startswith("ACCEPTED"), "report": report}
        except Exception as exc:
            verdicts[number] = {"accepted": False, "report": "verify error: %s" % exc}
    return verdicts


def page_kind(text):
    t = (text or "")
    if "ksg_mask_damage" in t:
        return "SAM mask"
    if "ksg_model_call" in t:
        return "model call"
    low = t.strip().lower()
    if low.startswith("result:") or "\nresult:" in low:
        return "decision"
    if low.startswith("input:") or "\ninput:" in low:
        return "input"
    if "policy_lookup" in t:
        return "input (policy lookup)"
    return "note"


def citations(text):
    seen = []
    for number in CITATION.findall(text or ""):
        if int(number) not in seen:
            seen.append(int(number))
    return seen


CAPSULE_EXPECTED = 6291456
CAPSULE_IMG_W = 64
CAPSULE_IMG_H = 64


def read_capsule(path):
    if not path:
        return None
    cp = Path(path)
    if not cp.exists():
        return {"path": str(cp), "exists": False, "size": None, "ok_size": False, "head": b""}
    size = cp.stat().st_size
    try:
        with open(cp, "rb") as f:
            head = f.read(CAPSULE_IMG_W * CAPSULE_IMG_H)
    except Exception:
        head = b""
    return {"path": str(cp), "exists": True, "size": size,
            "ok_size": (size == CAPSULE_EXPECTED), "head": head}


def capsule_png_datauri(noise, w=CAPSULE_IMG_W, h=CAPSULE_IMG_H):
    import struct
    import zlib
    data = bytes(noise or b"")
    need = w * h
    if len(data) < need:
        data = data + bytes(need - len(data))
    else:
        data = data[:need]
    raw = b"".join(b"\x00" + bytes(data[i * w:(i + 1) * w]) for i in range(h))
    def chunk(ctype, payload):
        c = ctype + payload
        import binascii
        return struct.pack(">I", len(payload)) + c + struct.pack(">I", binascii.crc32(c) & 0xffffffff)
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 6))
           + chunk(b"IEND", b""))
    import base64
    return "data:image/png;base64," + base64.b64encode(png).decode()


def capsule_block(before, after):
    if before is None and after is None:
        return "<p>No capsule files given (--capsule-before/--capsule-after).</p>"
    parts = []
    for label, info in (("before", before), ("after", after)):
        if info is None:
            parts.append("<div><h3>Capsule %s: not given</h3></div>" % label)
            continue
        if not info.get("exists"):
            parts.append("<div><h3>Capsule %s: missing</h3><p>%s</p></div>"
                         % (label, htmlmod.escape(str(info.get("path")))))
            continue
        uri = capsule_png_datauri(info.get("head", b""))
        size = info.get("size")
        ok = "expected 6 MiB (6291456 bytes)" if info.get("ok_size") else "UNEXPECTED SIZE (expected 6291456 bytes)"
        parts.append(
            "<div><h3>Capsule %s: %d bytes — %s</h3>"
            "<img src=\"%s\" alt=\"capsule %s noise\" width=\"128\" height=\"128\">"
            "<p>First %d bytes of %s rendered as grayscale %dx%d.</p></div>"
            % (label, size, ok, uri, label,
               CAPSULE_IMG_W * CAPSULE_IMG_H,
               htmlmod.escape(str(info.get("path"))), CAPSULE_IMG_W, CAPSULE_IMG_H)
        )
    if before and after and before.get("exists") and after.get("exists"):
        if before.get("size") == after.get("size"):
            parts.append("<p>Capsule size unchanged: %d bytes before and after.</p>" % before.get("size"))
        else:
            parts.append("<p>SIZE MISMATCH: before %s bytes, after %s bytes.</p>"
                         % (before.get("size"), after.get("size")))
    return "\n".join(parts)


def read_mask_recheck(path):
    if not path:
        return None
    mp = Path(path)
    if not mp.exists():
        return {"exists": False, "path": str(mp), "matched": None,
                "verdict": "not checked", "why": "file %s does not exist" % mp}
    try:
        data = json.loads(mp.read_text())
    except Exception as exc:
        return {"exists": False, "path": str(mp), "matched": None,
                "verdict": "not checked", "why": "unreadable JSON: %s" % exc}
    data.setdefault("exists", True)
    data.setdefault("path", str(mp))
    return data


def mask_block(recheck):
    if not recheck:
        return "<p>Mask not rechecked (no --mask-json).</p>"
    if not recheck.get("exists", True):
        return ("<p>Mask recheck unavailable: %s</p>"
                % htmlmod.escape(str(recheck.get("why", recheck.get("path", "unknown")))))
    matched = recheck.get("matched")
    verdict = str(recheck.get("verdict", ""))
    mark = "\u2713" if matched else ("\u2717" if matched is False else "?")
    box = recheck.get("box", recheck.get("page", {}).get("box", "?") if isinstance(recheck.get("page"), dict) else "?")
    detail = []
    if isinstance(box, list):
        box = ",".join(str(v) for v in box)
    detail.append("Same box re-asked: %s." % htmlmod.escape(str(box)))
    for key in ("image_sha256", "mask_sha256"):
        if recheck.get(key):
            detail.append("%s: %s." % (key, htmlmod.escape(str(recheck[key]))[:32] + "\u2026"))
    page = recheck.get("page")
    if isinstance(page, dict):
        for key in ("model", "mask sha256"):
            if page.get(key):
                detail.append("page %s: %s." % (key, htmlmod.escape(str(page[key]))[:48]))
    if recheck.get("why"):
        detail.append("Why: %s." % htmlmod.escape(str(recheck["why"])))
    state = "match — hash coincides" if matched else ("MISMATCH" if matched is False else "unknown")
    return ("<p><strong>%s</strong> %s (%s).</p><p>%s</p>"
            % (htmlmod.escape(mark), htmlmod.escape(verdict), state, " ".join(detail)))


def read_tamper_recheck(path):
    if not path:
        return None
    tp = Path(path)
    if not tp.exists():
        return {"exists": False, "path": str(tp), "accepted": None,
                "verdict": "not checked", "reason": "file %s does not exist" % tp}
    try:
        data = json.loads(tp.read_text())
    except Exception as exc:
        return {"exists": False, "path": str(tp), "accepted": None,
                "verdict": "not checked", "reason": "unreadable JSON: %s" % exc}
    data.setdefault("exists", True)
    data.setdefault("path", str(tp))
    return data


def read_steps(path):
    """Step→page map the orchestrator records ($KSG_WORK/steps.json, N7).

    Returns None when no --steps given, else a record with exists/mapping.
    Non-numeric entries are skipped: the map is {step: page}, both ints.
    """
    if not path:
        return None
    sp = Path(path)
    if not sp.exists():
        return {"exists": False, "path": str(sp), "mapping": {},
                "reason": "file %s does not exist" % sp}
    try:
        data = json.loads(sp.read_text())
    except Exception as exc:
        return {"exists": False, "path": str(sp), "mapping": {},
                "reason": "unreadable JSON: %s" % exc}
    if not isinstance(data, dict):
        return {"exists": False, "path": str(sp), "mapping": {},
                "reason": "expected {step: page} object, got %s" % type(data).__name__}
    mapping = {}
    for key, value in data.items():
        try:
            mapping[int(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return {"exists": True, "path": str(sp), "mapping": mapping}


def steps_block(steps, pages, verdicts):
    """Block (6): every step has a page that verifies ACCEPTED.

    A missing step, a missing page file, or a REJECTED page is red;
    a page the verifier never saw is neutral (not checked).
    """
    if not steps:
        return "<p>Steps not recorded (no --steps).</p>"
    if not steps.get("exists", True):
        return ('<p><span style="color:red">Steps unavailable</span>: %s</p>'
                % htmlmod.escape(str(steps.get("reason", steps.get("path", "unknown")))))
    mapping = steps.get("mapping") or {}
    if not mapping:
        return ('<p><span style="color:red">No steps recorded</span>'
                " (%s is empty).</p>" % htmlmod.escape(str(steps.get("path", "steps.json"))))
    rows = []
    for number in range(1, max(mapping) + 1):
        page = mapping.get(number)
        if page is None:
            rows.append('<span style="color:red">step %d: missing — no page recorded</span>' % number)
            continue
        info = (pages or {}).get(page)
        if info is None:
            rows.append('<span style="color:red">step %d → page %d: page file missing</span>'
                        % (number, page))
            continue
        kind = page_kind(info.get("text", ""))
        accepted = (verdicts or {}).get(page, {}).get("accepted")
        if accepted is True:
            rows.append('<span style="color:green">step %d → page %d (%s): ACCEPTED \u2713</span>'
                        % (number, page, htmlmod.escape(kind)))
        elif accepted is False:
            verdict = (verdicts or {}).get(page, {})
            report = (verdict.get("report") or "REJECTED").splitlines()[0][:120]
            rows.append('<span style="color:red">step %d → page %d (%s): REJECTED — %s</span>'
                        % (number, page, htmlmod.escape(kind), htmlmod.escape(report)))
        else:
            rows.append("step %d → page %d (%s): not checked (?)"
                        % (number, page, htmlmod.escape(kind)))
    return "<ul>\n%s\n</ul>" % "\n".join("<li>%s</li>" % row for row in rows)


def tamper_block(tamper):
    if not tamper:
        return "<p>Tamper check not run (no --tamper-json).</p>"
    if not tamper.get("exists", True):
        return ("<p>Tamper check unavailable: %s</p>"
                % htmlmod.escape(str(tamper.get("reason", tamper.get("path", "unknown")))))
    accepted = tamper.get("accepted")
    verdict = str(tamper.get("verdict", ""))
    reason = str(tamper.get("reason", ""))[:300]
    page = tamper.get("tampered_page", tamper.get("page", "?"))
    if accepted is False or verdict.upper().startswith("REJECTED"):
        line = "tampered copy: REJECTED, reason %s" % (reason or verdict or "seal mismatch")
    elif accepted is True:
        line = ("tampered copy: ACCEPTED (UNEXPECTED \u2014 tamper not detected), reason %s"
                % (reason or verdict or "none"))
    else:
        line = "tampered copy: %s%s" % (verdict or "not checked",
                                        (", reason %s" % reason) if reason else "")
    return ("<p>%s (tampered page %s).</p>"
            % (htmlmod.escape(line), htmlmod.escape(str(page))))


def explain_html(explanation, pages):
    existing = set(pages or {})
    def repl(match):
        number = int(match.group(1))
        ok = number in existing
        tag = "checked by program" if ok else "MISSING PAGE — not checked"
        return ('<a href="#p-%d">[p:%d]</a>'
                '<span> (%s)</span>' % (number, number, tag))
    return CITATION.sub(repl, htmlmod.escape(explanation or ""))


def build_html(name, pages, verdicts, explanation, capsule_before=None, capsule_after=None,
               mask_recheck=None, tamper_recheck=None, steps=None):
    cited = citations(explanation)
    blocks = []
    for number in sorted(pages):
        info = pages[number]
        text = info.get("text", "")
        kind = page_kind(text)
        verdict = verdicts.get(number, {})
        accepted = verdict.get("accepted")
        mark = "UNKNOWN" if accepted is None else ("ACCEPTED" if accepted else "REJECTED")
        report = (verdict.get("report") or "").strip()
        first_report = report.splitlines()[0] if report else "not checked"
        body = htmlmod.escape(text) if text else "<p>Unreadable export: %s</p>" % htmlmod.escape(str(info.get("error", "unknown error")))
        if text:
            body = "<pre>%s</pre>" % body
        blocks.append(
            "<article id=\"p-%d\">\n<h3>Page %d — %s — %s</h3>\n%s\n<p>Verify: %s</p>\n</article>"
            % (number, number, htmlmod.escape(kind), mark, body, htmlmod.escape(first_report[:300]))
        )
    if blocks:
        pages_block = "\n".join(blocks)
    else:
        pages_block = "<p>No pages found.</p>"
    if explanation:
        expl_block = htmlmod.escape(explanation)
    else:
        expl_block = "<p>No explanation given (--text).</p>"
    parts = []
    parts.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
    parts.append("<title>Judge page — %s</title>\n</head>\n<body>\n" % htmlmod.escape(name))
    parts.append("<h1>Claim case — %s</h1>\n" % htmlmod.escape(name))
    parts.append("<h2>(1) Journal pages in order</h2>\n" + pages_block + "\n")
    parts.append("<h2>(2) Capsule noise before/after</h2>\n" + capsule_block(capsule_before, capsule_after) + "\n")
    parts.append("<h2>(3) SAM mask recheck</h2>\n" + mask_block(mask_recheck) + "\n")
    parts.append("<h2>(5) Tamper check</h2>\n" + tamper_block(tamper_recheck) + "\n")
    parts.append("<h2>(6) Steps \u2194 pages</h2>\n" + steps_block(steps, pages, verdicts) + "\n")
    parts.append("<h2>(4) Explanation for the judge</h2>\n")
    parts.append("<p>Citations checked by program: %s</p>\n" % htmlmod.escape(str(cited)))
    parts.append("<div>%s</div>\n</body>\n</html>\n" % explain_html(explanation, pages))
    return "".join(parts)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Static judge page, stdlib only.")
    parser.add_argument("--work", default="ksg-work", help="directory holding container boxes")
    parser.add_argument("--box", required=True, help="box dir path or bare name under --work")
    parser.add_argument("--out", default="demo/out/judge.html", help="output HTML file")
    parser.add_argument("--text", default=None, help="explanation text file ([p:N] citations)")
    parser.add_argument("--verify", default=None, help="ksg-verify-v2 binary (auto-detected)")
    parser.add_argument("--class", dest="klass", default=None, help="light | heavy")
    parser.add_argument("--capsule-before", default=None, help="capsule file before (6 MiB)")
    parser.add_argument("--capsule-after", default=None, help="capsule file after (6 MiB)")
    parser.add_argument("--mask-json", default=None,
                        help="precomputed expert_recheck_mask.py verdict JSON (--json)")
    parser.add_argument("--tamper-json", default=None,
                        help="tamper-check verdict JSON (tampered copy verify result)")
    parser.add_argument("--steps", default=None,
                        help="step→page JSON the orchestrator records ($KSG_WORK/steps.json, N7)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    box_dir = resolve_box(args.work, args.box)
    name = Path(box_dir).name
    pages = read_pages(box_dir)
    if not pages:
        raise SystemExit("no page-*.json under %s" % box_dir)
    explanation = read_explanation(args.text)
    verdicts = verify_pages(name, box_dir, pages, verify_bin=args.verify, klass=args.klass)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    cap_before = read_capsule(args.capsule_before)
    cap_after = read_capsule(args.capsule_after)
    mask_recheck = read_mask_recheck(args.mask_json)
    tamper_recheck = read_tamper_recheck(args.tamper_json)
    steps = read_steps(args.steps)
    out.write_text(build_html(name, pages, verdicts, explanation, cap_before, cap_after,
                              mask_recheck, tamper_recheck, steps))
    accepted = sum(1 for v in verdicts.values() if v["accepted"] is True)
    print("judge page: %s (box %s, pages %d, accepted %d)" % (out, name, len(pages), accepted))
    return 0


if __name__ == "__main__":
    sys.exit(main())
