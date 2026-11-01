#!/usr/bin/env python3
"""The judge's explanation — and the program, not the model, checks its citations.

Owner's decision 27.10: the explanation is written by the agent itself (Hermes,
Muse Spark), so the tool does not call a model for it. It takes the exported
pages the expert already holds, checks every one of them offline with
`ksg-verify-v2` (the same check the expert runs), and checks the citations of
the explanation it was given. The program — not the model — decides whether the
answer is honest:

  * every `[p:N]` names a page that exists **and** was ACCEPTED;
  * the answer cites at least one page;
  * a citation of a missing or unverified page is an error.

  # the agent wrote it: only the links are checked, no model is called
  scripts/judge_explain.py --name c-1a2b3c4d --text /tmp/explanation.txt \
      --page 1=ksg-work/c-1a2b3c4d/page-1.json \
      --page 2=ksg-work/c-1a2b3c4d/page-2.json

  # the old mode: the program asks Muse Spark and checks the same links
  scripts/judge_explain.py --name c-1a2b3c4d \
      --page 1=ksg-work/c-1a2b3c4d/page-1.json \
      --page 2=ksg-work/c-1a2b3c4d/page-2.json

Only the demo's synthetic claim leaves the machine (API Terms § 6.2), and only
in the old mode: `--text` touches no network at all.
"""
import argparse
import json
import sys
from pathlib import Path

import ksg_mcp
import ksg_model_api as api
import ksg_pages as pages

SYSTEM = (
    "You explain an insurance agent's decision to hackathon judges. Use only the journal "
    "pages given. Every statement needs a citation [p:N] where N is the page's number. "
    "Plain language, no jargon, at most 120 words. If the pages do not answer something, "
    "say so instead of guessing."
)

DEFAULT_QUESTION = "Why did the agent reject claim 4417, and what proves each step?"


def parse_pages(specs) -> dict:
    """`N=FILE` arguments → {N: Path}."""
    mapping = {}
    for spec in specs:
        number, _, path = spec.partition("=")
        if not path:
            raise SystemExit(f"--page {spec!r}: expected N=FILE")
        mapping[int(number)] = Path(path)
    return mapping


def verified_pages(name, mapping) -> dict:
    """{N: text} of the pages that exist and are ACCEPTED; anything else is an error."""
    texts, refusals = {}, []
    for number, path in sorted(mapping.items()):
        if not path.exists():
            refusals.append(f"page {number}: {path} does not exist")
            continue
        report = ksg_mcp.verify_export(name, path)
        if not report["accepted"]:
            refusals.append(f"page {number}: not verified — {report['report'].splitlines()[0] if report['report'] else 'no report'}")
            continue
        texts[number] = pages.exported_text(json.loads(path.read_text()))
    if refusals:
        raise SystemExit("the pages are not proof: " + "; ".join(refusals))
    if not texts:
        raise SystemExit("no pages given: nothing to explain")
    return texts


def build_prompt(texts, question) -> str:
    """The pages, then the question: the model sees only what was verified."""
    blocks = [f"--- p.{number} ---\n{text}" for number, text in sorted(texts.items())]
    return "\n\n".join(blocks) + f"\n\nQuestion: {question}\nAnswer with [p:N] citations."


def check_answer(answer, numbers) -> list:
    """The cited pages, or an error when the answer leans on nothing or on a page it never saw."""
    cited = pages.citations(answer)
    if not cited:
        raise SystemExit("the explanation cites no page: every claim needs [p:N]")
    unknown = [n for n in cited if n not in numbers]
    if unknown:
        raise SystemExit(
            "the explanation cites pages that are not verified proof: "
            + ", ".join(f"[p:{n}]" for n in unknown)
        )
    return cited


def explain(name, mapping, question=DEFAULT_QUESTION, model=api.AGENT_MODEL, transport=None) -> dict:
    """Verify the pages, ask the model, and check the citations (the old mode)."""
    texts = verified_pages(name, mapping)
    answer = api.messages(model, build_prompt(texts, question), system=SYSTEM, max_tokens=4096, transport=transport)
    text = api.answer_text(answer)
    cited = check_answer(text, set(texts))
    return {"pages": sorted(texts), "cited": cited, "model": model, "text": text,
            "usage": answer.get("usage", {})}


def check_explanation(name, mapping, text) -> dict:
    """Verify the pages, then check the links of the explanation the agent wrote.

    No model is called: the text is the agent's own, the program only decides
    whether every `[p:N]` in it points at a page that exists and was ACCEPTED.
    """
    texts = verified_pages(name, mapping)
    cited = check_answer(text, set(texts))
    return {"pages": sorted(texts), "cited": cited, "model": None, "text": text}


def text_from_file(path) -> str:
    """The explanation the agent wrote, from a file: a missing or empty one is an error."""
    path = Path(path)
    if not path.exists():
        raise SystemExit(f"--text {path} does not exist")
    text = path.read_text()
    if not text.strip():
        raise SystemExit(f"--text {path} is empty: the explanation needs at least one [p:N]")
    return text


def main() -> int:
    parser = argparse.ArgumentParser(description="Explain the decision; [p:N] checked by the program.")
    parser.add_argument("--name", required=True, help="container name (ksg-work/<name>)")
    parser.add_argument("--page", action="append", required=True, metavar="N=FILE",
                        help="exported page, repeatable")
    parser.add_argument("--text", default=None, metavar="FILE",
                        help="the explanation the agent wrote; no model is called")
    parser.add_argument("--question", default=DEFAULT_QUESTION)
    parser.add_argument("--model", default=api.AGENT_MODEL)
    parser.add_argument("--work", default=None, help="KSG_WORK of the stand")
    parser.add_argument("--class", dest="klass", default=None, help="light | heavy, for ksg-verify-v2")
    parser.add_argument("--out", default=None, help="also write the explanation here")
    args = parser.parse_args()

    if args.work:
        ksg_mcp.WORK = Path(args.work)
    if args.klass:
        ksg_mcp.CLASS = args.klass

    mapping = parse_pages(args.page)
    if args.text:
        result = check_explanation(args.name, mapping, text_from_file(args.text))
        print("explanation (written by the agent):")
    else:
        result = explain(args.name, mapping, question=args.question, model=args.model)
        print(f"explanation ({result['model']}):")
    print(result["text"])
    print()
    print(f"pages verified: {', '.join(f'p.{n}' for n in result['pages'])}")
    print(f"citations checked: {', '.join(f'[p:{n}]' for n in result['cited'])}")
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
