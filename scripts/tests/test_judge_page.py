#!/usr/bin/env python3
"""Tests of scripts/judge_page.py — fixtures only, no network, no binary.

`python3 -m unittest discover -s scripts/tests` (from `core-v2/`).
"""
import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import judge_page as jp


def export_of(text) -> dict:
    inline = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
    return {"page": {"body": {"content": {"kind": "work", "content": {"inline": inline}}}}}


FIXTURES = {
    1: "input: claim 4417, water damage\npolicy_lookup clause 7.2",
    2: "tool call: ksg_model_call\nmodel: muse-spark-1.3\nExclusion 7.2 applies.",
    3: "tool call: ksg_mask_damage\nmodel: sam-3.1\nbox: 0,0,1,1\nmask sha256: abc",
    4: "result: rejected under 7.2, gradual leak",
}


class FixtureBox(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.box = self.dir / "c-fix"
        self.box.mkdir()
        for number, text in FIXTURES.items():
            (self.box / f"page-{number}.json").write_text(json.dumps(export_of(text)))

    def test_find_pages_in_order(self):
        found = jp.find_pages(self.box)
        self.assertEqual([n for n, _ in found], [1, 2, 3, 4])

    def test_read_pages_decodes_inline(self):
        pages = jp.read_pages(self.box)
        self.assertEqual(set(pages), {1, 2, 3, 4})
        self.assertIn("claim 4417", pages[1]["text"])
        self.assertNotIn("error", pages[1])

    def test_page_kind(self):
        pages = jp.read_pages(self.box)
        self.assertEqual(jp.page_kind(pages[1]["text"]), "input")
        self.assertEqual(jp.page_kind(pages[2]["text"]), "model call")
        self.assertEqual(jp.page_kind(pages[3]["text"]), "SAM mask")
        self.assertEqual(jp.page_kind(pages[4]["text"]), "decision")

    def test_citations_keep_order_unique(self):
        self.assertEqual(jp.citations("rejected [p:2], input [p:1], again [p:2]"), [2, 1])
        self.assertEqual(jp.citations("no links"), [])


class VerifyFallback(unittest.TestCase):
    def test_no_binary_no_keys_is_not_checked(self):
        box = Path(tempfile.mkdtemp())
        pages = {1: {"path": box / "page-1.json", "text": "input: x"}}
        verdicts = jp.verify_pages("c-fix", box, pages,
                                   verify_bin=str(box / "no-such-binary"))
        self.assertIsNone(verdicts[1]["accepted"])
        self.assertIn("not checked", verdicts[1]["report"])


class CapsuleTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def cap(self, name, data: bytes):
        path = self.dir / name
        path.write_bytes(data)
        return jp.read_capsule(str(path))

    def test_missing_capsule(self):
        info = jp.read_capsule(str(self.dir / "no-such.cap"))
        self.assertFalse(info["exists"])
        self.assertFalse(info["ok_size"])

    def test_small_mock_capsule_renders_as_image(self):
        before = self.cap("before.cap", bytes(range(256)) * 16)
        after = self.cap("after.cap", bytes([255 - (i % 256) for i in range(4096)]))
        self.assertTrue(before["exists"])
        self.assertFalse(before["ok_size"])  # mock is small, not 6 MiB
        uri = jp.capsule_png_datauri(before["head"])
        self.assertTrue(uri.startswith("data:image/png;base64,"))
        block = jp.capsule_block(before, after)
        self.assertIn("Capsule before", block)
        self.assertIn("Capsule after", block)
        self.assertIn("UNEXPECTED SIZE", block)
        self.assertIn("Capsule size unchanged", block)

    def test_size_mismatch_flagged(self):
        before = self.cap("b.cap", b"\x01" * 100)
        after = self.cap("a.cap", b"\x02" * 200)
        self.assertIn("SIZE MISMATCH", jp.capsule_block(before, after))

    def test_no_capsules_placeholder(self):
        self.assertIn("No capsule", jp.capsule_block(None, None))


class MaskBlockTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def test_matched_mask_renders_tick(self):
        path = self.dir / "mask.json"
        path.write_text(json.dumps({"matched": True, "verdict": "\u2713 \u0441\u043e\u0432\u043f\u0430\u043b\u043e",
                                    "box": [0, 0, 1, 1], "image_sha256": "a" * 64,
                                    "mask_sha256": "b" * 64}))
        block = jp.mask_block(jp.read_mask_recheck(str(path)))
        self.assertIn("\u2713", block)
        self.assertIn("Same box re-asked", block)

    def test_mismatch_renders_cross(self):
        path = self.dir / "mask.json"
        path.write_text(json.dumps({"matched": False, "verdict": "\u2717 \u0440\u0430\u0441\u0445\u043e\u0434\u0438\u0442\u0441\u044f",
                                    "box": [0, 0, 1, 1]}))
        self.assertIn("\u2717", jp.mask_block(jp.read_mask_recheck(str(path))))

    def test_missing_mask_json(self):
        block = jp.mask_block(jp.read_mask_recheck(str(self.dir / "no.json")))
        self.assertIn("unavailable", block)

    def test_no_mask_arg(self):
        self.assertIn("no --mask-json", jp.mask_block(jp.read_mask_recheck(None)))


class TamperBlockTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def tamper(self, name, payload: dict):
        path = self.dir / name
        path.write_text(json.dumps(payload))
        return jp.read_tamper_recheck(str(path))

    def test_rejected_tamper_renders_line(self):
        t = self.tamper("tamper.json", {"exists": True, "tampered_page": "1",
                                        "accepted": False, "verdict": "REJECTED",
                                        "reason": "seal mismatch at byte 42"})
        block = jp.tamper_block(t)
        self.assertIn("tampered copy: REJECTED, reason seal mismatch at byte 42", block)
        self.assertIn("tampered page 1", block)

    def test_accepted_tamper_flagged_unexpected(self):
        t = self.tamper("tamper.json", {"exists": True, "tampered_page": "2",
                                        "accepted": True, "verdict": "ACCEPTED",
                                        "reason": "verify passed"})
        self.assertIn("UNEXPECTED", jp.tamper_block(t))

    def test_not_checked_state(self):
        t = self.tamper("tamper.json", {"exists": True, "tampered_page": "1",
                                        "accepted": None, "verdict": "not checked",
                                        "reason": "not checked (no binary/keys/container id)"})
        self.assertIn("tampered copy: not checked", jp.tamper_block(t))

    def test_missing_tamper_json(self):
        block = jp.tamper_block(jp.read_tamper_recheck(str(self.dir / "no.json")))
        self.assertIn("unavailable", block)

    def test_no_tamper_arg(self):
        self.assertIn("no --tamper-json", jp.tamper_block(jp.read_tamper_recheck(None)))

    def test_unreadable_tamper_json(self):
        bad = self.dir / "bad.json"
        bad.write_text("{not json")
        block = jp.tamper_block(jp.read_tamper_recheck(str(bad)))
        self.assertIn("unavailable", block)


class ExplainTest(unittest.TestCase):
    def test_cited_pages_become_links_checked_by_program(self):
        out = jp.explain_html("rejected [p:2], input [p:1]", {1: {}, 2: {}})
        self.assertIn('href="#p-2"', out)
        self.assertIn("checked by program", out)

    def test_missing_page_flagged(self):
        out = jp.explain_html("rejected [p:9]", {1: {}})
        self.assertIn("MISSING PAGE", out)


class BuildHtmlTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.box = self.dir / "c-fix"
        self.box.mkdir()
        for number, text in FIXTURES.items():
            (self.box / f"page-{number}.json").write_text(json.dumps(export_of(text)))
        self.pages = jp.read_pages(str(self.box))
        self.verdicts = {n: {"accepted": (n != 4),
                             "report": "ACCEPTED" if n != 4 else "REJECTED: seal"}
                         for n in self.pages}
        self.explanation = "Rejected under 7.2 [p:4], model said so [p:2], input [p:1]."
        before_p, after_p = self.dir / "b.cap", self.dir / "a.cap"
        before_p.write_bytes(b"\x01" * 5000)
        after_p.write_bytes(b"\x02" * 5000)
        self.before = jp.read_capsule(str(before_p))
        self.after = jp.read_capsule(str(after_p))
        mask_p = self.dir / "mask.json"
        mask_p.write_text(json.dumps({"matched": True, "verdict": "\u2713 \u0441\u043e\u0432\u043f\u0430\u043b\u043e",
                                      "box": [0, 0, 1, 1]}))
        self.mask = jp.read_mask_recheck(str(mask_p))
        tamper_p = self.dir / "tamper.json"
        tamper_p.write_text(json.dumps({"exists": True, "tampered_page": "1",
                                        "accepted": False, "verdict": "REJECTED",
                                        "reason": "seal mismatch"}))
        self.tamper = jp.read_tamper_recheck(str(tamper_p))

    def test_four_blocks_present(self):
        out = jp.build_html("c-fix", self.pages, self.verdicts, self.explanation,
                            self.before, self.after, self.mask, self.tamper)
        self.assertIn("(1) Journal pages", out)
        self.assertIn("(2) Capsule noise", out)
        self.assertIn("(3) SAM mask", out)
        self.assertIn("(5) Tamper check", out)
        self.assertIn("tampered copy: REJECTED", out)
        self.assertIn("(4) Explanation", out)
        for n in (1, 2, 3, 4):
            self.assertIn(f'id="p-{n}"', out)
        self.assertIn("ACCEPTED", out)
        self.assertIn("REJECTED", out)
        self.assertIn('href="#p-2"', out)
        self.assertIn("checked by program", out)
        self.assertIn("\u2713", out)
        self.assertIn("data:image/png;base64,", out)


class MainTest(unittest.TestCase):
    def test_main_writes_html_from_fixtures(self):
        d = Path(tempfile.mkdtemp())
        box = d / "c-e2e"
        box.mkdir()
        for number, text in FIXTURES.items():
            (box / f"page-{number}.json").write_text(json.dumps(export_of(text)))
        text_p = d / "expl.txt"
        text_p.write_text("Rejected [p:4], see input [p:1].")
        cap_b, cap_a = d / "b.cap", d / "a.cap"
        cap_b.write_bytes(b"\x01" * 5000)
        cap_a.write_bytes(b"\x01" * 5000)
        mask_p = d / "mask.json"
        mask_p.write_text(json.dumps({"matched": True, "verdict": "\u2713 \u0441\u043e\u0432\u043f\u0430\u043b\u043e",
                                      "box": [0, 0, 1, 1]}))
        tamper_p = d / "tamper.json"
        tamper_p.write_text(json.dumps({"exists": True, "tampered_page": "1",
                                        "accepted": False, "verdict": "REJECTED",
                                        "reason": "seal mismatch"}))
        out = d / "judge.html"
        rc = jp.main(["--work", str(d), "--box", "c-e2e", "--out", str(out),
                      "--text", str(text_p), "--verify", str(d / "no-bin"),
                      "--capsule-before", str(cap_b), "--capsule-after", str(cap_a),
                      "--mask-json", str(mask_p), "--tamper-json", str(tamper_p)])
        self.assertEqual(rc, 0)
        html = out.read_text()
        self.assertIn("(1) Journal pages", html)
        self.assertIn("(5) Tamper check", html)
        self.assertIn("tampered copy: REJECTED", html)
        self.assertIn("(4) Explanation", html)


if __name__ == "__main__":
    unittest.main()
