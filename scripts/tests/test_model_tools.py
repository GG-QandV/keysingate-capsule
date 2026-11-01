#!/usr/bin/env python3
"""Tests of the demo's model tools — no network, no capsule, no Meta API key.

`python3 -m unittest discover -s scripts/tests` (from `core-v2/`).

The HTTP transport is replaced by a function that answers from a fixture, the
journal page writing is replaced by a sink that keeps the page's text, and the
offline verifier is replaced by a verdict per page — so every test pins what the
tools do, not what the stand or the API happen to answer today.
"""
import base64
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import expert_recheck_mask  # noqa: E402
import judge_explain  # noqa: E402
import ksg_mcp  # noqa: E402
import ksg_model_api as api  # noqa: E402
import ksg_pages as pages  # noqa: E402

#: A 1×1 PNG: the tools read the picture's size from its IHDR.
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def export_of(text) -> dict:
    """An exported page, shaped like `ksg_remote_panel export-page` writes it."""
    inline = base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
    return {"page": {"body": {"content": {"kind": "work", "content": {"inline": inline}}}}}


def sam_answer(data="1,1,AAECAw") -> dict:
    """A SAM 3.1 answer in the format of `/tmp/sam-check/REPORT.md`."""
    text = f"<0f>1<|box;x1=0;y1=0;x2=1;y2=1;w=1;h=1|><|mask;x=0;y=0;data={data}|>"
    return {"output": [{"type": "message", "content": [{"type": "output_text", "text": text}]}],
            "usage": {"images_processed": 1}}


class Transport:
    """A stand-in for the API: one canned answer, and a note of what was asked."""

    def __init__(self, answer, status=200):
        self.answer, self.status = answer, status
        self.calls = []

    def __call__(self, url, headers, body):
        self.calls.append({"url": url, "headers": headers, "body": json.loads(body)})
        return self.status, json.dumps(self.answer).encode()


class Base(unittest.TestCase):
    def setUp(self):
        self.page_text = None
        # A fake key: the tools read MODEL_API_KEY, tests must never need the real one.
        self.saved_key = os.environ.get(api.KEY_ENV)
        os.environ[api.KEY_ENV] = "test-key-not-a-secret"
        self.order = []
        self.saved = (api.TRANSPORT, ksg_mcp.write_page, ksg_mcp.verify_export, ksg_mcp.WORK)

        def write_page(name, text):
            self.order.append("page")
            self.page_text = text
            return {"page": 7, "pages": 8}

        api.TRANSPORT = Transport({})
        ksg_mcp.write_page = write_page

    def tearDown(self):
        api.TRANSPORT, ksg_mcp.write_page, ksg_mcp.verify_export, ksg_mcp.WORK = self.saved
        if self.saved_key is None:
            os.environ.pop(api.KEY_ENV, None)
        else:
            os.environ[api.KEY_ENV] = self.saved_key

    def answer_with(self, answer):
        transport = Transport(answer)

        def via(url, headers, body):
            self.order.append("api")
            return transport(url, headers, body)

        api.TRANSPORT = via
        return transport


class ModelCallTest(Base):
    def test_one_call_one_page_with_both_hashes(self):
        answer = {
            "content": [
                {"type": "text", "text": "Exclusion 7.2 applies: a gradual leak."},
                {"type": "tool_use", "name": "policy_lookup", "input": {"clause": "7.2"}},
            ],
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
        transport = self.answer_with(answer)

        result = ksg_mcp.ksg_model_call("c-1", "read the claim", model="muse-spark-1.3",
                                        tool_args={"claim": "4417"})

        # The page is written before the answer is handed back.
        self.assertEqual(self.order, ["api", "page"])
        self.assertEqual(result["page"], 7)
        self.assertEqual(result["text"], "Exclusion 7.2 applies: a gradual leak.")

        fields = pages.page_fields(self.page_text)
        self.assertEqual(fields["tool call"], "ksg_model_call")
        self.assertEqual(fields["model"], "muse-spark-1.3")
        expected_request = api.sha256_hex(api.canonical_json({
            "model": "muse-spark-1.3", "system": None, "max_tokens": 4096,
            "prompt": "read the claim",
        }))
        self.assertEqual(fields["request sha256"], expected_request)
        self.assertEqual(fields["response sha256"], api.sha256_hex(api.canonical_json(answer)))
        self.assertEqual(json.loads(fields["tool args"]), {"claim": "4417"})
        self.assertTrue(fields["time"].endswith("Z"))

        # Anthropic Messages: the key travels in a header, never in the body.
        call = transport.calls[0]
        self.assertTrue(call["url"].endswith("/v1/messages"))
        self.assertEqual(call["headers"]["x-api-key"], "test-key-not-a-secret")
        self.assertNotIn("test-key-not-a-secret", json.dumps(call["body"]))

    def test_tool_arguments_come_from_the_answer_when_not_given(self):
        self.answer_with({"content": [
            {"type": "text", "text": "ok"},
            {"type": "tool_use", "name": "policy_lookup", "input": {"clause": "7.2", "page": 3}},
        ]})
        ksg_mcp.ksg_model_call("c-1", "read the claim")
        fields = pages.page_fields(self.page_text)
        self.assertEqual(json.loads(fields["tool args"]), {"clause": "7.2", "page": 3})

    def test_a_page_without_arguments_has_no_arguments_line(self):
        self.answer_with({"content": [{"type": "text", "text": "ok"}]})
        ksg_mcp.ksg_model_call("c-1", "read the claim")
        self.assertNotIn("tool args", pages.page_fields(self.page_text))

    def test_an_empty_answer_is_an_error_and_writes_no_page(self):
        # Muse Spark spends `max_tokens` on its thinking first: no text, no page.
        self.answer_with({"content": [{"type": "redacted_thinking", "data": "AAA"}],
                          "stop_reason": "max_tokens"})
        with self.assertRaises(api.ModelApiError):
            ksg_mcp.ksg_model_call("c-1", "read the claim")
        self.assertIsNone(self.page_text)

    def test_a_refused_call_writes_no_page(self):
        api.TRANSPORT = lambda url, headers, body: (429, b'{"error":"slow down"}')
        with self.assertRaises(api.ModelApiError):
            ksg_mcp.ksg_model_call("c-1", "read the claim")
        self.assertIsNone(self.page_text)


class MaskTest(Base):
    def setUp(self):
        super().setUp()
        self.dir = tempfile.mkdtemp()
        self.image = Path(self.dir) / "damage_4417.png"
        self.image.write_bytes(PNG)

    def test_one_mask_one_page_with_picture_box_and_mask_hashes(self):
        transport = self.answer_with(sam_answer("1,1,AAECAw"))

        result = ksg_mcp.ksg_mask_damage("c-1", str(self.image), [0, 0, 1, 1])

        self.assertEqual(result["page"], 7)
        fields = pages.page_fields(self.page_text)
        self.assertEqual(fields["tool call"], "ksg_mask_damage")
        self.assertEqual(fields["model"], "sam-3.1")
        self.assertEqual(fields["image sha256"], api.sha256_hex(PNG))
        self.assertEqual(fields["image size"], "1x1")
        self.assertEqual(fields["box"], "0,0,1,1")
        self.assertEqual(fields["mask sha256"], api.sha256_hex("1,1,AAECAw"))
        self.assertEqual(fields["prompt"], "<0f>1<|box;x1=0;y1=0;x2=1;y2=1;w=1;h=1|>")
        self.assertEqual(fields["masks"], "1")

        # The picture travels as a data URL, the box as the documented prompt.
        body = transport.calls[0]["body"]
        self.assertTrue(body["input"][0]["content"][1]["image_url"].startswith("data:image/png;base64,"))
        self.assertIn("<|box;x1=0;y1=0;x2=1;y2=1;w=1;h=1|>", body["input"][0]["content"][0]["text"])

    def test_a_box_outside_the_picture_is_refused_before_any_call(self):
        transport = self.answer_with(sam_answer())
        with self.assertRaises(api.ModelApiError):
            ksg_mcp.ksg_mask_damage("c-1", str(self.image), [0, 0, 5, 5])
        self.assertEqual(transport.calls, [])

    def test_no_mask_is_an_error_not_an_empty_page(self):
        self.answer_with({"output": [{"type": "message", "content": [{"type": "output_text", "text": ""}]}]})
        with self.assertRaises(api.ModelApiError):
            ksg_mcp.ksg_mask_damage("c-1", str(self.image), [0, 0, 1, 1])
        self.assertIsNone(self.page_text)


class ExpertRecheckTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.saved_key = os.environ.get(api.KEY_ENV)
        os.environ[api.KEY_ENV] = "test-key-not-a-secret"
        self.image = self.dir / "damage_4417.png"
        self.image.write_bytes(PNG)
        self.page = self.dir / "page-5.json"
        self.saved = api.TRANSPORT

    def tearDown(self):
        api.TRANSPORT = self.saved
        if self.saved_key is None:
            os.environ.pop(api.KEY_ENV, None)
        else:
            os.environ[api.KEY_ENV] = self.saved_key

    def write_page(self, data="1,1,AAECAw", image_sha=None, box="0,0,1,1"):
        text = "\n".join([
            "tool call: ksg_mask_damage",
            "model: sam-3.1",
            "image: damage_4417.png",
            f"image sha256: {image_sha or api.sha256_hex(PNG)}",
            "image size: 1x1",
            f"box: {box}",
            "prompt: <0f>1<|box;x1=0;y1=0;x2=1;y2=1;w=1;h=1|>",
            f"mask sha256: {api.sha256_hex(data)}",
            "masks: 1",
            "time: 2026-10-27T08:00:00Z",
        ])
        self.page.write_text(json.dumps(export_of(text)))

    def test_the_same_box_gives_the_same_mask(self):
        self.write_page("1,1,AAECAw")
        transport = Transport(sam_answer("1,1,AAECAw"))
        api.TRANSPORT = transport

        result = expert_recheck_mask.recheck(self.page, self.image)

        self.assertTrue(result["matched"])
        self.assertEqual(result["verdict"], "✓ match")
        self.assertEqual(result["mask_sha256"], api.sha256_hex("1,1,AAECAw"))
        self.assertEqual(transport.calls[0]["body"]["input"][0]["content"][0]["text"],
                         "<0f>1<|box;x1=0;y1=0;x2=1;y2=1;w=1;h=1|>")

    def test_a_different_mask_is_a_mismatch(self):
        self.write_page("1,1,AAECAw")
        api.TRANSPORT = Transport(sam_answer("1,1,AAECBB"))

        result = expert_recheck_mask.recheck(self.page, self.image)

        self.assertFalse(result["matched"])
        self.assertEqual(result["verdict"], "✗ mismatch")

    def test_another_picture_is_a_mismatch_without_a_call(self):
        self.write_page(image_sha="0" * 64)
        transport = Transport(sam_answer("1,1,AAECAw"))
        api.TRANSPORT = transport

        result = expert_recheck_mask.recheck(self.page, self.image)

        self.assertFalse(result["matched"])
        self.assertEqual(result["why"], "the picture is not the one the page names")
        self.assertEqual(transport.calls, [])

    def test_a_page_of_another_tool_is_refused(self):
        text = "tool call: ksg_model_call\nmodel: muse-spark-1.3\ntime: 2026-10-27T08:00:00Z"
        self.page.write_text(json.dumps(export_of(text)))
        with self.assertRaises(SystemExit):
            expert_recheck_mask.recheck(self.page, self.image)


class JudgeExplainTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.saved_key = os.environ.get(api.KEY_ENV)
        os.environ[api.KEY_ENV] = "test-key-not-a-secret"
        self.pages = {}
        for number, text in {1: "input: claim 4417, water damage", 2: "result: rejected, 7.2"}.items():
            path = self.dir / f"page-{number}.json"
            path.write_text(json.dumps(export_of(text)))
            self.pages[number] = path
        self.saved = (api.TRANSPORT, ksg_mcp.verify_export, ksg_mcp.WORK)
        ksg_mcp.WORK = self.dir
        ksg_mcp.verify_export = lambda name, file: {"accepted": True, "report": "ACCEPTED"}

    def tearDown(self):
        api.TRANSPORT, ksg_mcp.verify_export, ksg_mcp.WORK = self.saved
        if self.saved_key is None:
            os.environ.pop(api.KEY_ENV, None)
        else:
            os.environ[api.KEY_ENV] = self.saved_key

    def answer_with(self, text):
        transport = Transport({"content": [{"type": "text", "text": text}]})
        api.TRANSPORT = transport
        return transport

    def test_an_explanation_that_cites_verified_pages_passes(self):
        transport = self.answer_with("The claim was rejected because of the gradual leak [p:2], "
                                     "as the input page shows [p:1].")

        result = judge_explain.explain("c-1", self.pages)

        self.assertEqual(result["pages"], [1, 2])
        self.assertEqual(result["cited"], [2, 1])
        # Only the verified pages' text goes to the model, never a file path.
        prompt = transport.calls[0]["body"]["messages"][0]["content"]
        self.assertIn("input: claim 4417", prompt)
        self.assertIn("result: rejected, 7.2", prompt)
        self.assertNotIn(str(self.dir / "page-1.json"), prompt)

    def test_no_citation_is_an_error(self):
        self.answer_with("The claim was rejected because the leak was gradual.")
        with self.assertRaises(SystemExit):
            judge_explain.explain("c-1", self.pages)

    def test_a_citation_of_a_missing_page_is_an_error(self):
        self.answer_with("Rejected [p:1] and also [p:9].")
        with self.assertRaises(SystemExit):
            judge_explain.explain("c-1", self.pages)

    def test_an_unverified_page_is_not_proof(self):
        def verify(name, file):
            accepted = "page-1" in str(file)
            return {"accepted": accepted, "report": "ACCEPTED" if accepted else "REJECTED: seal"}
        ksg_mcp.verify_export = verify
        transport = self.answer_with("Rejected [p:1].")
        with self.assertRaises(SystemExit) as caught:
            judge_explain.explain("c-1", self.pages)
        self.assertIn("page 2", str(caught.exception))
        self.assertEqual(transport.calls, [])

    def test_a_missing_export_is_an_error(self):
        self.answer_with("Rejected [p:1].")
        with self.assertRaises(SystemExit):
            judge_explain.explain("c-1", {1: self.pages[1], 4: self.dir / "page-4.json"})

    # --text: the agent writes the explanation, the program only checks its links.

    def text_file(self, text, name="explanation.txt"):
        path = self.dir / name
        path.write_text(text)
        return path

    def test_text_mode_checks_the_links_and_calls_no_model(self):
        # No key at all: the --text mode must not need one.
        os.environ.pop(api.KEY_ENV, None)
        transport = self.answer_with("the model must not be asked")

        path = self.text_file("The claim was rejected under clause 7.2 [p:2], "
                              "as the input page shows [p:1].")
        result = judge_explain.check_explanation("c-1", self.pages, judge_explain.text_from_file(path))

        self.assertEqual(result["pages"], [1, 2])
        self.assertEqual(result["cited"], [2, 1])
        self.assertIsNone(result["model"])
        self.assertIn("[p:2]", result["text"])
        self.assertEqual(transport.calls, [])

    def test_text_mode_with_a_link_to_a_missing_page_is_an_error(self):
        path = self.text_file("Rejected [p:1] and also [p:9].")
        with self.assertRaises(SystemExit) as caught:
            judge_explain.check_explanation("c-1", self.pages, judge_explain.text_from_file(path))
        self.assertIn("p:9", str(caught.exception))

    def test_text_mode_without_links_is_an_error(self):
        path = self.text_file("The claim was rejected because the leak was gradual.")
        with self.assertRaises(SystemExit):
            judge_explain.check_explanation("c-1", self.pages, judge_explain.text_from_file(path))

    def test_text_mode_with_an_empty_file_is_an_error(self):
        path = self.text_file(" \n")
        with self.assertRaises(SystemExit):
            judge_explain.check_explanation("c-1", self.pages, judge_explain.text_from_file(path))

    def test_text_mode_with_a_missing_file_is_an_error(self):
        with self.assertRaises(SystemExit):
            judge_explain.text_from_file(self.dir / "no-such-explanation.txt")


class CanonicalTest(unittest.TestCase):
    def test_key_order_does_not_change_the_hash(self):
        one = {"b": 1, "a": {"y": 2, "x": 3}}
        two = {"a": {"x": 3, "y": 2}, "b": 1}
        self.assertEqual(api.canonical_json(one), api.canonical_json(two))
        self.assertEqual(api.sha256_hex(api.canonical_json(one)), api.sha256_hex(api.canonical_json(two)))

    def test_the_page_format_survives_a_colon_in_the_value(self):
        fields = pages.page_fields("tool call: ksg_model_call\ntool args: {\"q\":\"a: b\"}\ntime: 2026-10-27T08:00:00Z")
        self.assertEqual(fields["tool args"], '{"q":"a: b"}')
        self.assertEqual(fields["time"], "2026-10-27T08:00:00Z")


if __name__ == "__main__":
    unittest.main()


class GetContainerOncePerRun(unittest.TestCase):
    """`ksg_get_container` makes the run's container once and hands the same one
    to every later step (KSG_WORK/.current) — no second payment or print."""

    def test_second_call_reuses_the_container(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            calls = []

            def fake_run(args, stdin=None):
                calls.append(args)
                if "init" in args:
                    home = Path(args[args.index("--home") + 1])
                    home.mkdir(parents=True)
                    (home / "container.json").write_text(json.dumps({"id": "did:test:1"}))
                return "ok"

            saved = (ksg_mcp.WORK, ksg_mcp.run, ksg_mcp.panel)
            ksg_mcp.WORK, ksg_mcp.run = work, fake_run
            ksg_mcp.panel = lambda d, cmd, mobile=True: None
            try:
                first = ksg_mcp.ksg_get_container()
                n = len(calls)
                second = ksg_mcp.ksg_get_container()
            finally:
                ksg_mcp.WORK, ksg_mcp.run, ksg_mcp.panel = saved
            self.assertEqual(first["name"], second["name"])
            self.assertEqual(second["payment"], "reused")
            self.assertEqual(len(calls), n, "the second call paid or printed again")
            self.assertEqual((work / ".current").read_text(), first["name"])
