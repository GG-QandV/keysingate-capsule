#!/usr/bin/env python3
"""Regression tests for the demo orchestrator's STEP-line parsing (N10).

`python3 -m unittest discover -s scripts/tests` (from `core-v2/`).

The bug: the agent's answer "...STEP 1 OK page=1" arrived with no newline
before STEP, and the orchestrator's `^STEP ...` anchor missed it, so the demo
run failed. The helper below runs the same `grep` pipeline the orchestrator
uses (demo_orchestrator.sh: STEP_LINE=...), pinning the contract: the STEP
line is found anywhere in the answer, and the OK/FAIL verdict plus page=<n>
are read from that line — not from the whole answer.
"""
import subprocess
import tempfile
import unittest
from pathlib import Path


def parse_step_answer(step, text):
    """Run the orchestrator's STEP_LINE pipeline on the answer text.

    Mirrors demo_orchestrator.sh: STEP_LINE=$(grep -oE "STEP $STEP
    (OK|FAIL)[^[:cntrl:]]*" "$STEP_ANSWER" | tail -1); the OK/FAIL verdict
    and page=<n> are read from STEP_LINE.
    """
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write(text)
        answer = f.name
    found = subprocess.run(
        ["grep", "-oE", "STEP %d (OK|FAIL)[^[:cntrl:]]*" % step, answer],
        capture_output=True, text=True).stdout.splitlines()
    step_line = found[-1] if found else ""
    if not step_line:
        return {"found": False}
    ok = subprocess.run(["grep", "-qE", "STEP %d OK" % step],
                        input=step_line,
                        capture_output=True, text=True).returncode == 0
    page = subprocess.run("grep -oE 'page=[0-9]+' | head -1 | cut -d= -f2",
                          shell=True, input=step_line,
                          capture_output=True, text=True).stdout.strip()
    return {"found": True, "ok": ok, "page": page or None}


class StepLineTest(unittest.TestCase):
    def test_step_glued_to_text_without_a_newline_is_ok(self):
        result = parse_step_answer(1, "Выполняю.STEP 1 OK page=1")
        self.assertTrue(result["found"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["page"], "1")

    def test_fail_line_glued_to_text_is_fail(self):
        result = parse_step_answer(2, "текст STEP 2 FAIL причина")
        self.assertTrue(result["found"])
        self.assertFalse(result["ok"])

    def test_a_plain_step_line_still_parses(self):
        result = parse_step_answer(1, "STEP 1 OK page=3\n")
        self.assertTrue(result["found"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["page"], "3")

    def test_a_bare_step_line_has_no_page(self):
        result = parse_step_answer(7, "STEP 7 OK\n")
        self.assertTrue(result["found"])
        self.assertTrue(result["ok"])
        self.assertIsNone(result["page"])

    def test_step_10_does_not_match_step_1(self):
        result = parse_step_answer(1, "STEP 10 OK page=5\n")
        self.assertFalse(result["found"])

    def test_a_missing_step_line_is_not_found(self):
        result = parse_step_answer(3, "some cut-off text with no verdict")
        self.assertFalse(result["found"])


class RetryPromptTest(unittest.TestCase):
    def test_the_retry_note_tells_the_agent_not_to_redo_the_step(self):
        script = Path(__file__).resolve().parent.parent / "demo_orchestrator.sh"
        self.assertIn("do NOT do it again", script.read_text())


if __name__ == "__main__":
    unittest.main()
