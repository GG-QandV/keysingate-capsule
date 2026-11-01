#!/usr/bin/env python3
"""Unit tests for the judge_page.py --steps block (N9) — no network, no binary.

`python3 -m unittest discover -s scripts/tests` (from `core-v2/`).

Pins the spec (ops/supervisor/spec_demo_checklist.md §3): every step has a page
that verifies ACCEPTED (green); a missing page — no steps.json, a gap in the
step map, a step pointing at a page file that is gone, or a REJECTED page —
is shown in red.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import judge_page  # noqa: E402


def accepted_pages(*numbers, kinds=None):
    """Pages plus ACCEPTED verdicts: the all-green fixture."""
    kinds = kinds or {}
    pages, verdicts = {}, {}
    for number in numbers:
        pages[number] = {"path": Path("page-%d.json" % number),
                         "text": kinds.get(number, "result: accepted, clause 7.2")}
        verdicts[number] = {"accepted": True, "report": "ACCEPTED c-pages/%d" % number}
    return pages, verdicts


def steps_of(mapping):
    return {"exists": True, "path": "steps.json", "mapping": dict(mapping)}


class ReadStepsTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())

    def write(self, name, text):
        path = self.dir / name
        path.write_text(text)
        return path

    def test_no_flag_means_no_steps_block(self):
        self.assertIsNone(judge_page.read_steps(None))

    def test_a_missing_steps_file_is_reported_not_raised(self):
        steps = judge_page.read_steps(self.dir / "no-steps.json")
        self.assertFalse(steps["exists"])
        self.assertEqual(steps["mapping"], {})

    def test_unreadable_json_is_reported_not_raised(self):
        steps = judge_page.read_steps(self.write("steps.json", "{not json"))
        self.assertFalse(steps["exists"])
        self.assertIn("unreadable", steps["reason"])

    def test_a_non_object_is_reported_not_raised(self):
        steps = judge_page.read_steps(self.write("steps.json", "[1, 2]"))
        self.assertFalse(steps["exists"])
        self.assertIn("step", steps["reason"])

    def test_numeric_entries_become_an_int_map(self):
        path = self.write("steps.json", json.dumps({"1": 1, "2": 3}))
        self.assertEqual(judge_page.read_steps(path)["mapping"], {1: 1, 2: 3})

    def test_non_numeric_entries_are_skipped(self):
        path = self.write("steps.json", json.dumps({"1": 1, "two": 2, "3": "x"}))
        self.assertEqual(judge_page.read_steps(path)["mapping"], {1: 1})


class StepsBlockTest(unittest.TestCase):
    def test_all_steps_accepted_is_all_green(self):
        pages, verdicts = accepted_pages(1, 2)
        html = judge_page.steps_block(steps_of({1: 1, 2: 2}), pages, verdicts)
        self.assertEqual(html.count('color:green'), 2)
        self.assertNotIn('color:red', html)
        self.assertIn('ACCEPTED', html)

    def test_no_steps_flag_is_neutral_not_red(self):
        pages, verdicts = accepted_pages(1)
        html = judge_page.steps_block(None, pages, verdicts)
        self.assertIn('no --steps', html)
        self.assertNotIn('color:red', html)

    def test_a_missing_steps_file_is_red(self):
        steps = judge_page.read_steps(Path(tempfile.mkdtemp()) / "no-steps.json")
        pages, verdicts = accepted_pages(1)
        html = judge_page.steps_block(steps, pages, verdicts)
        self.assertIn('color:red', html)

    def test_a_step_without_a_recorded_page_is_red(self):
        pages, verdicts = accepted_pages(1, 3)
        html = judge_page.steps_block(steps_of({1: 1, 3: 3}), pages, verdicts)
        self.assertIn('color:red', html)
        self.assertIn('step 2: missing', html)
        self.assertEqual(html.count('color:green'), 2)

    def test_a_step_pointing_at_a_missing_page_file_is_red(self):
        pages, verdicts = accepted_pages(1)
        html = judge_page.steps_block(steps_of({1: 1, 2: 5}), pages, verdicts)
        self.assertIn('color:red', html)
        self.assertIn('page file missing', html)

    def test_a_rejected_page_is_red(self):
        pages, verdicts = accepted_pages(1, 2)
        verdicts[2] = {"accepted": False, "report": "REJECTED: seal mismatch"}
        html = judge_page.steps_block(steps_of({1: 1, 2: 2}), pages, verdicts)
        self.assertIn('color:red', html)
        self.assertIn('REJECTED', html)
        self.assertEqual(html.count('color:green'), 1)

    def test_an_empty_step_map_is_red(self):
        pages, verdicts = accepted_pages(1)
        html = judge_page.steps_block(steps_of({}), pages, verdicts)
        self.assertIn('color:red', html)
        self.assertIn('No steps recorded', html)

    def test_an_unchecked_page_is_neutral_not_red(self):
        pages, _ = accepted_pages(1)
        html = judge_page.steps_block(steps_of({1: 1}), pages, {})
        self.assertIn('not checked', html)
        self.assertNotIn('color:red', html)
        self.assertNotIn('color:green', html)


if __name__ == "__main__":
    unittest.main()
