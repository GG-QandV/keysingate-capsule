#!/usr/bin/env python3
"""The expert repeats the SAM 3.1 request of a journal page and compares the mask.

The page `ksg_mask_damage` writes carries the model, sha256 of the picture, the
box and sha256 of the mask. This script takes the exported page and the picture,
checks the picture is the one the page names, asks SAM 3.1 the same question
(same model, same box) and compares the mask byte for byte:

  scripts/expert_recheck_mask.py --page page-5.json --image demo/damage_4417.png

Prints `✓ match` (exit 0) or `✗ mismatch` (exit 1). Only the picture of the
demo leaves the machine: synthetic, generated for the demo (API Terms § 6.2).
"""
import argparse
import json
import sys
from pathlib import Path

import ksg_model_api as api
import ksg_pages as pages

MATCH = "✓ match"
MISMATCH = "✗ mismatch"


def recheck(page_file, image_file, model=None) -> dict:
    """Re-ask SAM for the page's box and compare the mask hash."""
    data = json.loads(Path(page_file).read_text())
    text = pages.exported_text(data)
    fields = pages.page_fields(text)
    if fields.get("tool call") != "ksg_mask_damage":
        raise SystemExit(f"{page_file}: not a mask page (tool call: {fields.get('tool call')!r})")
    missing = [k for k in ("model", "image sha256", "box", "mask sha256") if k not in fields]
    if missing:
        raise SystemExit(f"{page_file}: the page has no {', '.join(missing)}")

    image = api.image_bytes(image_file)
    image_sha256 = api.sha256_hex(image)
    if image_sha256 != fields["image sha256"]:
        return {
            "matched": False,
            "verdict": MISMATCH,
            "why": "the picture is not the one the page names",
            "page": fields,
            "image_sha256": image_sha256,
        }

    box = [int(v) for v in fields["box"].split(",")]
    asked = api.sam_mask(image, box, model=model or fields["model"])
    same = asked["mask_sha256"] == fields["mask sha256"]
    return {
        "matched": same,
        "verdict": MATCH if same else MISMATCH,
        "why": None if same else "the mask differs from the page's hash",
        "page": fields,
        "image_sha256": image_sha256,
        "mask_sha256": asked["mask_sha256"],
        "box": box,
        "size": asked["size"],
        "masks": len(asked["masks"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Re-ask SAM 3.1 and compare a mask page.")
    parser.add_argument("--page", required=True, help="exported page JSON (ksg_export_page)")
    parser.add_argument("--image", required=True, help="the picture the page names")
    parser.add_argument("--model", default=None, help="default: the model on the page")
    parser.add_argument("--json", default=None, help="also write the verdict here")
    args = parser.parse_args()

    result = recheck(args.page, args.image, model=args.model)
    page = result["page"]
    print(f"page {args.page}: {page.get('tool call')} · {page.get('model', '?')}")
    print(f"picture sha256 {result['image_sha256']}")
    print(f"box           {page.get('box', '?')} of {page.get('image size', '?')}")
    print(f"page mask     {page.get('mask sha256', '?')}")
    print(f"asked mask    {result.get('mask_sha256', '—')}")
    print(f"masks         {result.get('masks', '—')}")
    if result["why"]:
        print(f"why           {result['why']}")
    print(result["verdict"])
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=1, ensure_ascii=False))
    return 0 if result["matched"] else 1


if __name__ == "__main__":
    sys.exit(main())
