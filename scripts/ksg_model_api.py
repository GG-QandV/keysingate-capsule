#!/usr/bin/env python3
"""Meta Model API calls of the hackathon demo, in the protocols the API speaks.

Two of them are used here, because the demo needs two different things:

  * Anthropic Messages (`POST /messages`) — the agent's reasoning: Muse Spark
    reads the claim and names the clause (`ksg_model_call`, `judge_explain.py`).
  * OpenAI Responses (`POST /responses`) — segmentation: SAM 3.1 turns a box
    into a damage mask (`ksg_mask_damage`, `expert_recheck_mask.py`).

What leaves this module is a synthetic demo artefact only — the invented claim
`demo/case_4417.md` and generated pictures. No repository code, no private documents,
no keys (API Terms § 6.2).

Configuration (environment; the value is never printed, logged or put on a
command line):

  MODEL_API_KEY    the Meta Model API key
  KSG_MODEL_BASE   the API base (default: https://api.meta.ai/v1)

Transport is a plain function `transport(url, headers, body) -> (status, bytes)`,
default `TRANSPORT`; tests replace `TRANSPORT`, so nothing here needs a network.
"""
import base64
import hashlib
import json
import os
import re
import urllib.error
import urllib.request

KEY_ENV = "MODEL_API_KEY"
BASE = os.environ.get("KSG_MODEL_BASE", "https://api.meta.ai/v1")

#: The demo agent's model, and the two other models the demo uses.
AGENT_MODEL = "muse-spark-1.3"
MASK_MODEL = "sam-3.1"
IMAGE_MODEL = "muse-image-1.0"

ANTHROPIC_VERSION = "2023-06-01"

#: `<|mask;x=..;y=..;data=H,W,marker+payload|>` — SAM's answer record.
MASK_RECORD = re.compile(r"<\|mask;x=(\d+);y=(\d+);data=(.*?)\|>", re.S)


class ModelApiError(RuntimeError):
    """The API refused, the answer made no sense, or the key is missing."""


def api_key() -> str:
    """The key from the environment; a missing one is an error, not an empty header."""
    key = os.environ.get(KEY_ENV, "")
    if not key:
        raise ModelApiError(f"{KEY_ENV} is empty: put the Meta Model API key in the environment")
    return key


def canonical_json(value) -> bytes:
    """One value, one byte string: the hash of a request must not depend on key order."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data) -> str:
    """sha256 of bytes (or of a string's UTF-8)."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def _urllib_transport(url, headers, body):
    """The real transport: one POST, no retries, a short timeout."""
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=180) as answer:
            return answer.status, answer.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except urllib.error.URLError as error:
        raise ModelApiError(f"the API is unreachable: {error.reason}") from error


#: The transport `post_json` uses; tests replace this one.
TRANSPORT = _urllib_transport


def post_json(path, payload, transport=None) -> dict:
    """POST a JSON payload to `path` of the API and return the parsed answer."""
    url = BASE.rstrip("/") + path
    body = canonical_json(payload)
    headers = {
        "content-type": "application/json",
        "x-api-key": api_key(),
        "anthropic-version": ANTHROPIC_VERSION,
        "authorization": f"Bearer {api_key()}",
    }
    status, raw = (transport or TRANSPORT)(url, headers, body)
    if status // 100 != 2:
        raise ModelApiError(f"POST {url}: HTTP {status}: {raw[:400].decode(errors='replace')}")
    try:
        return json.loads(raw)
    except ValueError as error:
        raise ModelApiError(f"POST {url}: the answer is not JSON: {error}") from error


def messages(model, prompt, system=None, max_tokens=1024, tools=None, transport=None) -> dict:
    """One Anthropic-Messages turn: `prompt` in, the model's answer out."""
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        payload["system"] = system
    if tools:
        payload["tools"] = tools
    return post_json("/messages", payload, transport)


def answer_text(answer) -> str:
    """The text of an answer, whichever protocol carried it.

    Anthropic Messages answers in `content` blocks, Responses in `output`;
    both carry text blocks with a `text` field.
    """
    blocks = list(answer.get("content") or [])
    for item in answer.get("output") or []:
        blocks.extend(item.get("content") or [])
    kinds = ("text", "output_text")
    return "\n".join(b.get("text", "") for b in blocks if b.get("type") in kinds).strip()


def tool_calls(answer) -> list:
    """The tool the model asked the caller to run, if it did: [{"name", "input"}]."""
    blocks = answer.get("content") or []
    return [{"name": b.get("name"), "input": b.get("input", {})} for b in blocks if b.get("type") == "tool_use"]


def png_size(data: bytes) -> tuple:
    """Width and height from a PNG's IHDR — the SAM prompt wants the media's size."""
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ModelApiError("the picture is not a PNG")
    if data[12:16] != b"IHDR":
        raise ModelApiError("the PNG has no IHDR chunk")
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


def box_prompt(box, size) -> str:
    """SAM 3.1's box prompt: pixels of the media, and the media's size, one box.

    Format from the SAM check on this machine (`/tmp/sam-check/REPORT.md`):
    `<0f>1<|box;x1=..;y1=..;x2=..;y2=..;w=..;h=..|>`. `box` is (x1, y1, x2, y2).
    """
    x1, y1, x2, y2 = (int(v) for v in box)
    width, height = (int(v) for v in size)
    if not (0 <= x1 < x2 <= width and 0 <= y1 < y2 <= height):
        raise ModelApiError(
            f"box {x1},{y1},{x2},{y2} is not inside the {width}x{height} picture"
        )
    return f"<0f>1<|box;x1={x1};y1={y1};x2={x2};y2={y2};w={width};h={height}|>"


def sam_mask(image: bytes, box, model=MASK_MODEL, transport=None) -> dict:
    """Ask SAM 3.1 for the mask inside `box`.

    Returns the request (for its hash), the answer, the mask records and their
    sha256. The mask bytes are the answer's `data=H,W,payload` records, one per
    line: the expert re-asks the same question and compares the hash.
    """
    width, height = png_size(image)
    prompt = box_prompt(box, (width, height))
    payload = {
        "model": model,
        "input": [
            {
                "type": "message",
                "role": "user",
                "content": [
                    {"type": "input_text", "text": prompt},
                    {
                        "type": "input_image",
                        "image_url": "data:image/png;base64," + base64.b64encode(image).decode(),
                    },
                ],
            }
        ],
        "metadata": {"include_confidence": "false", "mask_encoding": "one_bit"},
    }
    answer = post_json("/responses", payload, transport)
    text = answer_text(answer)
    records = [{"x": int(x), "y": int(y), "data": data} for x, y, data in MASK_RECORD.findall(text)]
    if not records:
        raise ModelApiError(f"SAM answered no mask for the box: {text[:400]!r}")
    return {
        "model": model,
        "prompt": prompt,
        "request": payload,
        "answer": answer,
        "masks": records,
        "mask_sha256": mask_sha256(records),
        "size": (width, height),
        "box": [int(v) for v in box],
    }


def mask_sha256(records) -> str:
    """The hash of the mask bytes: records in answer order, one per line."""
    return sha256_hex("\n".join(record["data"] for record in records))


def image_bytes(path) -> bytes:
    """The picture as bytes."""
    with open(path, "rb") as handle:
        return handle.read()
