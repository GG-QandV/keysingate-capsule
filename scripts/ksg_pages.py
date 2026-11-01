#!/usr/bin/env python3
"""Journal pages as a format: the text inside an export, its fields, its citations.

The demo's tools write one field per line (`tool call: ...`, `model: ...`,
`mask sha256: ...`), so a page reads like a note to a person and still parses.
Nothing here touches the network or the capsule: an exported page is JSON with
its content inline, base64url, unpadded.
"""
import base64
import re

#: `[p:N]` — how an explanation points at a journal page.
CITATION = re.compile(r"\[p:(\d+)\]")


def find_inline(value):
    """The first `inline` string anywhere in an export (`page.body.content.content.inline`)."""
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


def exported_text(data) -> str:
    """The text of an exported page (single page or a one-element list), decoded."""
    if isinstance(data, list):
        if not data:
            raise ValueError("the export is empty")
        data = data[0]
    inline = find_inline(data)
    if inline is None:
        raise ValueError("the export carries no inline content")
    padded = inline + "=" * (-len(inline) % 4)
    return base64.urlsafe_b64decode(padded).decode(errors="replace")


def page_fields(text: str) -> dict:
    """`key: value` lines of a page → a dict; the first `: ` splits, the rest is the value."""
    fields = {}
    for line in text.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            fields[key.strip()] = value.strip()
    return fields


def citations(text: str) -> list:
    """The page numbers an explanation points at, in order, without duplicates."""
    seen = []
    for number in CITATION.findall(text or ""):
        if int(number) not in seen:
            seen.append(int(number))
    return seen
