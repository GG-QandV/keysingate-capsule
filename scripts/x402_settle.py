#!/usr/bin/env python3
"""The issuer's side of one live x402 payment (Base Sepolia only).

    x402_settle.py 402.json header.txt [--facilitator URL] [--dry]

402.json  -- the till's 402 answer (`till required ...`), its first `accepts`
             entry is the payment requirements;
header.txt -- the payer's X-PAYMENT header (`ksg-smoke < 402.json`).

Asks the facilitator `/verify`, then `/settle`; the facilitator submits the
EIP-3009 transfer and pays the gas. Prints the facilitator's answers. The
transaction hash and the addresses go to the owner's local registry, never
to GitHub or the PR bus.

Refuses any network but base-sepolia: this script is for the stand.
"""
import base64
import json
import sys
import urllib.error
import urllib.request

DEFAULT_FACILITATOR = "https://x402.org/facilitator"
# Cloudflare in front of the facilitator answers 403 / error 1010 to urllib's
# default "Python-urllib/3.x" signature; a named client passes.
HEADERS = {
    "content-type": "application/json",
    "accept": "application/json",
    "user-agent": "ksg-x402-settle/0.1 (+https://github.com/keysingate/keysingate-core)",
}
NETWORK = "base-sepolia"


def post(url, body):
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers=HEADERS,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            # Cloudflare pages are HTML: keep only the error code line.
            text = raw.decode(errors="replace")
            code_line = next((l.strip() for l in text.splitlines() if "error code" in l.lower()), "")
            return e.code, {"raw": code_line or text[:300]}


def main(argv):
    facilitator, dry, args = DEFAULT_FACILITATOR, False, []
    it = iter(argv)
    for a in it:
        if a == "--facilitator":
            facilitator = next(it, "")
        elif a == "--dry":
            dry = True
        else:
            args.append(a)
    if len(args) != 2 or not facilitator:
        print(__doc__, file=sys.stderr)
        return 2

    with open(args[0], encoding="utf-8") as f:
        answer = json.load(f)
    with open(args[1], encoding="utf-8") as f:
        header = f.read().strip()

    requirements = answer["accepts"][0]
    payload = json.loads(base64.b64decode(header))
    for name, got in (("requirements", requirements["network"]), ("payment", payload["network"])):
        if got != NETWORK:
            print(f"REFUSED: {name} network is {got!r}, this script pays only on {NETWORK}")
            return 1

    body = {
        "x402Version": payload.get("x402Version", 1),
        "paymentPayload": payload,
        "paymentRequirements": requirements,
    }
    code, verdict = post(facilitator.rstrip("/") + "/verify", body)
    print(f"verify: HTTP {code} {json.dumps(verdict)}")
    if code != 200 or not verdict.get("isValid"):
        print("NOT SETTLED: the facilitator did not verify the payment")
        return 1
    if dry:
        print("DRY: verified, not settled")
        return 0
    code, settled = post(facilitator.rstrip("/") + "/settle", body)
    print(f"settle: HTTP {code} {json.dumps(settled)}")
    if code != 200 or not settled.get("success"):
        print("NOT SETTLED")
        return 1
    print("SETTLED")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
