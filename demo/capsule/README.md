# A demo capsule you can open yourself

This folder holds **one real capsule** and the secret files of both its parties, so you can open it, write a page, take the page out and check it — on your machine, without us.

> **Demo only — the keys here are public on purpose.** These side files belong to a throw-away demo container. In a real deployment each party keeps its side file to itself, and without it the capsule cannot be opened. Nothing here protects anything.

| File | What it is |
|---|---|
| `capsule.bin` | the capsule: one file of exactly 6 291 456 bytes (6 MiB) that reads as random noise; the container's code, state and the parties' sealed parts are mixed inside it |
| `client.side` | the client agent's secret file: its map (the key to its slot in the capsule) and its half of the signing key |
| `owner.side` | the owner's secret file: its own map and signing key |
| `keys.json` | the public keys a verifier checks the pages with |
| `page-1.json`, `page-2.json` | two pages already exported from this capsule |

## 1. Build (once, from the repository root)
```bash
cargo build --release -p ksg-capsule-reader -p ksg-verify-v2
cargo build --release -p ksg-capsule-module --target wasm32-unknown-unknown
```
(`rustup target add wasm32-unknown-unknown` first if the target is missing.)

## 2. Work on a copy
Every command rewrites the capsule, so work on a copy and keep this folder as it is:
```bash
cp -r demo/capsule /tmp/my-capsule
C=target/release/ksg-capsule; V=target/release/ksg-verify-v2; H=/tmp/my-capsule
```

## 3. Look at it
```bash
stat -c%s $H/capsule.bin          # 6291456
od -An -tx1 -N32 $H/capsule.bin    # noise: no header, no format marker
$C --home $H status               # the container as the capsule reports it
```

## 4. Write a page as the client agent
```bash
$C --home $H work "my first page in this capsule"
stat -c%s $H/capsule.bin          # still 6291456
```

## 5. Take the page out and check it, offline
```bash
ID=$($C --home $H status | python3 -c "import json,sys;print(json.load(sys.stdin)['id'])")
N=$($C --home $H status | python3 -c "import json,sys;print(json.load(sys.stdin)['pages']-1)")
$C --home $H export-page $N --out $H/mine.json
$C --home $H keys --out $H/keys.json
$V --export $H/mine.json --container "$ID" --class light --keys $H/keys.json    # ACCEPTED …
```
The pages already here check the same way: `$V --export demo/capsule/page-1.json --container "$ID" --class light --keys demo/capsule/keys.json`.

## 6. Change one byte, see it refused
The page's text is stored base64-encoded inside the export; flip one bit of it. The path below fits a page written by
`work` (step 5); other pages, such as page 1 (the opening), have another shape:
```bash
python3 - "$H/mine.json" <<'PY'
import base64, json, sys
p = sys.argv[1]; d = json.load(open(p))
c = d["page"]["body"]["content"]["content"]
raw = base64.urlsafe_b64decode(c["inline"] + "=" * (-len(c["inline"]) % 4))
c["inline"] = base64.urlsafe_b64encode(bytes([raw[0] ^ 1]) + raw[1:]).decode().rstrip("=")
json.dump(d, open(p, "w"))
PY
$V --export $H/mine.json --container "$ID" --class light --keys $H/keys.json    # REJECTED …
```

## What this shows — and what it does not
- The capsule is one constant-size file, noise to anyone without a side file; a side file opens its party's slot only.
- The client writes and exports pages through the capsule; a verifier checks each page with public keys only, offline.
- This capsule is `light` and has **no anchors** in a public chain, so the time of a page is not proven here. Anchored runs: claims 17, 26, 31 in [`../CLAIMS.md`](../CLAIMS.md) (claim 31 — the Pro demo part anchored on Solana mainnet-beta).
