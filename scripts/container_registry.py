#!/usr/bin/env python3
"""Registry of software functions inside the container and which tests covered them.

Inside the container there are two crates: `ksg-container` (buttons, loop, layers,
client key) and `ksg-journal` (operation log). For each of their functions the registry
records whether tests executed it and which ones:

  * unit and integration tests — everything except the stand;
  * e2e — stand scenarios (`tests/e2e_stand.rs`): the whole container life through buttons;
  * smoke — `tests/smoke_stand.rs`.

"Executed" is a coverage fact (`cargo llvm-cov`), not a static-graph fact:
in Rust the call graph does not resolve method calls through the receiver, and
GitNexus sees only some of the functions from tests. GitNexus is used for the inventory:
the registry compares the coverage function list against the index symbol list and names
the mismatches.

Result: `[doc:CONTAINER-FUNCTIONS]` (generated, do not edit by hand) and
`[doc:CONTAINER-FUNCTIONS-JSON]`; the output directory is set by `KSG_DOCS_DIR`.

Requires: `cargo-llvm-cov`, the `llvm-tools-preview` component, `rustfilt`.
Run from this directory root (core v2): `python3 scripts/container_registry.py`.
Exit code 1 — if a test failed or some button operation did not pass on the stand.
"""

import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMPL = ROOT
# Since 01.10 core v2: the journal moved into the core (`ksg-core-v2`).
CRATES = ('ksg-container-v2', 'ksg-core-v2')
# The registry is a private document, it lives outside this directory: `[doc:CONTAINER-FUNCTIONS]`
# and `[doc:CONTAINER-FUNCTIONS-JSON]`. The output directory is KSG_DOCS_DIR.
REPO = ROOT.parent
DOCS = Path(os.environ.get('KSG_DOCS_DIR', REPO / 'internal'))
OUT_MD = DOCS / 'Reestr_funktsiy_konteynera.md'
OUT_JSON = DOCS / 'reestr_funktsiy_konteynera.json'

# Modules the button press goes through: loop §3.3 and everything it calls
# in steps 1–9. Functions of these modules are marked separately in the registry.
BUTTON_PATH = {
    'ksg-container/src/command.rs', 'ksg-container/src/event.rs',
    'ksg-container/src/operation.rs', 'ksg-container/src/container.rs',
    'ksg-container/src/unload_gate.rs', 'ksg-container/src/client_key.rs',
    'ksg-container/src/timecheck.rs', 'ksg-container/src/followup.rs',
    'ksg-container/src/order.rs', 'ksg-container/src/artifact.rs',
    'ksg-container/src/dispute.rs', 'ksg-container/src/seal.rs',
}

# Branches no test can trigger, with the reason. Not a gap, but a boundary: the registry
# prints them separately. Key — (file, function name as in coverage).
UNREACHABLE = {
    # --- core v2 (since 01.10): ksg-container-v2 -----------------------------
    ('ksg-container-v2/src/noise.rs', 'ksg_container_v2::noise::pad::{closure#0}'):
        'content length over u32::MAX (4 GiB) — the layout size is set at print time and is smaller',
    ('ksg-container-v2/src/client_key.rs', 'answer::{closure#0}'):
        'FROST dkg::part2 returns a round-two packet for each round-one packet; '
        'there is a single round-one packet — from the mobile side, and its packet always exists',
    ('ksg-container-v2/src/client_key.rs', 'finish::{closure#1}'):
        '`begin` binds the client commitment to the only group signer when there is no second one, '
        'and FROST round2::sign rejects earlier: the commitment is not its own. Test '
        '`registry_gaps.rs::a_stored_half_rewritten_to_sign_alone_signs_nothing`',
    ('ksg-container-v2/src/client_key.rs', 'client_public::{closure#0}'):
        'an Ed25519 FROST key serializes to exactly 32 bytes',
    ('ksg-container-v2/src/client_key.rs', 'share_public::{closure#0}'):
        'an Ed25519 FROST verification share serializes to exactly 32 bytes',
    ('ksg-container-v2/src/client_key.rs', 'sign_alone::{closure#0}'):
        'a FROST secret share serializes to exactly 32 bytes',
    ('ksg-container-v2/src/client_key.rs', 'sign_alone::{closure#1}'):
        'a secret share is a canonical scalar: FROST does not read a non-canonical one on deserialization',
    ('ksg-container-v2/src/client_key.rs', 'from_bytes::{closure#1}'):
        'a slice from get(..4) into [u8; 4] — the length is already 4, the conversion cannot fail',
    ('ksg-container-v2/src/client_key.rs', 'from_bytes::{closure#2}'):
        'u32 into usize — cannot fail on 32-bit and wider platforms, and the reference has no others',
    ('ksg-container-v2/src/container.rs', 'to_state::{closure#0}'):
        'FROST element serialization fails only on the neutral group point; FROST does not '
        'deserialize it, and a generator-derived key hits it with probability ≈2^-252',
    ('ksg-container-v2/src/container.rs', 'to_state::{closure#1}'):
        'same for the previous client half: the neutral point is neither read nor born',
    ('ksg-container-v2/src/store.rs', 'seal_to_bytes::{closure#0}'):
        'serde_json::to_vec of a state with string keys cannot fail',
    ('ksg-container-v2/src/store.rs', 'stored_len::{closure#0}'):
        'serde_json::to_vec of a state with string keys cannot fail',
    ('ksg-container-v2/src/store.rs', 'stored_packed_len::{closure#0}'):
        'serde_json::to_vec of a state with string keys cannot fail',
    ('ksg-container-v2/src/store.rs', 'seal_to_bytes::{closure#2}'):
        'serde_json::to_vec of a signature (three string fields) cannot fail',
    ('ksg-container-v2/src/store.rs', 'seal_to_bytes::{closure#3}'):
        'an ML-DSA-65 signature in JSON is about 4.5 KiB, below u32::MAX',
    # --- core v2: ksg-core-v2 -------------------------------------------------
    ('ksg-core-v2/src/crypto/sign.rs', 'ksg_core_v2::crypto::sign::verify_one::{closure#7}'):
        'any 1952 bytes read as an ML-DSA-65 key: t1 coefficients are 10 bits each, '
        'all values in range (fips204 pk_decode)',
    ('ksg-core-v2/src/doc/mod.rs', 'from_unix_ms::{closure#0}'):
        'u64::MAX / 86_400_000 is below i64::MAX',
    ('ksg-core-v2/src/doc/mod.rs', 'millis_of::{closure#3}'):
        'the year is checked above to be no earlier than 1970, the day count since the epoch is not negative',
    ('ksg-core-v2/src/journal/mod.rs', 'draft::{closure#0}'):
        'over 2^32 pages in one record: `place` rejects past zone capacity (1102 pages)',
    ('ksg-core-v2/src/journal/mod.rs', 'draft::{closure#1}'):
        'over 2^32 pages in one record — over 128 GiB of bodies in memory; zones hold 1102',
    ('ksg-core-v2/src/journal/mod.rs', 'draft_record::{closure#1}'):
        'over 2^32 parts in a record: `draft_pages_only` hits zone capacity earlier',
    ('ksg-core-v2/src/journal/mod.rs', 'draft_pages_only::{closure#0}'):
        'over 2^32 pages in one record: `place` rejects past zone capacity (1102 pages)',
    ('ksg-core-v2/src/journal/mod.rs', 'draft_pages_only::{closure#1}'):
        'over 2^32 parts in one record — over 128 GiB of parts in memory',
    ('ksg-core-v2/src/journal/mod.rs', 'export_one::{closure#0}'):
        'u64 into usize fails only on a 32-bit target past 2^32, and there is no journal with such a page there',
    ('ksg-core-v2/src/journal/mod.rs', 'export_one::{closure#1}'):
        'the page was found among the journal pages, and the chain has a leaf per page: '
        'the inclusion proof builds',
    ('ksg-core-v2/src/journal/mod.rs', 'export_pages::{closure#0}'):
        'u64 into usize fails only on a 32-bit target past 2^32, and there is no journal with such a page there',
    ('ksg-core-v2/src/journal/mod.rs', 'export_pages::{closure#1}'):
        'the page was found among the journal pages, and the chain has a leaf per page',
    ('ksg-core-v2/src/journal/mod.rs', 'expert_pages::{closure#0}::{closure#0}'):
        'u64 into usize fails only on a 32-bit target past 2^32, and there is no journal with such a page there',
    ('ksg-core-v2/src/journal/mod.rs', 'expert_pages::{closure#0}::{closure#1}'):
        'the page was found among the journal pages, and the chain has a leaf per page',
    ('ksg-core-v2/src/merkle/inclusion.rs',
     'ksg_core_v2::merkle::inclusion::inclusion_proof::{closure#0}'):
        'u64 into usize fails only on a 32-bit target past 2^32 leaves, which cannot fit there',
}


def run(cmd, env=None, check=False):
    r = subprocess.run(cmd, cwd=IMPL, capture_output=True, text=True, env=env)
    if check and r.returncode != 0:
        sys.stderr.write(r.stdout[-4000:] + r.stderr[-4000:])
        sys.exit(f'command failed: {" ".join(cmd)}')
    return r


def coverage(label, test_args, extra_env=None):
    """One coverage test run. Returns (test summary, functions)."""
    pkgs = [a for c in CRATES for a in ('-p', c)]
    env = dict(os.environ, **(extra_env or {}))
    run(['cargo', 'llvm-cov', 'clean', '--workspace'])
    r = run(['cargo', 'llvm-cov', '--no-report', *pkgs, *test_args], env=env)
    passed = sum(int(m) for m in re.findall(r'test result: \w+\. (\d+) passed', r.stdout))
    failed = sum(int(m) for m in re.findall(r'(\d+) failed', r.stdout))
    ok = r.returncode == 0
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        path = f.name
    run(['cargo', 'llvm-cov', 'report', '--json', *pkgs, '--output-path', path], check=True)
    data = json.load(open(path))['data'][0]['functions']
    os.unlink(path)
    return {'label': label, 'ok': ok, 'passed': passed, 'failed': failed}, data


def demangle(names):
    try:
        r = subprocess.run(['rustfilt'], input='\n'.join(names), capture_output=True, text=True)
        out = r.stdout.splitlines()
        if len(out) == len(names):
            return out
    except FileNotFoundError:
        pass
    return names


def normalize(name):
    """Function name without hash and generic parameters — one for all instantiations."""
    name = name.split('::h')[0] if re.search(r'::h[0-9a-f]{16}$', name) else name
    prev = None
    while prev != name:
        prev = name
        name = re.sub(r'<[^<>]*>', '', name)
    return name.replace('::::', '::').strip(':')


def functions(raw):
    """{(file, name): (line, counter)} only for functions inside the container."""
    picked = [f for f in raw if any(f'{c}/src/' in f['filenames'][0] for c in CRATES)]
    names = demangle([f['name'] for f in picked])
    out = {}
    for f, n in zip(picked, names):
        rel = f['filenames'][0].split('crates/', 1)[1]
        key = (rel, normalize(n))
        line = f['regions'][0][0] if f['regions'] else 0
        prev = out.get(key)
        count = f['count'] + (prev[1] if prev else 0)
        out[key] = (min(line, prev[0]) if prev else line, count)
    return out


def gitnexus_inventory():
    """Functions in the GitNexus index for the container crates, if the index exists."""
    runner = REPO / '.gitnexus' / 'run.cjs'
    if not runner.exists():
        return None
    q = ("MATCH (f:Function) WHERE f.filePath CONTAINS 'ksg-container/src' "
         "OR f.filePath CONTAINS 'ksg-journal/src' RETURN f.name, f.filePath, f.startLine")
    r = subprocess.run(['node', str(runner), 'cypher', q, '--repo', '.'],
                       cwd=REPO, capture_output=True, text=True)
    try:
        md = json.loads(r.stdout[r.stdout.index('{'):])['markdown']
    except (ValueError, KeyError):
        return None
    rows = [l.split('|')[1:-1] for l in md.splitlines()[2:]]
    return {(c[1].strip().split('crates/', 1)[-1], c[0].strip()) for c in rows if len(c) >= 2}


def operations():
    """Button operations: name → button, from the `Operation::button` table."""
    src = (IMPL / 'crates/ksg-container-v2/src/operation.rs').read_text()
    body = src[src.index('pub const fn button'):]
    body = body[:body.index('\n    }\n')]
    out = {}
    for m in re.finditer(r'((?:\s*\|?\s*Self::\w+)+)\s*=>\s*Button::(\w+)', body):
        for op in re.findall(r'Self::(\w+)', m.group(1)):
            out[op] = m.group(2)
    return out


def main():
    date = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    sha = subprocess.run(['git', 'rev-parse', '--short', 'HEAD'], cwd=ROOT,
                         capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(['git', 'status', '--porcelain', '--', '.'], cwd=ROOT,
                           capture_output=True, text=True).stdout.strip()
    version = sha + (' + uncommitted changes' if dirty else '')

    report = Path(tempfile.gettempdir()) / 'ksg_stand_pressed.txt'
    if report.exists():
        report.unlink()
    unit_run, unit_raw = coverage('unit and integration', ['--', '--skip', 'e2e_', '--skip', 'smoke_'])
    e2e_run, e2e_raw = coverage('e2e (stand)', ['--test', 'e2e_stand'],
                                {'KSG_STAND_REPORT': str(report)})
    smoke_run, smoke_raw = coverage('smoke (stand)', ['--test', 'smoke_stand'])
    all_run, all_raw = coverage('all', [])

    unit, e2e, smoke, every = (functions(x) for x in (unit_raw, e2e_raw, smoke_raw, all_raw))
    pressed = set(re.findall(r'"(\w+)"', report.read_text())) if report.exists() else set()
    ops = operations()

    rows = []
    for (rel, name), (line, count) in sorted(every.items(), key=lambda kv: (kv[0][0], kv[1][0])):
        rows.append({
            'function': name, 'file': rel, 'line': line,
            'button_path': rel in BUTTON_PATH,
            'unit': unit.get((rel, name), (0, 0))[1],
            'e2e': e2e.get((rel, name), (0, 0))[1],
            'smoke': smoke.get((rel, name), (0, 0))[1],
        })
    zero = [r for r in rows if r['unit'] == 0 and r['e2e'] == 0 and r['smoke'] == 0]
    never = [r for r in zero if (r['file'], r['function']) not in UNREACHABLE]
    bounded = [r for r in zero if (r['file'], r['function']) in UNREACHABLE]

    gn = gitnexus_inventory()
    gn_note = ''
    if gn is not None:
        cov_short = {(r['file'], r['function'].split('::')[-1]) for r in rows}
        only_gn = sorted(k for k in gn if k not in cov_short)
        gn_note = (f'GitNexus: {len(gn)} function symbols in the same files; '
                   f'missing from coverage: {len(only_gn)} (usually `const fn` inlined '
                   f'by the compiler, and test-module functions `#[cfg(test)]`).')

    ops_rows = [{'operation': op, 'button': b, 'e2e': op in pressed or op == 'PrintRelease'}
                for op, b in ops.items()]
    ops_missing = [o['operation'] for o in ops_rows if not o['e2e']]

    runs = [unit_run, e2e_run, smoke_run, all_run]
    doc = {'date': date, 'version': version, 'runs': runs, 'operations': ops_rows,
           'functions': rows,
           'never_executed': [f"{r['file']}:{r['line']} {r['function']}" for r in never],
           'unreachable': [f"{r['file']}:{r['line']} {r['function']}" for r in bounded]}
    OUT_JSON.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + '\n')

    L = []
    L.append('# Registry of software functions inside the container\n')
    L.append('**Generated** by `scripts/container_registry.py`. Do not edit by hand.\n')
    L.append(f'**Run:** {date} · **version:** `{version}`\n')
    L.append('"Executed" is a coverage fact (`cargo llvm-cov`): the function ran '
             'at least once in this test-set run. The number is the execution counter.\n')
    L.append('## 1. Runs\n')
    L.append('| Set | Result | Passed | Failed |')
    L.append('|---|---|---|---|')
    for r in runs:
        L.append(f"| {r['label']} | {'green' if r['ok'] else '**red**'} | {r['passed']} | {r['failed']} |")
    L.append('')
    L.append('## 2. Button operations on the stand (e2e)\n')
    L.append('`PrintRelease` — record 0 of the status section, lands at build time, before the buttons.\n')
    L.append('| Operation | Button | Went through the button on the stand |')
    L.append('|---|---|---|')
    names = {'Issuer': 'D-1 of issuer', 'Signatures': 'D-2 of signatures', 'Export': 'D-3 of export'}
    for o in ops_rows:
        L.append(f"| `{o['operation']}` | {names.get(o['button'], o['button'])} | {'yes' if o['e2e'] else '**no**'} |")
    L.append('')
    L.append(f'## 3. Functions — {len(rows)}; gaps — {len(never)}, '
             f'unreachable by design — {len(bounded)}\n')
    if gn_note:
        L.append(gn_note + '\n')
    L.append('"Buttons" — a function in a module the press goes through (loop §3.3).\n')
    L.append('| # | Function | File:line | Buttons | Unit | e2e | Smoke |')
    L.append('|---|---|---|---|---|---|---|')
    for i, r in enumerate(rows, 1):
        mark = lambda n: str(n) if n else '**0**'
        L.append(f"| {i} | `{r['function']}` | `{r['file']}:{r['line']}` | "
                 f"{'yes' if r['button_path'] else ''} | {mark(r['unit'])} | {r['e2e'] or 0} | {r['smoke'] or 0} |")
    L.append('')
    L.append('## 4. Never executed — gaps\n')
    if never:
        for r in never:
            L.append(f"- `{r['file']}:{r['line']}` `{r['function']}`")
    else:
        L.append('None.')
    L.append('')
    if bounded:
        L.append('## 5. Not triggered by tests by design — boundaries\n')
        for r in bounded:
            L.append(f"- `{r['file']}:{r['line']}` `{r['function']}` — "
                     f"{UNREACHABLE[(r['file'], r['function'])]}")
        L.append('')
    L.append('## 6. Worker procedure\n')
    L.append('1. `python scripts/container_registry.py` — the runs and this file.')
    L.append('2. Section 4 is not empty — one test per function, named after what it '
             'holds; scenario ones — on the stand (`tests/stand/`), pinpoint ones — in '
             '`tests/registry_gaps.rs`.')
    L.append('3. Section 2 contains "no" — a stand scenario bringing the operation to the button.')
    L.append('4. A function cannot be triggered by a test — the reason goes into script `UNREACHABLE`, no silence.')
    L.append('5. Repeat item 1, commit the registry together with the tests.')
    L.append('')
    OUT_MD.write_text('\n'.join(L))

    print(f'{OUT_MD.relative_to(ROOT)}: functions {len(rows)}, never executed {len(never)}, '
          f'operations without e2e {len(ops_missing)}')
    for r in runs:
        print(f"  {r['label']}: {'ok' if r['ok'] else 'FAILED'} {r['passed']} passed, {r['failed']} failed")
    if not all(r['ok'] for r in runs) or ops_missing or never:
        if never:
            print('  gaps:', ', '.join(f"{r['file']}:{r['line']}" for r in never), file=sys.stderr)
        if ops_missing:
            print('  operations without e2e:', ', '.join(ops_missing), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
