# What the demo does not cover yet — and what comes next

The hackathon demo runs on the **test stand**: some keys that the product keeps away from the issuer are, on the stand, generated and stored next to the container so that the whole chain can run on one machine. Everything below is designed and decided; it is scheduled right after the demo so that the demo itself is not put at risk by changes to the container core.

| # | Area | In the demo (test stand) | Next |
|---|---|---|---|
| 1 | Owner's key | A single signing seed prepared by the stand | Same scheme as the client's key: the issuer plants only a seed in the container template; at initiation the key grows inside the container together with the recipient's own randomness (FROST 2-of-2); one half is cut off, encrypted and handed to the owner — or to an orchestrator acting for the owner |
| 2 | Client agent's key half | Held by the stand process | Handed to the agent's own signer process, encrypted at rest; a phone is only an option for a human owner |
| 3 | Capsule mixing map | Derived from a stand key the printer knows | Grows at initiation from the printer's seed plus the recipient's randomness, so the printer's knowledge no longer opens anything written after initiation |
| 4 | Secrets folder | Plain files with strict permissions on the stand | Every Keysingate file in the folder is encrypted; the folder key lives elsewhere and is handed only to the signer process at start-up — identical on servers and on Linux, macOS and Windows; the model never sees key material |
| 5 | Journal-write guarantee | The agent is instructed to write a page for every step, and model calls and SAM masks write their pages automatically | Every agent tool writes its page before returning; an optional watcher compares the agent's reports with the container's export and alerts the owner or orchestrator on any gap |
| 6 | Owner's approvals | — | The owner (or orchestrator) approves only global actions (initiation, transfer, declaring a key lost); writing and sealing pages is the agent's routine work and needs no human |
| 7 | Remote signer | Local only | A network channel for agents that live in short-lived environments and for orchestrators that keep their agents' signers |
| 8 | Anchored (Pro) run time | ~400 s on a local Solana node with a 120 s anchor wait | Profile and shorten |
| 9 | Code comments | Partly not in English | All comments and messages in English |
| 10 | Light anchors in the written standard | The code anchors `light` minimally on Base Sepolia (birth, initiation, before a value leaves, every ten records); the published IETF draft `-00` still says `light` anchors only after it switches to Pro | Draft revision `-01` with the minimal schedule |

## Known limits — stated, not hidden

| Limit | What it means |
|---|---|
| One payer per container (Pro, Solana) | Anchor memos are blind — they reveal nothing of the content — but the payer's transaction history groups one container's anchors for anyone who knows the payer's address. A payer per container is the holder's choice |
| A copy is seen at the next anchor, not instantly | Base (`light`): within the ten offline records two copies can each write; the second learns it is a copy when its next anchor is refused — before any export or transfer of rights. Solana (Pro): a rolled-back file is caught when a later copy anchored through the same payer |
| `bare` may be copied | By design: a `bare` journal is never anchored and is meant to be copied; its identifier only labels whose it is |
| Tests with real-time waits | A few end-to-end tests wait on the clock (a standing that must expire, an anchor that must land); their deadlines are generous, so a slow machine makes them slower, not red |
