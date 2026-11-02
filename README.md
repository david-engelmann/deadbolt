# deadbolt

Secrets brokering for agents, where tools get scoped, expiring capability tokens instead of your real API keys ever touching the agent process.

## What this is

Every agent user quietly fears the moment a long-lived key lands in a transcript, a log, or a compromised tool call, and identity proposals that need a standards body's permission do nothing about the credentials today. Deadbolt brokers secrets on the developer's own machine, which needs no one's permission. An agent asks for a key and receives a short-lived token scoped to one resource, read one bucket for sixty seconds, and the real key never appears in the process, the transcript, or on screen. When an agent is cut off, its outstanding tokens die with it. The boundary with its sibling is one sentence. Portcullis guards the calls, deadbolt guards the credentials the calls ask for.

## Status

The remote seed was verified on 2026-11-02 against the staged seed and its commit is 08a05b881350c6ca5eb8a42af28d25f194c6d039, a parentless commit holding exactly README.md and LICENSE and .gitignore. Setup arrives through a pull request and no work lands on main directly.

The contract lives in CONTRACT.md. Setup obligations S1 to S5 are the contract state until the full contract lands as the first build act of this repo, and this setup slice claims no feature behaviour for deadbolt.

Closed perfection rounds are 0 of 100. A round counts only when a full cycle of work and audit and review and red team and approval has closed, and seeding and setup are not rounds.

The local gate is python -m pytest -q plus python scripts/codepoint_scan.py, run on the exact final head before any push, with the continuous integration workflow running the same commands as a backstop.

## Licence

MIT. See LICENSE.
