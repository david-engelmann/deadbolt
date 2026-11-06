# deadbolt

Secrets brokering for agents, where tools get scoped, expiring capability tokens instead of your real API keys ever touching the agent process.

## What this is

Every agent user quietly fears the moment a long-lived key lands in a transcript, a log, or a compromised tool call, and identity proposals that need a standards body's permission do nothing about the credentials today. Deadbolt brokers secrets on the developer's own machine, which needs no one's permission. An agent asks for a key and receives a short-lived token scoped to one resource, read one bucket for sixty seconds, and the real key never appears in the process, the transcript, or on screen. When an agent is cut off, its outstanding tokens die with it. The boundary with its sibling is one sentence. Portcullis guards the calls, deadbolt guards the credentials the calls ask for.

## The broker

Deadbolt is a Rust library crate with a thin command line binary over one local state file. An operator enrolls a credential with the scopes it may be granted for, taking the value from a file and never from an argument. A caller asks for a grant against one enrolled scope and a time to live of at most a day and receives a capability token, and the state keeps only the hash of that token. Redeem presents the token and the scope and returns the real value alone when the grant stands live and unrevoked and unexpired for exactly that scope, and each refusal names its reason. Revoke ends one grant, cutoff ends every grant a run carries, and the audit trail records every act in order while never carrying a value or a token or a token hash. The state file is owner only and the broker refuses to operate on it when its mode grants anyone else access. The full obligations stand in CONTRACT.md as DK-1 to DK-24.

## Status

The remote seed was verified on 2026-11-02 against the staged seed and its commit is 08a05b881350c6ca5eb8a42af28d25f194c6d039, a parentless commit holding exactly README.md and LICENSE and .gitignore. Setup arrives through a pull request and no work lands on main directly.

The contract lives in CONTRACT.md. The full contract landed as the first build act of this repo in Round 1 slice 1, with obligations DK-1 to DK-14 over the setup obligations S1 to S5, and that slice built the broker core described above. One amendment stands in S2, which names the Rust gate in place of the setup gate under the program language ruling of 2026-11-02.

Closed perfection rounds are 1 of 100. A round counts only when a full cycle of work and audit and review and red team and approval has closed, and seeding and setup are not rounds.

The local gate is cargo test plus the codepoint scan run through cargo, run on the exact final head before any push, with the continuous integration workflow running the same commands as a backstop.

## Licence

MIT. See LICENSE.
