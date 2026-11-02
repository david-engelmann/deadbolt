# deadbolt

Secrets brokering for agents, where tools get scoped, expiring capability tokens instead of your real API keys ever touching the agent process.

## What this is

Every agent user quietly fears the moment a long-lived key lands in a transcript, a log, or a compromised tool call, and identity proposals that need a standards body's permission do nothing about the credentials today. Deadbolt brokers secrets on the developer's own machine, which needs no one's permission. An agent asks for a key and receives a short-lived token scoped to one resource, read one bucket for sixty seconds, and the real key never appears in the process, the transcript, or on screen. When an agent is cut off, its outstanding tokens die with it. The boundary with its sibling is one sentence. Portcullis guards the calls, deadbolt guards the credentials the calls ask for.

## Status

Seeded in October 2026. The build has not started. Part of the impatient programming portfolio, in the Fleet Operations arc.

## Licence

MIT. See LICENSE.
