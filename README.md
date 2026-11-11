# deadbolt

A secrets broker for agents, where a credential is enrolled once and tools redeem scoped, expiring capability tokens so the real key never touches the agent process, with the store encrypted on disk under a key the operating system keychain holds and a passphrase route as the fallback.

Deadbolt is one local binary backed by a Rust library, working over one state file. An operator enrolls a credential once, naming the scopes it may be granted for and taking the value from a file, never from an argument. A tool then asks for a grant against one enrolled scope and receives a capability token, and the state keeps only the hash of that token. Redeem presents the token and returns the real value only while the grant stands live for exactly the scope it names, and every refusal names its reason. The state document sits inside an encrypted envelope on disk, sealed under a key the operating system keychain holds, or under a key derived from a passphrase on a machine where no keychain service answers. Portcullis guards the calls, deadbolt guards the credentials the calls ask for.

[![CI](https://github.com/david-engelmann/deadbolt/actions/workflows/ci.yml/badge.svg)](https://github.com/david-engelmann/deadbolt/actions/workflows/ci.yml)

```
{"enrolled":"api-key"}
{"expires_at":1794116244,"grant_id":"dac0b16c68979b2bf68b0b283baa7b7e","token":"5aea44dddf7a58eed31a1c0b37b0cf80e9c6ab66179bb4434214fec76784bc1a"}
SYNTHETIC-TEST-VALUE-api-key
```

## Install

Install from a clean checkout with Cargo. The checkout ships two binaries, and the install names the deadbolt binary on its own because a shared scanner binary of the same name from a sibling repo blocks a plain install of every binary at once.

On Linux the build also needs the libdbus-1 development package, libdbus-1-dev, and pkg-config, the two the workflow installs before its gate.

```
git clone https://github.com/david-engelmann/deadbolt.git
cd deadbolt
cargo install --path . --bin deadbolt
```

## Quickstart

The smallest complete run creates a store on the passphrase route, enrolls one credential, grants a token against one scope, and redeems it. The passphrase travels in an environment variable and never in an argument, and the credential value travels in a file and never in an argument. The values below are synthetic test values, and the store they make is thrown away with the directory.

```
export DEADBOLT_PASSPHRASE='SYNTHETIC-TEST-VALUE-passphrase'
echo 'SYNTHETIC-TEST-VALUE-api-key' > api-key.txt
deadbolt --state quickstart.json --route passphrase enroll --name api-key --value-file api-key.txt --scope bucket:read
```

```
{"enrolled":"api-key"}
```

The route is named once, on the act that creates the store. Later acts against the standing store name no route, and naming one beside a store that already stands is refused.

```
deadbolt --state quickstart.json grant --credential api-key --scope bucket:read --ttl 300
```

```
{"expires_at":1794116244,"grant_id":"dac0b16c68979b2bf68b0b283baa7b7e","token":"5aea44dddf7a58eed31a1c0b37b0cf80e9c6ab66179bb4434214fec76784bc1a"}
```

The token prints once, in the grant receipt, and the redeem below carries the token from the receipt above it. Every grant mints a fresh token, so a run of your own prints a different one, and its redeem carries the one its grant printed. Nothing else in deadbolt ever prints it, and the state stores only its hash.

```
deadbolt --state quickstart.json redeem --token 5aea44dddf7a58eed31a1c0b37b0cf80e9c6ab66179bb4434214fec76784bc1a --scope bucket:read
```

```
SYNTHETIC-TEST-VALUE-api-key
```

## Usage

### Enroll and grant

Every command names the state file first. Enrollment names at least one scope, and a grant may ask only for a scope the credential carries. A grant may also carry a run identifier, which is what a later cutoff ends.

```
deadbolt --state usage.json --route passphrase enroll --name api-key --value-file api-key.txt --scope bucket:read --scope bucket:write
deadbolt --state usage.json grant --credential api-key --scope bucket:read --ttl 600 --run demo-run
```

```
{"enrolled":"api-key"}
{"expires_at":1794116546,"grant_id":"d21c69c6d7acc16aae55a7d7d0b57627","token":"136bc0599d2f0bb079863c5640c10530f14185f786441dd04a9e69a0bc255c65"}
```

### Redeem

Redeem presents the token and one scope, and prints the value alone when the grant stands live and unexpired for exactly that scope. Each redeem in this section carries the token from the grant receipt printed above it. A time to live stands from 1 to 86400 seconds, counted from the grant.

```
deadbolt --state usage.json redeem --token 136bc0599d2f0bb079863c5640c10530f14185f786441dd04a9e69a0bc255c65 --scope bucket:read
```

```
SYNTHETIC-TEST-VALUE-api-key
```

### Refusals

A redeem against any other scope than the granted one is refused, and the refusal prints one line on standard error and exits 1. Nothing is redeemed and no value leaves the store.

```
deadbolt --state usage.json redeem --token 136bc0599d2f0bb079863c5640c10530f14185f786441dd04a9e69a0bc255c65 --scope bucket:write
```

```
error: redeem refused, scope mismatch
```

A grant whose time to live has lapsed is refused the same way. This grant stood for one second.

```
deadbolt --state usage.json grant --credential api-key --scope bucket:read --ttl 1
sleep 2
deadbolt --state usage.json redeem --token e7441d25747a4eed42e1610a50d13ae6e6646b874773587391779a46b9ad7460 --scope bucket:read
```

```
{"expires_at":1794115949,"grant_id":"474a1561a3593b94bf6245ce0c4b02b8","token":"e7441d25747a4eed42e1610a50d13ae6e6646b874773587391779a46b9ad7460"}
error: redeem refused, expired
```

### Cutoff

Cutoff ends every grant that carries one run identifier, in one act. A grant the cutoff ended refuses redemption as revoked, because the grant no longer stands.

```
deadbolt --state usage.json cutoff --run demo-run
deadbolt --state usage.json redeem --token 136bc0599d2f0bb079863c5640c10530f14185f786441dd04a9e69a0bc255c65 --scope bucket:read
```

```
{"grants_ended":1,"run_id":"demo-run"}
error: redeem refused, revoked
```

### Rotation

Rotation replaces a credential with a successor under a new name in one act, and it ends every grant that stands live against the predecessor. The run below stands on the passphrase route, the only route this box and continuous integration can run, because no platform keychain service answers on either, and the shapes it prints are the shapes both routes print. It runs on its own store named rotation.json, apart from the usage.json sequence the earlier sections share.

```
export DEADBOLT_PASSPHRASE='SYNTHETIC-TEST-VALUE-passphrase'
echo 'SYNTHETIC-TEST-VALUE-cache-key-v1' > cache-key-v1.txt
echo 'SYNTHETIC-TEST-VALUE-cache-key-v2' > cache-key-v2.txt
deadbolt --state rotation.json --route passphrase enroll --name cache-key --value-file cache-key-v1.txt --scope bucket:read --scope bucket:write
```

```
{"enrolled":"cache-key"}
```

A grant against the predecessor redeems the first value.

```
deadbolt --state rotation.json grant --credential cache-key --scope bucket:read --ttl 600 --run rotation-demo
```

```
{"expires_at":1794272744,"grant_id":"3871c1c444150157a2b658bd82ffe6a0","token":"5d2dedd46d4a4cc55a570c855631e939146509bea24c5818ef682fdaf56f6b1c"}
```

```
deadbolt --state rotation.json redeem --token 5d2dedd46d4a4cc55a570c855631e939146509bea24c5818ef682fdaf56f6b1c --scope bucket:read
```

```
SYNTHETIC-TEST-VALUE-cache-key-v1
```

The rotation names the successor and its scopes in the act, with no scope carried over from the predecessor.

```
deadbolt --state rotation.json rotate --name cache-key --new-name cache-key-2026 --value-file cache-key-v2.txt --scope bucket:read --scope bucket:write
```

```
{"grants_ended":1,"rotated":"cache-key","successor":"cache-key-2026"}
```

The grant the rotation ended answers revoked, and its token redeems never again.

```
deadbolt --state rotation.json redeem --token 5d2dedd46d4a4cc55a570c855631e939146509bea24c5818ef682fdaf56f6b1c --scope bucket:read
```

```
error: redeem refused, revoked
```

A grant against the successor redeems the second value.

```
deadbolt --state rotation.json grant --credential cache-key-2026 --scope bucket:read --ttl 600
```

```
{"expires_at":1794272809,"grant_id":"d9debb47692800a97ff2a501eac4a403","token":"2c1fe8e4aa4360c433a9feffa1758f94816cd528e61e311331eec1962ccf21eb"}
```

```
deadbolt --state rotation.json redeem --token 2c1fe8e4aa4360c433a9feffa1758f94816cd528e61e311331eec1962ccf21eb --scope bucket:read
```

```
SYNTHETIC-TEST-VALUE-cache-key-v2
```

The audit read over this store shows the rotation as a linked pair, the enroll of the successor and the retire of the predecessor consecutive at one instant.

```
deadbolt --state rotation.json audit
```

```
{"seq":1,"at":1794272130,"kind":"enroll","credential":"cache-key","resource":null,"action":null,"run_id":null,"outcome":"enrolled"}
{"seq":2,"at":1794272144,"kind":"grant","credential":"cache-key","resource":"bucket","action":"read","run_id":"rotation-demo","outcome":"granted"}
{"seq":3,"at":1794272156,"kind":"redeem","credential":"cache-key","resource":"bucket","action":"read","run_id":"rotation-demo","outcome":"redeemed"}
{"seq":4,"at":1794272169,"kind":"enroll","credential":"cache-key-2026","resource":null,"action":null,"run_id":null,"outcome":"enrolled, rotation of cache-key"}
{"seq":5,"at":1794272169,"kind":"retire","credential":"cache-key","resource":null,"action":null,"run_id":null,"outcome":"retired, rotation to cache-key-2026"}
{"seq":6,"at":1794272191,"kind":"redeem","credential":"cache-key","resource":"bucket","action":"read","run_id":"rotation-demo","outcome":"refused, revoked"}
{"seq":7,"at":1794272209,"kind":"grant","credential":"cache-key-2026","resource":"bucket","action":"read","run_id":null,"outcome":"granted"}
{"seq":8,"at":1794272231,"kind":"redeem","credential":"cache-key-2026","resource":"bucket","action":"read","run_id":null,"outcome":"redeemed"}
```

### Audit

The audit read prints one record per act in order, and the sequence runs gapless from one. Every act stands in the log with its outcome, grants and redemptions and refusals alike, and no record carries a value, a token, or a token hash.

```
deadbolt --state usage.json audit
```

```
{"seq":1,"at":1794115946,"kind":"enroll","credential":"api-key","resource":null,"action":null,"run_id":null,"outcome":"enrolled"}
{"seq":2,"at":1794115946,"kind":"grant","credential":"api-key","resource":"bucket","action":"read","run_id":"demo-run","outcome":"granted"}
{"seq":3,"at":1794115947,"kind":"redeem","credential":"api-key","resource":"bucket","action":"read","run_id":"demo-run","outcome":"redeemed"}
{"seq":4,"at":1794115948,"kind":"redeem","credential":"api-key","resource":"bucket","action":"write","run_id":"demo-run","outcome":"refused, scope mismatch"}
{"seq":5,"at":1794115948,"kind":"grant","credential":"api-key","resource":"bucket","action":"read","run_id":null,"outcome":"granted"}
{"seq":6,"at":1794115952,"kind":"redeem","credential":"api-key","resource":"bucket","action":"read","run_id":null,"outcome":"refused, expired"}
{"seq":7,"at":1794115952,"kind":"cutoff","credential":null,"resource":null,"action":null,"run_id":"demo-run","outcome":"cut off, 1 ended"}
{"seq":8,"at":1794115953,"kind":"redeem","credential":"api-key","resource":"bucket","action":"read","run_id":"demo-run","outcome":"refused, revoked"}
```

## Status

The broker works end to end through the command line and the library against one state file. Enrollment, grant, redeem, revoke, cutoff, retire, rotation, replacement, and the audit read all stand landed and tested. The state file holds the deadbolt-state/1 document inside a deadbolt-envelope/1 envelope, sealed with XChaCha20-Poly1305 under a fresh random 24 byte nonce per write, with the header bytes authenticated as written. The unlock key stands in the operating system keychain on macOS, in the Windows credential store, and in Linux Secret Service. Where no keychain service answers, the passphrase route is the fallback, its key derived from a per-session passphrase with Argon2id and never stored. The state file is owner only, and the broker refuses to operate on it when its mode grants anyone else access.

What does not stand proven. The keychain route is verified at the custody seam and against platform probes, not against a live keychain service, because no keychain daemon runs in the build environment or in continuous integration. That residue stands named in the contract as DK-24. A store whose key is lost does not open, and deadbolt offers no recovery for a lost keychain entry or a forgotten passphrase, and no way to move a store between routes or rekey one in place.

What is not built. Deadbolt has no daemon, no network service, and no Python binding, and the binding absence is by design. Nothing watches the state file, and a grant is judged at the instant a redeem presents it, so expiry needs no timer.

Closed perfection rounds are 8 of 100. A round counts only when a full cycle of work and audit and review and red team and approval has closed, and seeding and setup are not rounds.

The contract lives in CONTRACT.md, where obligations DK-1 to DK-27 state the broker semantics, the limits, and the custody and envelope rules.

The remote seed was verified on 2026-11-02 against the staged seed and its commit is 08a05b881350c6ca5eb8a42af28d25f194c6d039, a parentless commit holding exactly README.md and LICENSE and .gitignore.

## License

MIT. See [LICENSE](LICENSE).
