# Contract

Deadbolt asks whether an agent can do its work with credentials it never sees, acting through scoped and expiring tokens while the real keys never enter the agent process. This file is the stub contract for the setup slice. It states the setup obligations only, and each obligation is stated so it can fail.

Obligation S1 covers seed integrity. The seed files README.md and LICENSE and .gitignore are present from the first commit, and every later change lands through a pull request rather than a direct push to main. This is covered by inspection of the repository history and by the status section of the README.

Obligation S2 covers the local gate. The test suite runs with cargo test plus the codepoint scan run through cargo, and running it needs no paid service, and the continuous integration workflow runs the same commands as the local gate. This wording is amended by Round 1 slice 1. The setup wording named python and pytest alone and no network access, and the amendment replaces it under the program language ruling of 2026-11-02, which made every repo in the program a Rust crate. The amended gate keeps the no paid service term. It drops the no network access term for one stated reason, a first build fetches the crate dependencies from the public crates.io registry, and the tests themselves then run with no network access. This is covered by the tests in the tests folder and by the workflow in the .github folder.

Obligation S3 covers honest status. The README status section records the seed state and the contract state truthfully and it reports closed perfection rounds as 0 of 100 until a full cycle of work and audit and review and red team and approval has closed. This is covered by inspection of the README against this contract and against the repository history.

Obligation S4 covers synthetic content only. Every fixture and every example in this repository is synthetic and written for this repo, and no file carries a real trace or a real transcript or a real name or any private operational detail. This is covered by inspection of the repository contents before any push.

Obligation S5 covers the canonical agents file. The part of AGENTS.md above the marked line is identical to the canonical template for the program, and only the repo annex below the marked line differs for deadbolt. This is covered by tests in the tests folder that pin the SHA-256 digest of the part above the marked line and check the marked line and the annex.

The full contract for deadbolt is the first build act of this repo and it lands with the first slice. This stub is not the full contract, and no feature claim for deadbolt rests on this stub.

## The full contract, Round 1 slice 1

The stub above stands as the record of the setup state, with the one amendment stated inside obligation S2 itself. What follows is the full contract the stub promised, landed as the first build act of this repo in Round 1 slice 1. Slice 1 builds the broker core as a Rust library crate with a thin command line binary over one local state file. It runs no network service, integrates with no proxy or harness, and brokers only for callers who share the machine and the filesystem.

### Probe preamble

The obligations below rest on behaviour probed on this machine rather than on habit. The toolchain is cargo 1.91.1 and rustc 1.91.1. A scratch crate depending on serde and serde_json and sha2 and fs2 and getrandom resolved every dependency from the crates.io registry and built and ran clean, so the broker is built on those crates and on no hand rolled JSON or hash code.

The getrandom crate filled 32 bytes from the operating system random source in about four microseconds. The fs2 exclusive lock blocked a second handle that tried to take the lock while it was held and allowed it after release. A rename within one directory preserved a mode of 0600 set on the temporary file, and the mode bits read back as 0600 for a process running as root, so the permission gate can read bits rather than attempt access. Eight workers each performing 25 increments as a locked read and modify and rename publish against one document produced a final count of exactly 200, and a reader thread parsing the document throughout observed 1626 reads with zero parse failures, so publication by rename never shows a torn document on this machine.

Plain serde_json parsing accepts a document with a duplicated key into an untyped value and keeps the last value, so strict reading cannot rest on untyped parsing. Parsing the same document into the typed state structures refuses it, because the derived readers reject a repeated field, and they reject a field the format does not name when the structure denies unknown fields. A 5000 digit integer refuses with a number out of range error rather than parsing, an integer past the u64 range refuses as a type error, and a fractional number refuses for an integer field. The strict reader of obligation DK-2 is built from those typed structures plus the cross field checks of DK-2 itself.

### Obligation DK-1 covers the state document and its publication

The broker keeps credentials and grants and the audit trail in one JSON document whose format field names deadbolt-state/1. Every change is published by writing the whole document to a temporary file in the same directory, setting its mode to owner only before the write, syncing it, and renaming it over the state file, and every act happens while holding one exclusive advisory lock on a lock file standing beside the state file. The lock file is the standing companion file of the broker. Opening the broker creates it whether or not a state file stands, it is created with mode 0600 like the state file, and it carries no credential data and no record of any act. A grant and the audit record of the grant land in the same rename, so the document never shows one without the other. A state file that does not stand is read as an empty broker, and an act that changes nothing and records nothing creates no state file.

### Obligation DK-2 covers strict reading

A state document that stands must parse as the one format and nothing else. A duplicated key at any level, a field the format does not name, a value of the wrong type, and a number outside the range of its field each refuse as typed corruption. Cross field invariants are validated on every read. Credential names stand unique, grant ids stand unique, token hashes stand unique, the audit sequence stands gapless from one, and every live grant names a credential that stands. A state that fails any of this blocks every operation with the corruption named, and the broker never resets or truncates or repairs a state file on its own.

### Obligation DK-3 covers enrollment

Enroll names a credential, its value, and its allowed scopes, and each scope is one resource and one action stated as a pair. The command line takes the value from a named file only and never from an argument, and the library operation takes the value as data. The value must be one nonempty line of text, and an enroll that names no scope or repeats a scope fails validation of the request shape. Enrolling a name that already stands is refused against the loaded state.

### Obligation DK-4 covers retirement

Retire names a credential and removes it, and every live grant for that credential ends in the same act with the retirement named as its reason. Retiring a name that does not stand is refused. A grant ended by retirement redeems never again, including at instants inside its window.

### Obligation DK-5 covers granting

Grant names a credential, one scope, a time to live, and optionally the run the grant belongs to. The grant succeeds only when the requested scope equals one of the credential enrolled scopes as a whole pair. On success the caller receives a grant id and the token and the expiry instant, and the state records the grant with the hash of the token and never the token itself. Granting against a credential that does not stand is refused, and granting a scope the credential does not carry is refused.

### Obligation DK-6 covers the token

A token is 32 bytes from the operating system random source, written as 64 lowercase hexadecimal characters. The state stores only the SHA-256 hash of the token text. The token is returned once, by the grant that created it, and no later operation displays it. Redeem finds its grant by hashing the presented token and comparing hashes, and the broker never stores or logs the presented token.

### Obligation DK-7 covers redemption

Redeem presents a token and the scope the caller wants to exercise. When the grant stands live at the presented instant and the presented scope equals the grant scope, redeem returns the credential value and nothing else on its output. Every other outcome is a refusal that names its reason, and the reasons are distinct and checked in one order. Unknown token names the case where no grant carries the presented token hash. Revoked names a grant that has ended by revocation or cutoff or retirement, and it is reported at every instant, including instants before the grant expiry and instants after it. Expired names a grant that stands unended at or after its expiry instant. Scope mismatch names a grant that stands live and unexpired whose scope differs from the presented scope. A grant is live strictly before its expiry instant and dead at it.

### Obligation DK-8 covers revocation and cutoff

Revoke names one grant id and ends that grant. Revoking an id no grant carries is refused, and revoking a grant that already ended is refused with the ending named. Cutoff names a run id and ends every live grant carrying that run id in one act, and it reports how many grants it ended. Cutoff for a run id no grant carries is refused, and a cutoff whose run grants have all already ended succeeds and reports zero. Grants of other runs and grants carrying no run are untouched by a cutoff.

### Obligation DK-9 covers the audit trail

Every act the broker performs against a state it could load is appended to the audit trail in order, enrollments and retirements and grants and redemptions and refusals of grants and redemptions and revocations and cutoffs, each with a sequence number, the instant supplied for the act, the credential name where one is known, the scope where one is in play, the run id where one is in play, and an outcome that names what happened, including the distinct redemption refusal reasons of DK-7. Request shapes that fail validation before the state is opened are caller errors and are never recorded. Acts refused by the permission gate or by corruption are never recorded, because the state they would be recorded in is the state being refused. An act refused against a state file that does not stand is recorded nowhere and creates no state file. The lock file of DK-1 is the standing exception to that sentence, because opening creates it before the broker can know whether a state file stands. The audit trail never carries a credential value or a token or a token hash, and the audit command prints the entries in sequence order and nothing else.

### Obligation DK-10 covers containment of the value

An enrolled value appears in exactly two places, the state file itself and the output of a successful redeem. It appears in no grant output and no audit output and no retire or revoke or cutoff output and no error message, and no operation echoes it back. The token appears in exactly one output, the grant that created it, and afterward only ever as caller input to redeem. The tests grep every command output and every error the broker produces for enrolled values and for live tokens and require their absence everywhere this contract does not name an appearance.

### Obligation DK-11 covers the permission gate

The state file is created with mode 0600, and every published replacement is created with mode 0600 before it is renamed over the old file. On every open the broker reads the state file mode bits, and when any group or other permission bit stands set it refuses every operation with a typed error naming the permission problem, and it writes nothing. The check reads the bits themselves rather than attempting access, so it holds for an operator running as root exactly as for any other operator. Tightening the mode back to owner only restores service with the state intact.

### Obligation DK-12 covers names and bounds

A credential name and a run id and a resource and an action are each safe names, one to 64 characters drawn from letters and digits and dot and underscore and hyphen, starting with a letter or a digit. Instants are whole seconds since the Unix epoch, from 0 to 253402300799. A time to live stands from 1 to 86400 seconds, and a request outside that range fails validation of the request shape before the state is opened. Expiry is computed with checked arithmetic, and an expiry that would pass the largest instant is refused. A number outside the range of its field, in a request or in a stored document, refuses as a typed error or as typed corruption, and the broker never panics on such input and never prints an offending number at the size it arrived.

### Obligation DK-13 covers the command line

The binary is named deadbolt and takes the state file path as a global option. It offers the commands enroll and retire and grant and redeem and revoke and cutoff and audit. Enroll takes the credential value from a named value file only and offers no option that takes the value itself. The command line passes the wall clock UTC instant to every operation and offers no option to override it. Success exits 0. A refusal and a corrupt state and a permission gated state exit 1. A caller error exits 2, and caller errors are bad arguments and an unreadable value file and a request shape that fails validation. A filesystem failure on a path the operator supplied stands in the caller error class as well and exits 2, following the precedent of obligation PC-11 in the portcullis contract, because the operator owns the path and the failure is theirs to repair. Its error line names the path and names the failure as the filesystem refusing it, and never as a fault in the request. Every error prints as one line on standard error. Redeem prints the value and a newline and nothing else.

### Obligation DK-14 covers the limits of slice 1

There is no encryption at rest in slice 1. The state file holds values in plain form behind the permission gate of DK-11, and encryption is named as a later slice because its hard part is custody of the encrypting key, and a cipher whose key sits beside the vault is theatre that would let this repo claim a property it does not hold. Redeem returns the value to its caller, and which local process may call redeem is deployment rather than something the broker proves. The broker trusts caller identity claims, a run id is a label the caller supplies, and cutoff by run is an operator tool and not a proof about who asked. Slice 1 has no network service and no daemon and no proxy or harness integration, no wildcard or prefix or implied scopes, no credential rotation workflow beyond retire and enroll, and no brokering for callers on other machines. Anything beyond these limits is a later slice and is not claimed here.

## Repair note for Round 1 slice 1

The three reviews of this slice found defects, and this repair pass fixes them and is recorded here so the contract and the code tell one story. Retire and cutoff ended grants that had already died by expiry, stamping an ending on them and turning their redemption answer from expired to revoked, and both acts now end only the grants that stand live at the supplied instant under the definition in DK-7, so a grant already dead by expiry keeps no end stamp and keeps answering expired. The strict reader of DK-2 reads the word live with that same definition, judging a grant against the latest instant the document itself records, so a state that retirement leaves behind stays readable by the broker that wrote it. DK-1 and DK-9 now name the lock file as the standing companion file that opening creates, so the creates no file wording of the first build no longer reads against its own design. The lock file is now created with mode 0600 like the state file, so no other local user can take the lock and hold the broker still. DK-13 now states the exit class of a filesystem failure on an operator supplied path and the shape of its error line. The local gate also gained the two commands the conversion template carries, a formatting check and a lint run with warnings denied, and both stand in the workflow beside cargo test and the codepoint scan.
