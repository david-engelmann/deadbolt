#!/usr/bin/env python3
"""Standalone standard-library CLI broker walkthrough for deadbolt.

Exercises credential enrollment, non-secret status inspection, scoped grant
minting, zero-leak environment injection via examples/redeem_wrapper.py,
scope-mismatch refusal, run-scoped cutoff, post-cutoff refusal, atomic
passphrase rekey, and audit trail reading inside a temporary directory
without printing any secret value or capability token.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def resolve_deadbolt_bin(explicit: str | None) -> str:
    if explicit:
        return explicit
    env_bin = os.environ.get("CARGO_BIN_EXE_deadbolt")
    if env_bin:
        return env_bin
    repo_root = Path(__file__).resolve().parent.parent
    exe_name = "deadbolt.exe" if os.name == "nt" else "deadbolt"
    for profile in ("debug", "release"):
        candidate = repo_root / "target" / profile / exe_name
        if candidate.is_file():
            return str(candidate)
    found = shutil.which("deadbolt")
    if found:
        return found
    raise RuntimeError(
        "deadbolt binary not found; build with `cargo build --bin deadbolt` or pass --deadbolt-bin"
    )


def run_deadbolt(
    deadbolt_bin: str,
    state_path: Path,
    passphrase: str,
    expected_rc: int,
    *args: str,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["DEADBOLT_PASSPHRASE"] = passphrase
    if extra_env:
        env.update(extra_env)
    proc = subprocess.run(
        [deadbolt_bin, "--state", str(state_path), *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode != expected_rc:
        raise RuntimeError(
            f"deadbolt {' '.join(args)} exited {proc.returncode} (expected {expected_rc}): {proc.stderr.strip()}"
        )
    return proc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="broker_walkthrough.py",
        description="Run a standalone CLI secrets-broker walkthrough with deadbolt.",
    )
    parser.add_argument(
        "--deadbolt-bin",
        default=None,
        help="Path to the deadbolt binary (defaults to CARGO_BIN_EXE_deadbolt, target/debug, or PATH)",
    )
    ns = parser.parse_args(argv)
    deadbolt_bin = resolve_deadbolt_bin(ns.deadbolt_bin)
    wrapper_path = Path(__file__).resolve().parent / "redeem_wrapper.py"
    passphrase = "SYNTHETIC-TEST-VALUE-passphrase"
    passphrase_v2 = "SYNTHETIC-TEST-VALUE-passphrase-v2"

    with tempfile.TemporaryDirectory(prefix="deadbolt-walkthrough-") as tmp:
        tmp_dir = Path(tmp)
        state_path = tmp_dir / "vault.json"
        value_file = tmp_dir / "storage-key.txt"
        value_file.write_text("SYNTHETIC-TEST-VALUE-storage-key\n", encoding="utf-8")

        # 1. Enroll credential from file on the passphrase route, then delete value file.
        enrolled = json.loads(
            run_deadbolt(
                deadbolt_bin,
                state_path,
                passphrase,
                0,
                "--route",
                "passphrase",
                "enroll",
                "--name",
                "storage-api",
                "--value-file",
                str(value_file),
                "--scope",
                "artifacts:read",
                "--scope",
                "artifacts:write",
            ).stdout
        )
        value_file.unlink()
        assert enrolled == {"enrolled": "storage-api"}, enrolled
        print("1. enrolled", enrolled["enrolled"])

        # 2. Non-secret store status summary.
        st = json.loads(run_deadbolt(deadbolt_bin, state_path, passphrase, 0, "status").stdout)
        assert st["route"] == "passphrase", st
        assert len(st["credentials"]) == 1, st
        print("2. status route=", st["route"], "credentials=", len(st["credentials"]))

        # 3. Mint a scoped grant tagged with --run walkthrough-run.
        receipt = json.loads(
            run_deadbolt(
                deadbolt_bin,
                state_path,
                passphrase,
                0,
                "grant",
                "--credential",
                "storage-api",
                "--scope",
                "artifacts:read",
                "--ttl",
                "300",
                "--run",
                "walkthrough-run",
            ).stdout
        )
        grant_id = receipt["grant_id"]
        token = receipt["token"]
        print("3. minted grant_id=", grant_id)

        # 4. Inject secret into one child command via redeem_wrapper.py without printing it.
        child_env = dict(os.environ)
        child_env["DEADBOLT_PASSPHRASE"] = passphrase
        child_env["DEADBOLT_TOKEN"] = token
        verify_code = (
            "import os; "
            "assert os.environ.get('STORAGE_TOKEN') == 'SYNTHETIC-TEST-VALUE-storage-key'; "
            "assert 'DEADBOLT_TOKEN' not in os.environ; "
            "assert 'DEADBOLT_PASSPHRASE' not in os.environ; "
            "print('child_env_verified')"
        )
        wrapped = subprocess.run(
            [
                sys.executable,
                str(wrapper_path),
                "--deadbolt-bin",
                deadbolt_bin,
                "--state",
                str(state_path),
                "--scope",
                "artifacts:read",
                "--env-var",
                "STORAGE_TOKEN",
                "--",
                sys.executable,
                "-c",
                verify_code,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=child_env,
            check=False,
        )
        if wrapped.returncode != 0:
            raise RuntimeError(f"redeem_wrapper failed: {wrapped.stderr.strip()}")
        assert wrapped.stdout.strip() == "child_env_verified", wrapped.stdout
        print("4. redeem_wrapper verified child secret injection and env scrubbing")

        # 5. Redeeming the artifacts:read token against artifacts:write is refused.
        mismatch = run_deadbolt(
            deadbolt_bin,
            state_path,
            passphrase,
            1,
            "redeem",
            "--token",
            token,
            "--scope",
            "artifacts:write",
        )
        assert "redeem refused, scope mismatch" in mismatch.stderr, mismatch.stderr
        print("5. scope mismatch refused cleanly")

        # 6. Cut off walkthrough-run and verify subsequent redemption is refused as revoked.
        cut = json.loads(
            run_deadbolt(
                deadbolt_bin, state_path, passphrase, 0, "cutoff", "--run", "walkthrough-run"
            ).stdout
        )
        assert cut == {"grants_ended": 1, "run_id": "walkthrough-run"}, cut
        refused = run_deadbolt(
            deadbolt_bin,
            state_path,
            passphrase,
            1,
            "redeem",
            "--token",
            token,
            "--scope",
            "artifacts:read",
        )
        assert "redeem refused, revoked" in refused.stderr, refused.stderr
        print("6. cutoff ended 1 grant and revoked subsequent redemption")

        # 7. Atomically rekey the store onto a rotated passphrase and verify access + audit.
        rekeyed = json.loads(
            run_deadbolt(
                deadbolt_bin,
                state_path,
                passphrase,
                0,
                "rekey",
                "--to-route",
                "passphrase",
                extra_env={"DEADBOLT_NEW_PASSPHRASE": passphrase_v2},
            ).stdout
        )
        assert rekeyed["from_route"] == "passphrase" and rekeyed["to_route"] == "passphrase", (
            rekeyed
        )
        post_status = json.loads(
            run_deadbolt(deadbolt_bin, state_path, passphrase_v2, 0, "status").stdout
        )
        assert post_status["grants"][0]["status"] == "revoked", post_status
        audit_lines = run_deadbolt(
            deadbolt_bin, state_path, passphrase_v2, 0, "audit"
        ).stdout.splitlines()
        assert len(audit_lines) == 7, audit_lines
        assert json.loads(audit_lines[-1])["kind"] == "rekey", audit_lines[-1]
        print("7. rekeyed store and verified", len(audit_lines), "non-secret audit records")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
