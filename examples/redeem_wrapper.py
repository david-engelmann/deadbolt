#!/usr/bin/env python3
"""Redeem a deadbolt grant token and inject the secret into one child command.

This standalone helper uses only the Python standard library. It calls the
deadbolt binary to redeem a grant token for a named scope, strips
DEADBOLT_TOKEN, DEADBOLT_PASSPHRASE, and DEADBOLT_NEW_PASSPHRASE from the child
environment, injects the redeemed secret under the requested environment
variable name, and executes the child command without ever printing the secret
value.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")
RESERVED_ENV_NAMES = frozenset(
    {
        "DEADBOLT_TOKEN",
        "DEADBOLT_PASSPHRASE",
        "DEADBOLT_NEW_PASSPHRASE",
    }
)


def parse_args(argv: list[str]) -> tuple[argparse.Namespace, list[str]]:
    if "--" in argv:
        sep = argv.index("--")
        head = argv[:sep]
        cmd: list[str] | None = argv[sep + 1 :]
    else:
        head = argv
        cmd = None

    parser = argparse.ArgumentParser(
        prog="redeem_wrapper.py",
        add_help=True,
        description="Redeem a deadbolt grant token into one child environment variable.",
    )
    parser.add_argument("--state", required=True, help="Path to the deadbolt store")
    parser.add_argument(
        "--scope", required=True, help="Scope in resource and action colon form"
    )
    parser.add_argument(
        "--env-var",
        required=True,
        help="Environment variable name receiving the redeemed secret",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Grant token (defaults to DEADBOLT_TOKEN environment variable)",
    )
    parser.add_argument(
        "--deadbolt-bin",
        default="deadbolt",
        help="Path or name of the deadbolt binary",
    )
    ns = parser.parse_args(head)

    if cmd is None:
        sys.stderr.write(
            "error: usage requires -- followed by the child command to execute\n"
        )
        raise SystemExit(2)
    if not cmd:
        sys.stderr.write("error: no child command stands after --\n")
        raise SystemExit(2)
    if not ENV_NAME_RE.match(ns.env_var) or ns.env_var in RESERVED_ENV_NAMES:
        sys.stderr.write(
            "error: --env-var must be a non-reserved ASCII identifier\n"
        )
        raise SystemExit(2)
    return ns, cmd


def main(argv: list[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    ns, child_cmd = parse_args(raw_argv)

    token = ns.token if ns.token is not None else os.environ.get("DEADBOLT_TOKEN")
    if not token:
        sys.stderr.write(
            "error: supply --token or set DEADBOLT_TOKEN in the environment\n"
        )
        return 2

    try:
        redeem = subprocess.run(
            [
                ns.deadbolt_bin,
                "--state",
                ns.state,
                "redeem",
                "--token",
                token,
                "--scope",
                ns.scope,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
        )
    except OSError as exc:
        sys.stderr.write(
            f"error: failed to execute deadbolt binary {ns.deadbolt_bin}, {exc}\n"
        )
        return 2

    if redeem.returncode != 0:
        if redeem.stderr:
            sys.stderr.write(redeem.stderr.decode("utf-8", errors="replace"))
        return redeem.returncode

    try:
        secret = redeem.stdout.decode("utf-8")
    except UnicodeDecodeError:
        sys.stderr.write("error: redeemed value is not valid UTF-8 text\n")
        return 2

    if secret.endswith("\n"):
        secret = secret[:-1]
    if "\x00" in secret:
        sys.stderr.write(
            "error: redeemed value contains a NUL byte and cannot enter an environment variable\n"
        )
        return 2

    child_env = dict(os.environ)
    child_env.pop("DEADBOLT_TOKEN", None)
    child_env.pop("DEADBOLT_PASSPHRASE", None)
    child_env.pop("DEADBOLT_NEW_PASSPHRASE", None)
    child_env[ns.env_var] = secret

    try:
        completed = subprocess.run(child_cmd, env=child_env)
    except OSError as exc:
        sys.stderr.write(
            f"error: failed to execute child command {child_cmd[0]}, {exc}\n"
        )
        return 127
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
