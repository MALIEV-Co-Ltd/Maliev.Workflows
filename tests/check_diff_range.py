#!/usr/bin/env python3
"""Run git diff --check against the exact GitHub event commit range."""

from __future__ import annotations

import os
import re
import subprocess
import sys


EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
ZERO_SHA = "0" * 40
SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def validated_sha(environment_name: str, *, allow_zero: bool = False) -> str:
    value = os.environ.get(environment_name, "")
    if not SHA_PATTERN.fullmatch(value):
        raise ValueError(f"{environment_name} must contain exactly 40 hexadecimal characters")
    normalized = value.lower()
    if normalized == ZERO_SHA and not allow_zero:
        raise ValueError(f"{environment_name} must identify a commit, not the all-zero SHA")
    return normalized


def run_diff_check(arguments: list[str], description: str) -> int:
    print(f"Checking committed whitespace in {description}")
    return subprocess.run(
        ["git", "diff", "--check", *arguments],
        check=False,
    ).returncode


def main() -> int:
    event_name = os.environ.get("MALIEV_EVENT_NAME", "").strip()
    try:
        if event_name == "pull_request":
            base = validated_sha("MALIEV_PR_BASE_SHA")
            head = validated_sha("MALIEV_PR_HEAD_SHA")
            return run_diff_check([f"{base}...{head}"], f"pull request {base}...{head}")

        if event_name == "push":
            before = validated_sha("MALIEV_PUSH_BEFORE_SHA", allow_zero=True)
            after = validated_sha("MALIEV_PUSH_AFTER_SHA")
            if before == ZERO_SHA:
                return run_diff_check(
                    [EMPTY_TREE_SHA, after],
                    f"initial push {EMPTY_TREE_SHA}..{after}",
                )
            return run_diff_check([f"{before}...{after}"], f"push {before}...{after}")

        if event_name in ("", "local"):
            return run_diff_check(["HEAD"], "local HEAD and working tree")
    except ValueError as error:
        return fail(str(error))

    return fail(f"unsupported MALIEV_EVENT_NAME: {event_name!r}")


if __name__ == "__main__":
    raise SystemExit(main())
