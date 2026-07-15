#!/usr/bin/env python3
"""Executable security contracts for MALIEV reusable workflows."""

from __future__ import annotations

import os
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
FIXTURES = ROOT / "tests" / "fixtures"
SHA_REF = re.compile(r"^(?P<action>[^\s@]+)@(?P<sha>[0-9a-f]{40})$")
ACTION_LINE = re.compile(
    r"^\s*uses:\s*(?P<action>[^\s@]+)@(?P<sha>[0-9a-f]{40})\s+#\s+(?P<version>v\S+)\s*$",
    re.MULTILINE,
)
ACTION_ALLOWLIST = {
    "actions/checkout": (
        "df4cb1c069e1874edd31b4311f1884172cec0e10",
        "v6.0.3",
    ),
    "actions/setup-dotnet": (
        "26b0ec14cb23fa6904739307f278c14f94c95bf1",
        "v5.4.0",
    ),
    "actions/setup-python": (
        "ece7cb06caefa5fff74198d8649806c4678c61a1",
        "v6.3.0",
    ),
    "actions/cache": (
        "caa296126883cff596d87d8935842f9db880ef25",
        "v5.1.0",
    ),
    "actions/upload-artifact": (
        "b7c566a772e6b6bfb58ed0dc250532a479d7789f",
        "v6.0.0",
    ),
    "github/codeql-action/init": (
        "99df26d4f13ea111d4ec1a7dddef6063f76b97e9",
        "v4.37.0",
    ),
    "github/codeql-action/analyze": (
        "99df26d4f13ea111d4ec1a7dddef6063f76b97e9",
        "v4.37.0",
    ),
}
EXPECTED_TRIGGERS = {
    "dotnet-pr-gate.yml": {"workflow_call"},
    "codeql-dotnet.yml": {"workflow_call"},
    "self-validate.yml": {"pull_request", "push"},
}
EXPECTED_PERMISSIONS = {
    "dotnet-pr-gate.yml": {"contents": "read"},
    "codeql-dotnet.yml": {"contents": "read", "security-events": "write"},
    "self-validate.yml": {},
}
EXPECTED_JOB_PERMISSIONS = {
    "self-validate.yml": {
        "repository-contracts": {"contents": "read"},
        "dotnet-gate-smoke": {"contents": "read"},
        "codeql-smoke": {"contents": "read", "security-events": "write"},
    },
}
EXPECTED_DOWNLOAD_STEPS = {
    "dotnet-pr-gate.yml": {"Install checksum-verified Gitleaks"},
    "codeql-dotnet.yml": set(),
    "self-validate.yml": {
        "Install hash-locked validation dependencies",
        "Install checksum-verified actionlint",
        "Install checksum-verified Gitleaks",
    },
}
OFFICIAL_DOTNET_SDK = "10.0.302"
EXPECTED_CHECK_NAMES = {
    "repository-contracts": "Repository contracts and supply chain",
    "dotnet-gate-smoke": "Live reusable .NET gate smoke",
    "codeql-smoke": "Live reusable CodeQL smoke",
}
EXPECTED_REUSABLE_JOB_NAMES = {
    "dotnet-pr-gate.yml": {"validate": "Build, test, and inspect"},
    "codeql-dotnet.yml": {"analyze": "Analyze C#"},
}
NETWORK_COMMAND_PATTERNS = {
    "cloud-copy": re.compile(r"(?m)(?:^|[;&|]\s*)(?:aws\s+s3\s+cp|az\s+storage\b|gcloud\s+storage\b|gsutil\s+(?:cp|rsync))"),
    "system-package": re.compile(r"(?m)(?:^|[;&|]\s*)(?:sudo\s+)?(?:apk|apt(?:-get)?|brew|choco|dnf|winget|yum|zypper)\s+(?:add|download|install|update|upgrade)\b"),
    "cargo": re.compile(r"(?m)(?:^|[;&|]\s*)cargo\s+(?:install|fetch)\b"),
    "composer": re.compile(r"(?m)(?:^|[;&|]\s*)(?:bundle|composer)\s+(?:install|update)\b"),
    "curl": re.compile(r"(?m)(?:^|\s)curl(?:\.exe)?\s+"),
    "docker": re.compile(r"(?m)(?:^|[;&|]\s*)docker\s+(?:pull|buildx\s+imagetools\s+create)\b"),
    "dotnet-package-audit": re.compile(r"(?m)(?:^|[;&|]\s*)dotnet\s+list\s+.*?\s+package\s+--(?:vulnerable|deprecated)\b"),
    "dotnet-restore": re.compile(r"(?m)(?:^|[;&|]\s*)dotnet\s+restore\b"),
    "dotnet-tool": re.compile(r"(?m)(?:^|[;&|]\s*)dotnet\s+tool\s+(?:install|restore|update)\b"),
    "gem": re.compile(r"(?m)(?:^|[;&|]\s*)gem\s+install\b"),
    "git-network": re.compile(r"(?m)(?:^|[;&|]\s*)git\s+(?:clone|fetch|pull|submodule\s+(?:add|update))\b"),
    "github-cli": re.compile(r"(?m)(?:^|[;&|]\s*)gh\s+(?:api|release\s+download)\b"),
    "go-install": re.compile(r"(?m)(?:^|[;&|]\s*)go\s+install\b"),
    "helm": re.compile(r"(?m)(?:^|[;&|]\s*)helm\s+(?:dependency\s+(?:build|update)|pull|repo\s+add)\b"),
    "node-package": re.compile(r"(?m)(?:^|[;&|]\s*)(?:npm|pnpm|yarn)\s+(?:add|ci|fetch|install|update)\b"),
    "nuget": re.compile(r"(?m)(?:^|[;&|]\s*)nuget\s+(?:install|restore|update)\b"),
    "pip": re.compile(r"(?m)(?:^|\s)(?:python(?:3)?\s+-m\s+)?pip\s+(?:download|install|wheel)\b"),
    "oci-client": re.compile(r"(?m)(?:^|[;&|]\s*)(?:crane|oras|skopeo)\s+(?:copy|pull)\b"),
    "python-package": re.compile(r"(?m)(?:^|[;&|]\s*)(?:pipx|poetry|uv)\s+(?:add|install|sync)\b"),
    "powershell-web": re.compile(r"(?im)(?:^|[;&|]\s*)(?:Invoke-RestMethod|Invoke-WebRequest|irm|iwr|Start-BitsTransfer)(?:\s|$)"),
    "python-http": re.compile(r"(?m)\b(?:aiohttp|httpx|requests|urllib(?:\.request)?|urlopen)\b"),
    "runtime-http": re.compile(r"(?m)\b(?:HttpClient|WebClient)\b|\bfetch\s*\("),
    "wget": re.compile(r"(?m)(?:^|\s)wget(?:\.exe)?\s+"),
}
EXPECTED_NETWORK_INVENTORY = {
    ("dotnet-pr-gate.yml", "Restore"): {"dotnet-restore"},
    ("dotnet-pr-gate.yml", "Audit vulnerable dependencies"): {"dotnet-package-audit"},
    ("dotnet-pr-gate.yml", "Audit deprecated dependencies"): {"dotnet-package-audit"},
    ("dotnet-pr-gate.yml", "Install checksum-verified Gitleaks"): {"curl"},
    ("codeql-dotnet.yml", "Restore and build analyzed source"): {"dotnet-restore"},
    ("self-validate.yml", "Install hash-locked validation dependencies"): {"pip"},
    ("self-validate.yml", "Install checksum-verified actionlint"): {"curl"},
    ("self-validate.yml", "Install checksum-verified Gitleaks"): {"curl"},
}


def yaml_paths(root: Path) -> list[Path]:
    return sorted({*root.rglob("*.yml"), *root.rglob("*.yaml")})


def load_yaml(path: Path) -> dict:
    with path.open(encoding="utf-8") as stream:
        data = yaml.load(stream, Loader=yaml.BaseLoader)
    if not isinstance(data, dict):
        raise AssertionError(f"{path}: top-level YAML value must be a mapping")
    return data


def steps(workflow: dict) -> list[dict]:
    return [
        step
        for job in workflow.get("jobs", {}).values()
        for step in job.get("steps", [])
    ]


def step_map(workflow: dict) -> dict[str, dict]:
    return {step["name"]: step for step in steps(workflow)}


def embedded_python(command: str, marker: str) -> str:
    match = re.search(r"python3 - .*?<<'PY'\n(?P<script>.*?)\nPY(?:\n|$)", command, re.DOTALL)
    if not match or marker not in match.group("script"):
        raise AssertionError(f"Embedded Python helper {marker!r} was not found")
    return match.group("script")


def run_python(script: str, args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as temporary:
        script_path = Path(temporary) / "helper.py"
        script_path.write_text(script, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(script_path), *args],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )


def run_git(repository: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )


def run_diff_helper(repository: Path, **environment: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(ROOT / "tests" / "check_diff_range.py")],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, **environment},
    )


def expected_codeql_upload(event_name: str, *, head_is_fork: bool, user_login: str) -> str:
    restricted_pull_request = event_name == "pull_request" and (
        head_is_fork or user_login == "dependabot[bot]"
    )
    return "never" if restricted_pull_request else "always"


class WorkflowContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow_paths = yaml_paths(WORKFLOWS)
        cls.workflows = {path.name: load_yaml(path) for path in cls.workflow_paths}
        cls.gate = cls.workflows["dotnet-pr-gate.yml"]
        cls.codeql = cls.workflows["codeql-dotnet.yml"]
        cls.gate_steps = step_map(cls.gate)

    def test_all_repository_yaml_files_parse(self) -> None:
        paths = yaml_paths(ROOT / ".github")
        self.assertGreaterEqual(len(paths), 3)
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                load_yaml(path)

    def test_repository_self_validation_caller_and_dotnet_fixture_exist(self) -> None:
        self.assertTrue(
            (WORKFLOWS / "self-validate.yml").is_file(),
            "the repository self-validation caller workflow is required",
        )
        self.assertTrue(
            (FIXTURES / "dotnet-smoke" / "Maliev.Workflows.Smoke.slnx").is_file(),
            "the live reusable-workflow .NET fixture is required",
        )

    def test_every_workflow_has_the_baseline_trigger_secret_and_permission_contract(self) -> None:
        self.assertEqual(set(EXPECTED_TRIGGERS), set(self.workflows))
        for name, workflow in self.workflows.items():
            with self.subTest(workflow=name):
                raw = next(path for path in self.workflow_paths if path.name == name).read_text(
                    encoding="utf-8"
                ).lower()
                self.assertEqual(EXPECTED_TRIGGERS[name], set(workflow.get("on", {})))
                if "workflow_call" in workflow["on"]:
                    call = workflow["on"]["workflow_call"] or {}
                    self.assertNotIn("secrets", call)
                self.assertNotIn("pull_request_target", repr(workflow).lower())
                self.assertNotIn("secrets: inherit", raw)
                self.assertNotRegex(raw, r"\$\{\{\s*secrets(?:\.|\[)")
                self.assertEqual(EXPECTED_PERMISSIONS[name], workflow.get("permissions"))
                for job_name, job in workflow.get("jobs", {}).items():
                    expected_job_permissions = EXPECTED_JOB_PERMISSIONS.get(name, {})
                    if expected_job_permissions:
                        self.assertEqual(
                            expected_job_permissions[job_name],
                            job.get("permissions"),
                            job_name,
                        )
                    else:
                        self.assertNotIn("permissions", job, job_name)
                    if "uses" not in job:
                        timeout = int(job.get("timeout-minutes", "0"))
                        self.assertGreater(timeout, 0, job_name)
                        self.assertLessEqual(timeout, 60, job_name)

    def test_self_validation_trigger_is_exact_and_fork_safe(self) -> None:
        caller = self.workflows.get("self-validate.yml")
        self.assertIsNotNone(caller)
        self.assertEqual("", caller["on"]["pull_request"])
        self.assertEqual(
            ["develop", "main"],
            caller["on"]["push"].get("branches"),
        )
        self.assertEqual({}, caller.get("permissions"))

    def test_every_workflow_cancels_superseded_runs_with_a_bounded_group(self) -> None:
        for name, workflow in self.workflows.items():
            with self.subTest(workflow=name):
                concurrency = workflow.get("concurrency", {})
                self.assertEqual("true", concurrency.get("cancel-in-progress"))
                group = concurrency.get("group", "")
                self.assertGreater(len(group), 0)
                self.assertLessEqual(len(group), 128)
                self.assertIn("${{ github.workflow }}", group)
                self.assertIn("${{ github.ref }}", group)

    def test_workflow_inputs_are_exact_typed_and_do_not_expand_the_trust_boundary(self) -> None:
        expected = {
            "dotnet-pr-gate.yml": {
                "target-path",
                "working-directory",
                "dotnet-version",
                "configuration",
                "coverage-threshold",
                "artifact-retention-days",
            },
            "codeql-dotnet.yml": {"target-path", "working-directory", "dotnet-version"},
        }
        forbidden = {"command", "script", "runner", "token", "secret", "action-ref"}
        for name, workflow in self.workflows.items():
            if "workflow_call" not in workflow["on"]:
                continue
            inputs = workflow["on"]["workflow_call"].get("inputs", {})
            self.assertEqual(expected[name], set(inputs))
            self.assertTrue(forbidden.isdisjoint(inputs))
            for input_name, spec in inputs.items():
                self.assertIn(spec.get("type"), {"string", "number", "boolean"}, input_name)
        self.assertEqual("10.0.x", self.gate["on"]["workflow_call"]["inputs"]["dotnet-version"]["default"])
        self.assertEqual("10.0.x", self.codeql["on"]["workflow_call"]["inputs"]["dotnet-version"]["default"])

    def test_self_validation_calls_local_reusable_workflows_with_exact_safe_inputs(self) -> None:
        caller = self.workflows.get("self-validate.yml")
        self.assertIsNotNone(caller)
        jobs = caller["jobs"]
        fixture_root = "tests/fixtures/dotnet-smoke"
        fixture = "Maliev.Workflows.Smoke.slnx"

        gate = jobs["dotnet-gate-smoke"]
        self.assertEqual("./.github/workflows/dotnet-pr-gate.yml", gate.get("uses"))
        self.assertEqual(
            {
                "target-path": fixture,
                "working-directory": fixture_root,
                "dotnet-version": OFFICIAL_DOTNET_SDK,
                "configuration": "Release",
                "coverage-threshold": "80",
                "artifact-retention-days": "3",
            },
            gate.get("with"),
        )

        codeql = jobs["codeql-smoke"]
        self.assertEqual("./.github/workflows/codeql-dotnet.yml", codeql.get("uses"))
        self.assertEqual(
            {
                "target-path": fixture,
                "working-directory": fixture_root,
                "dotnet-version": OFFICIAL_DOTNET_SDK,
            },
            codeql.get("with"),
        )
        for job in (gate, codeql):
            self.assertNotIn("secrets", job)

    def test_required_check_and_reusable_job_display_names_are_stable(self) -> None:
        caller = self.workflows["self-validate.yml"]
        self.assertEqual(
            EXPECTED_CHECK_NAMES,
            {job_id: job.get("name") for job_id, job in caller["jobs"].items()},
        )
        for workflow_name, expected in EXPECTED_REUSABLE_JOB_NAMES.items():
            with self.subTest(workflow=workflow_name):
                self.assertEqual(
                    expected,
                    {
                        job_id: job.get("name")
                        for job_id, job in self.workflows[workflow_name]["jobs"].items()
                    },
                )

    def test_codeql_analyze_disables_restricted_pull_request_uploads(self) -> None:
        analyze = step_map(self.codeql)["Analyze with CodeQL"]
        self.assertNotIn("if", analyze, "CodeQL analysis must still run for restricted pull requests")
        self.assertEqual(
            "${{ github.event_name == 'pull_request' && (github.event.pull_request.head.repo.fork || github.event.pull_request.user.login == 'dependabot[bot]') && 'never' || 'always' }}",
            analyze.get("with", {}).get("upload"),
        )

    def test_codeql_upload_policy_truth_table(self) -> None:
        cases = {
            "same-repository human pull request": ("pull_request", False, "contributor", "always"),
            "real fork pull request": ("pull_request", True, "contributor", "never"),
            "Dependabot pull request": ("pull_request", False, "dependabot[bot]", "never"),
            "push": ("push", False, "dependabot[bot]", "always"),
        }
        for name, (event_name, head_is_fork, user_login, expected) in cases.items():
            with self.subTest(case=name):
                self.assertEqual(
                    expected,
                    expected_codeql_upload(
                        event_name,
                        head_is_fork=head_is_fork,
                        user_login=user_login,
                    ),
                )

    def test_fixture_and_both_live_calls_use_the_same_exact_official_sdk(self) -> None:
        global_json_path = FIXTURES / "dotnet-smoke" / "global.json"
        self.assertTrue(global_json_path.is_file())
        global_json = json.loads(global_json_path.read_text(encoding="utf-8"))
        self.assertEqual(
            {
                "version": OFFICIAL_DOTNET_SDK,
                "rollForward": "disable",
                "allowPrerelease": False,
            },
            global_json.get("sdk"),
        )
        jobs = self.workflows["self-validate.yml"]["jobs"]
        self.assertEqual(
            global_json["sdk"]["version"],
            jobs["dotnet-gate-smoke"]["with"]["dotnet-version"],
        )
        self.assertEqual(
            global_json["sdk"]["version"],
            jobs["codeql-smoke"]["with"]["dotnet-version"],
        )

    def test_dotnet_commands_execute_from_the_validated_working_directory(self) -> None:
        gate_steps = step_map(self.gate)
        for step_name in (
            "Restore",
            "Audit vulnerable dependencies",
            "Audit deprecated dependencies",
            "Build",
            "Test with line coverage",
            "Verify formatting",
        ):
            with self.subTest(workflow="dotnet-pr-gate.yml", step=step_name):
                self.assertIn('cd "$CI_WORK_ROOT"', gate_steps[step_name].get("run", ""))

        codeql_steps = step_map(self.codeql)
        self.assertIn(
            'printf \'CI_WORK_ROOT=%s\\nCI_TARGET=%s\\n\'',
            codeql_steps["Resolve validated paths"].get("run", ""),
        )
        self.assertIn(
            'cd "$CI_WORK_ROOT"',
            codeql_steps["Restore and build analyzed source"].get("run", ""),
        )

    def test_network_capable_run_commands_match_the_explicit_inventory(self) -> None:
        observed: dict[tuple[str, str], set[str]] = {}
        for name, workflow in self.workflows.items():
            for step in steps(workflow):
                command = step.get("run", "")
                mechanisms = {
                    mechanism
                    for mechanism, pattern in NETWORK_COMMAND_PATTERNS.items()
                    if pattern.search(command)
                }
                if mechanisms:
                    observed[(name, step["name"])] = mechanisms
        self.assertEqual(EXPECTED_NETWORK_INVENTORY, observed)
        for (workflow_name, step_name), mechanisms in EXPECTED_NETWORK_INVENTORY.items():
            command = step_map(self.workflows[workflow_name])[step_name]["run"]
            for mechanism in mechanisms:
                with self.subTest(workflow=workflow_name, step=step_name, mechanism=mechanism):
                    self.assertEqual(
                        1,
                        len(NETWORK_COMMAND_PATTERNS[mechanism].findall(command)),
                        "each approved network mechanism must appear exactly once in its reviewed step",
                    )

    def test_external_downloads_are_reviewed_and_integrity_checked(self) -> None:
        for name, workflow in self.workflows.items():
            download_steps = {
                step["name"]
                for step in steps(workflow)
                if NETWORK_COMMAND_PATTERNS["curl"].search(step.get("run", ""))
                or NETWORK_COMMAND_PATTERNS["pip"].search(step.get("run", ""))
            }
            with self.subTest(workflow=name):
                self.assertEqual(EXPECTED_DOWNLOAD_STEPS[name], download_steps)

        caller_steps = step_map(self.workflows["self-validate.yml"])
        dependencies = caller_steps["Install hash-locked validation dependencies"]["run"]
        self.assertEqual(1, len(NETWORK_COMMAND_PATTERNS["pip"].findall(dependencies)))
        self.assertIn("--require-hashes", dependencies)
        self.assertIn("--only-binary=:all:", dependencies)
        self.assertIn("--index-url https://pypi.org/simple", dependencies)
        self.assertIn("tests/requirements-validation.txt", dependencies)

        actionlint = caller_steps["Install checksum-verified actionlint"]["run"]
        self.assertEqual(1, len(NETWORK_COMMAND_PATTERNS["curl"].findall(actionlint)))
        self.assertIn('readonly version="1.7.12"', actionlint)
        self.assertIn('readonly archive="actionlint_${version}_linux_amd64.tar.gz"', actionlint)
        self.assertIn(
            'readonly checksum="8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"',
            actionlint,
        )
        self.assertIn("sha256sum --check --strict", actionlint)
        self.assertIn(
            "curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output \"$RUNNER_TEMP/$archive\"",
            actionlint,
        )
        self.assertIn(
            'https://github.com/rhysd/actionlint/releases/download/v${version}/${archive}',
            actionlint,
        )
        self.assertIn(
            'tar -xzf "$RUNNER_TEMP/$archive" -C "$RUNNER_TEMP" actionlint',
            actionlint,
        )

        gitleaks = caller_steps["Install checksum-verified Gitleaks"]["run"]
        self.assertEqual(1, len(NETWORK_COMMAND_PATTERNS["curl"].findall(gitleaks)))
        self.assertIn('readonly version="8.30.1"', gitleaks)
        self.assertIn(
            'readonly checksum="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"',
            gitleaks,
        )
        self.assertIn("sha256sum --check --strict", gitleaks)
        self.assertIn(
            "curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output \"$RUNNER_TEMP/$archive\"",
            gitleaks,
        )
        self.assertIn(
            'https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive}',
            gitleaks,
        )
        self.assertIn(
            'tar -xzf "$RUNNER_TEMP/$archive" -C "$RUNNER_TEMP" gitleaks',
            gitleaks,
        )

        all_commands = "\n".join(
            step.get("run", "")
            for workflow in self.workflows.values()
            for step in steps(workflow)
        )
        literal_urls = set(re.findall(r"https://[^\s\"']+", all_commands))
        self.assertEqual(
            {
                "https://pypi.org/simple",
                "https://github.com/rhysd/actionlint/releases/download/v${version}/${archive}",
                "https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive}",
            },
            literal_urls,
        )
        self.assertEqual(
            {"github.com", "pypi.org"},
            {re.match(r"https://([^/]+)", url).group(1) for url in literal_urls},
        )

    def test_diff_range_is_wired_through_environment_without_shell_interpolation(self) -> None:
        validation = step_map(self.workflows["self-validate.yml"])[
            "Validate YAML, workflow contracts, actionlint, and diff"
        ]
        self.assertEqual(
            {
                "MALIEV_EVENT_NAME": "${{ github.event_name }}",
                "MALIEV_PR_BASE_SHA": "${{ github.event.pull_request.base.sha }}",
                "MALIEV_PR_HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
                "MALIEV_PUSH_BEFORE_SHA": "${{ github.event.before }}",
                "MALIEV_PUSH_AFTER_SHA": "${{ github.event.after }}",
            },
            validation.get("env"),
        )
        self.assertNotRegex(validation.get("run", ""), r"\$\{\{")
        entrypoint = (ROOT / "tests" / "validate.ps1").read_text(encoding="utf-8")
        self.assertIn("python tests/check_diff_range.py", entrypoint)
        self.assertNotIn("git diff --check", entrypoint)

    def test_diff_range_helper_rejects_committed_whitespace_and_accepts_clean_range(self) -> None:
        helper = ROOT / "tests" / "check_diff_range.py"
        self.assertTrue(helper.is_file())
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            self.assertEqual(0, run_git(repository, "init", "--initial-branch=main").returncode)
            self.assertEqual(0, run_git(repository, "config", "user.name", "Workflow Test").returncode)
            self.assertEqual(0, run_git(repository, "config", "user.email", "workflow@example.invalid").returncode)
            tracked = repository / "tracked.txt"
            tracked.write_text("clean\n", encoding="utf-8")
            self.assertEqual(0, run_git(repository, "add", "tracked.txt").returncode)
            self.assertEqual(0, run_git(repository, "commit", "-m", "clean base").returncode)
            base = run_git(repository, "rev-parse", "HEAD").stdout.strip()

            tracked.write_text("trailing whitespace \n", encoding="utf-8")
            self.assertEqual(0, run_git(repository, "add", "tracked.txt").returncode)
            self.assertEqual(0, run_git(repository, "commit", "-m", "bad whitespace").returncode)
            bad = run_git(repository, "rev-parse", "HEAD").stdout.strip()
            bad_result = run_diff_helper(
                repository,
                MALIEV_EVENT_NAME="pull_request",
                MALIEV_PR_BASE_SHA=base,
                MALIEV_PR_HEAD_SHA=bad,
            )
            self.assertNotEqual(0, bad_result.returncode)
            self.assertIn("trailing whitespace", bad_result.stdout + bad_result.stderr)

            initial_result = run_diff_helper(
                repository,
                MALIEV_EVENT_NAME="push",
                MALIEV_PUSH_BEFORE_SHA="0" * 40,
                MALIEV_PUSH_AFTER_SHA=bad,
            )
            self.assertNotEqual(0, initial_result.returncode)
            self.assertIn("trailing whitespace", initial_result.stdout + initial_result.stderr)

            tracked.write_text("clean again\n", encoding="utf-8")
            self.assertEqual(0, run_git(repository, "add", "tracked.txt").returncode)
            self.assertEqual(0, run_git(repository, "commit", "-m", "clean range").returncode)
            clean = run_git(repository, "rev-parse", "HEAD").stdout.strip()
            clean_result = run_diff_helper(
                repository,
                MALIEV_EVENT_NAME="push",
                MALIEV_PUSH_BEFORE_SHA=bad,
                MALIEV_PUSH_AFTER_SHA=clean,
            )
            self.assertEqual(0, clean_result.returncode, clean_result.stdout + clean_result.stderr)

    def test_diff_range_helper_rejects_unsafe_sha_text_before_git(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            marker = repository / "must-not-exist"
            result = run_diff_helper(
                repository,
                MALIEV_EVENT_NAME="push",
                MALIEV_PUSH_BEFORE_SHA="0" * 40,
                MALIEV_PUSH_AFTER_SHA=f"{'a' * 40};touch {marker}",
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("40 hexadecimal", result.stdout + result.stderr)
            self.assertFalse(marker.exists())

    def test_validation_requirements_are_exact_and_hash_locked(self) -> None:
        requirements = ROOT / "tests" / "requirements-validation.txt"
        self.assertTrue(requirements.is_file())
        lines = [
            line.strip()
            for line in requirements.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(1, len(lines))
        self.assertEqual(
            "PyYAML==6.0.3 --hash=sha256:ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc",
            lines[0],
        )

    def test_validation_entrypoint_accepts_only_an_explicit_actionlint_binary_path(self) -> None:
        validation = (ROOT / "tests" / "validate.ps1").read_text(encoding="utf-8")
        self.assertIn("[string] $ActionlintPath", validation)
        self.assertIn("Test-Path -LiteralPath $ActionlintPath -PathType Leaf", validation)
        self.assertIn("& $ActionlintPath -color", validation)
        self.assertNotIn("Get-Command actionlint", validation)

    def test_dotnet_smoke_fixture_is_minimal_deterministic_and_net10(self) -> None:
        root = FIXTURES / "dotnet-smoke"
        expected_files = {
            "Directory.Build.props",
            "Directory.Packages.props",
            "Maliev.Workflows.Smoke.slnx",
            "NuGet.config",
            "global.json",
            "src/Maliev.Workflows.Smoke/Maliev.Workflows.Smoke.csproj",
            "src/Maliev.Workflows.Smoke/HealthScore.cs",
            "src/Maliev.Workflows.Smoke/packages.lock.json",
            "tests/Maliev.Workflows.Smoke.Tests/Maliev.Workflows.Smoke.Tests.csproj",
            "tests/Maliev.Workflows.Smoke.Tests/HealthScoreTests.cs",
            "tests/Maliev.Workflows.Smoke.Tests/packages.lock.json",
        }
        actual_files = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and "bin" not in path.parts and "obj" not in path.parts
        }
        self.assertEqual(expected_files, actual_files)

        props = (root / "Directory.Build.props").read_text(encoding="utf-8")
        self.assertIn("<TargetFramework>net10.0</TargetFramework>", props)
        self.assertIn("<RestoreLockedMode>true</RestoreLockedMode>", props)
        self.assertIn("<TreatWarningsAsErrors>true</TreatWarningsAsErrors>", props)
        packages = (root / "Directory.Packages.props").read_text(encoding="utf-8")
        for package in ("Microsoft.NET.Test.Sdk", "coverlet.collector", "xunit.v3", "xunit.runner.visualstudio"):
            self.assertRegex(packages, rf'PackageVersion Include="{re.escape(package)}" Version="[0-9.]+"')
        self.assertNotIn('PackageVersion Include="xunit"', packages)

    def test_fixture_uses_only_the_exact_official_nuget_v3_source(self) -> None:
        nuget_config = (FIXTURES / "dotnet-smoke" / "NuGet.config").read_text(encoding="utf-8")
        self.assertEqual(1, nuget_config.count("<clear />"))
        self.assertEqual(1, nuget_config.count("<add "))
        self.assertIn('value="https://api.nuget.org/v3/index.json"', nuget_config)
        self.assertIn('protocolVersion="3"', nuget_config)

    def test_every_action_matches_the_reviewed_owner_sha_version_allowlist(self) -> None:
        observed: set[tuple[str, str, str]] = set()
        for path in self.workflow_paths:
            raw = path.read_text(encoding="utf-8")
            parsed_actions = [step["uses"] for step in steps(self.workflows[path.name]) if "uses" in step]
            raw_actions = {
                (match["action"], match["sha"], match["version"])
                for match in ACTION_LINE.finditer(raw)
            }
            self.assertEqual(len(parsed_actions), len(raw_actions), path.name)
            for reference in parsed_actions:
                match = SHA_REF.fullmatch(reference)
                self.assertIsNotNone(match, reference)
                action = match["action"]
                self.assertIn(action, ACTION_ALLOWLIST, action)
                expected_sha, expected_version = ACTION_ALLOWLIST[action]
                self.assertEqual(expected_sha, match["sha"], action)
                self.assertIn((action, expected_sha, expected_version), raw_actions)
                observed.add((action, expected_sha, expected_version))
        self.assertEqual(
            {(action, *values) for action, values in ACTION_ALLOWLIST.items()},
            observed,
        )

    def test_checkout_is_credential_free_and_gate_scans_full_history(self) -> None:
        for workflow_name, workflow in self.workflows.items():
            checkout = next(
                step
                for step in steps(workflow)
                if step.get("uses", "").startswith("actions/checkout@")
            )
            self.assertEqual("false", checkout.get("with", {}).get("persist-credentials"))
            if workflow_name == "dotnet-pr-gate.yml":
                self.assertEqual("0", checkout.get("with", {}).get("fetch-depth"))

    def test_gate_step_order_and_named_commands_preserve_dependencies(self) -> None:
        names = [step["name"] for step in steps(self.gate)]
        required_order = [
            "Validate bounded inputs",
            "Check out source without credentials",
            "Resolve validated paths",
            "Set up .NET SDK",
            "Cache NuGet packages",
            "Restore",
            "Audit vulnerable dependencies",
            "Audit deprecated dependencies",
            "Enforce dependency audit",
            "Build",
            "Test with line coverage",
            "Enforce line coverage threshold",
            "Verify formatting",
            "Install checksum-verified Gitleaks",
            "Scan repository history for secrets",
            "Upload test, coverage, and audit evidence",
        ]
        self.assertEqual(required_order, names)

        commands = {name: self.gate_steps[name].get("run", "") for name in required_order}
        self.assertIn('dotnet restore "$CI_TARGET"', commands["Restore"])
        self.assertIn("--vulnerable", commands["Audit vulnerable dependencies"])
        self.assertNotIn("--deprecated", commands["Audit vulnerable dependencies"])
        self.assertIn("--deprecated", commands["Audit deprecated dependencies"])
        self.assertNotIn("--vulnerable", commands["Audit deprecated dependencies"])
        self.assertIn("--include-transitive", commands["Audit vulnerable dependencies"])
        self.assertIn("--include-transitive", commands["Audit deprecated dependencies"])
        self.assertIn("vulnerabilities", commands["Enforce dependency audit"])
        self.assertIn("deprecationReasons", commands["Enforce dependency audit"])
        self.assertIn("dotnet build", commands["Build"])
        self.assertIn("--configuration", commands["Build"])
        self.assertIn("--no-restore", commands["Build"])
        self.assertIn("dotnet test", commands["Test with line coverage"])
        self.assertIn('--collect:"XPlat Code Coverage"', commands["Test with line coverage"])
        self.assertIn("dotnet format", commands["Verify formatting"])
        self.assertIn("--verify-no-changes", commands["Verify formatting"])
        self.assertIn("gitleaks-bin\" detect", commands["Scan repository history for secrets"])
        for command in commands.values():
            self.assertNotRegex(command, r"\$\{\{\s*inputs\.")

    def test_bounded_input_helper_executes_real_path_threshold_and_retention_boundaries(self) -> None:
        script = embedded_python(
            self.gate_steps["Validate bounded inputs"]["run"],
            "INPUT_VALIDATION_PYTHON",
        )
        baseline = {
            **os.environ,
            "TARGET_PATH": "src/App.slnx",
            "WORKING_DIRECTORY": ".",
            "DOTNET_VERSION": "10.0.x",
            "CONFIGURATION": "Release",
            "COVERAGE_THRESHOLD": "80.5",
            "ARTIFACT_RETENTION_DAYS": "7",
        }

        def validate(**overrides: str) -> subprocess.CompletedProcess[str]:
            return run_python(script, [], {**baseline, **overrides})

        for path in ("../escape.slnx", "src/../../escape.slnx", "/tmp/App.slnx", r"src\App.slnx"):
            with self.subTest(path=path):
                self.assertNotEqual(0, validate(TARGET_PATH=path).returncode)
        self.assertEqual(0, validate(TARGET_PATH="src/App.slnx").returncode)
        for directory in ("../escape", "src/../../escape", "/tmp", r"src\nested"):
            with self.subTest(directory=directory):
                self.assertNotEqual(0, validate(WORKING_DIRECTORY=directory).returncode)
        self.assertEqual(0, validate(WORKING_DIRECTORY="src/nested").returncode)

        for threshold in ("0", "0.01", "99.999", "100", "100.0"):
            with self.subTest(valid_threshold=threshold):
                self.assertEqual(0, validate(COVERAGE_THRESHOLD=threshold).returncode)
        for threshold in ("-0.1", "100.1", "101", "999", "nan", "1e2"):
            with self.subTest(invalid_threshold=threshold):
                self.assertNotEqual(0, validate(COVERAGE_THRESHOLD=threshold).returncode)

        for retention in ("1", "7", "30"):
            with self.subTest(valid_retention=retention):
                self.assertEqual(0, validate(ARTIFACT_RETENTION_DAYS=retention).returncode)
        for retention in ("0", "1.5", "31", "999", "-1"):
            with self.subTest(invalid_retention=retention):
                self.assertNotEqual(0, validate(ARTIFACT_RETENTION_DAYS=retention).returncode)

    def test_codeql_input_helper_executes_real_path_and_sdk_boundaries(self) -> None:
        codeql_steps = step_map(self.codeql)
        script = embedded_python(
            codeql_steps["Validate bounded inputs"]["run"],
            "CODEQL_INPUT_VALIDATION_PYTHON",
        )
        baseline = {
            **os.environ,
            "TARGET_PATH": "src/App.slnx",
            "WORKING_DIRECTORY": ".",
            "DOTNET_VERSION": "10.0.x",
        }

        def validate(**overrides: str) -> subprocess.CompletedProcess[str]:
            return run_python(script, [], {**baseline, **overrides})

        for path in ("../escape.slnx", "src/../../escape.slnx", "/tmp/App.slnx", r"src\App.slnx"):
            with self.subTest(target_path=path):
                self.assertNotEqual(0, validate(TARGET_PATH=path).returncode)
        for directory in ("../escape", "src/../../escape", "/tmp", r"src\nested"):
            with self.subTest(working_directory=directory):
                self.assertNotEqual(0, validate(WORKING_DIRECTORY=directory).returncode)
        for sdk in ("8.0.x", "10.0.100", "10.0.100-preview.1"):
            with self.subTest(valid_sdk=sdk):
                self.assertEqual(0, validate(DOTNET_VERSION=sdk).returncode)
        for sdk in ("", "10", "10.x", "latest", "10.0.x;echo", "../10.0.x", "10.0.*"):
            with self.subTest(invalid_sdk=sdk):
                self.assertNotEqual(0, validate(DOTNET_VERSION=sdk).returncode)

    def test_gitleaks_binary_provenance_is_exact_and_immutable(self) -> None:
        install = self.gate_steps["Install checksum-verified Gitleaks"]["run"]
        self.assertEqual(1, len(NETWORK_COMMAND_PATTERNS["curl"].findall(install)))
        self.assertIn('readonly version="8.30.1"', install)
        self.assertIn('readonly archive="gitleaks_${version}_linux_x64.tar.gz"', install)
        self.assertIn(
            'readonly checksum="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"',
            install,
        )
        self.assertIn(
            'https://github.com/gitleaks/gitleaks/releases/download/v${version}/${archive}',
            install,
        )
        self.assertIn(
            "curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output \"$RUNNER_TEMP/$archive\"",
            install,
        )
        self.assertIn("sha256sum --check --strict", install)
        self.assertIn(
            'tar -xzf "$RUNNER_TEMP/$archive" -C "$RUNNER_TEMP" gitleaks',
            install,
        )

    def test_coverage_helper_deduplicates_overlapping_source_lines(self) -> None:
        script = embedded_python(
            self.gate_steps["Enforce line coverage threshold"]["run"],
            "COVERAGE_ENFORCEMENT_PYTHON",
        )
        result = run_python(
            script,
            [str(FIXTURES / "coverage-overlap-inflation"), "40"],
        )
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("33.33%", result.stdout)

    def test_coverage_helper_treats_any_hit_for_same_line_as_covered(self) -> None:
        script = embedded_python(
            self.gate_steps["Enforce line coverage threshold"]["run"],
            "COVERAGE_ENFORCEMENT_PYTHON",
        )
        result = run_python(
            script,
            [str(FIXTURES / "coverage-overlap-any-hit"), "50"],
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("50.00%", result.stdout)

    def test_format_and_gitleaks_are_independent_non_cancelled_checks(self) -> None:
        formatting = self.gate_steps["Verify formatting"].get("if", "")
        install = self.gate_steps["Install checksum-verified Gitleaks"].get("if", "")
        scan = self.gate_steps["Scan repository history for secrets"].get("if", "")
        self.assertIn("!cancelled()", formatting)
        self.assertIn("steps.restore.outcome == 'success'", formatting)
        self.assertEqual("${{ !cancelled() }}", install)
        self.assertIn("!cancelled()", scan)
        self.assertIn("steps.checkout.outcome == 'success'", scan)
        self.assertIn("steps.gitleaks-install.outcome == 'success'", scan)

    def test_gate_only_caches_nuget_and_always_uploads_bounded_evidence(self) -> None:
        cache_steps = [step for step in steps(self.gate) if step.get("uses", "").startswith("actions/cache@")]
        self.assertEqual(1, len(cache_steps))
        cache = cache_steps[0].get("with", {})
        self.assertEqual("~/.nuget/packages", cache.get("path"))
        self.assertIn("hashFiles", cache.get("key", ""))
        self.assertNotRegex(cache.get("path", "").lower(), r"(^|/)(bin|obj)(/|$)")

        upload = self.gate_steps["Upload test, coverage, and audit evidence"]
        self.assertEqual("${{ always() }}", upload.get("if"))
        self.assertEqual("${{ github.workspace }}/ci-results", self.gate["jobs"]["validate"]["env"].get("RESULTS_DIRECTORY"))
        self.assertEqual("ci-results/", upload["with"].get("path"))
        self.assertEqual("error", upload["with"].get("if-no-files-found"))
        self.assertFalse(upload["with"].get("include-hidden-files", "false") == "true")
        self.assertEqual("${{ inputs.artifact-retention-days }}", upload["with"].get("retention-days"))
        retention = self.gate["on"]["workflow_call"]["inputs"]["artifact-retention-days"]
        self.assertEqual("number", retention.get("type"))
        self.assertEqual("7", retention.get("default"))

    def test_codeql_has_only_the_additional_permission_it_needs(self) -> None:
        self.assertEqual(
            {"contents": "read", "security-events": "write"},
            self.codeql.get("permissions"),
        )
        action_names = {step.get("uses", "").split("@", 1)[0] for step in steps(self.codeql)}
        self.assertIn("github/codeql-action/init", action_names)
        self.assertIn("github/codeql-action/analyze", action_names)

    def test_repository_ownership_and_operating_docs_exist(self) -> None:
        codeowners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        self.assertIn("@MALIEV-Co-Ltd/core-developers", codeowners)
        for relative in ("README.md", "SECURITY.md", "AGENTS.md"):
            content = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("Legacy.Maliev.Workflows", content)
            self.assertRegex(content, r"(?i)commit SHA")
            self.assertRegex(content, r"(?i)secret")

    def test_operating_docs_describe_live_self_validation_and_release_evidence(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("Repository self-validation", readme)
        self.assertIn("-ActionlintPath", readme)
        self.assertIn("live local reusable-workflow calls", readme)
        self.assertIn("-ActionlintPath", agents)
        self.assertIn("self-validation", security.lower())
        self.assertRegex(readme, r"(?i)release.*commit SHA")
        self.assertIn(
            "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/10.0/releases.json",
            readme,
        )
        self.assertIn(
            "introducing pull request can discover the workflow from its pull request merge ref",
            readme,
        )
        self.assertIn("Actions UI or API may list zero runs", readme)
        self.assertIn("push to `develop` is deterministic", readme)
        self.assertIn("actual live run is required before release", readme)
        self.assertIn("`ci-results/`", readme)
        self.assertIn("fails if required evidence is absent", readme)


if __name__ == "__main__":
    unittest.main(verbosity=2)
