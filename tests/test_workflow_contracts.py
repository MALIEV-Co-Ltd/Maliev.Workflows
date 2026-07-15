#!/usr/bin/env python3
"""Executable security contracts for MALIEV reusable workflows."""

from __future__ import annotations

import os
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
EXPECTED_PERMISSIONS = {
    "dotnet-pr-gate.yml": {"contents": "read"},
    "codeql-dotnet.yml": {"contents": "read", "security-events": "write"},
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

    def test_every_workflow_has_the_baseline_trigger_secret_and_permission_contract(self) -> None:
        for name, workflow in self.workflows.items():
            with self.subTest(workflow=name):
                raw = next(path for path in self.workflow_paths if path.name == name).read_text(
                    encoding="utf-8"
                ).lower()
                self.assertEqual({"workflow_call"}, set(workflow.get("on", {})))
                call = workflow["on"]["workflow_call"] or {}
                self.assertNotIn("secrets", call)
                self.assertNotIn("pull_request_target", repr(workflow).lower())
                self.assertNotIn("secrets: inherit", raw)
                self.assertNotRegex(raw, r"\$\{\{\s*secrets(?:\.|\[)")
                self.assertEqual(EXPECTED_PERMISSIONS[name], workflow.get("permissions"))
                for job_name, job in workflow.get("jobs", {}).items():
                    self.assertNotIn("permissions", job, job_name)
                    timeout = int(job.get("timeout-minutes", "0"))
                    self.assertGreater(timeout, 0, job_name)
                    self.assertLessEqual(timeout, 60, job_name)

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
            inputs = workflow["on"]["workflow_call"].get("inputs", {})
            self.assertEqual(expected[name], set(inputs))
            self.assertTrue(forbidden.isdisjoint(inputs))
            for input_name, spec in inputs.items():
                self.assertIn(spec.get("type"), {"string", "number", "boolean"}, input_name)

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
        self.assertIn("sha256sum --check --strict", install)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
