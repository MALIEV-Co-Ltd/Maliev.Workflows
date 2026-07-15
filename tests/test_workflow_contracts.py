#!/usr/bin/env python3
"""Security contract tests for MALIEV reusable workflows."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SHA_REF = re.compile(r"^[^\s@]+@[0-9a-f]{40}(?:\s+#\s+v?\S+)?$")


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


class WorkflowContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gate_path = WORKFLOWS / "dotnet-pr-gate.yml"
        cls.codeql_path = WORKFLOWS / "codeql-dotnet.yml"
        cls.gate = load_yaml(cls.gate_path)
        cls.codeql = load_yaml(cls.codeql_path)

    def test_all_yaml_files_parse(self) -> None:
        yaml_files = sorted((ROOT / ".github").rglob("*.yml"))
        self.assertGreaterEqual(len(yaml_files), 3)
        for path in yaml_files:
            with self.subTest(path=path.relative_to(ROOT)):
                load_yaml(path)

    def test_workflows_are_reusable_only_and_do_not_accept_secrets(self) -> None:
        allowed_gate_inputs = {
            "target-path",
            "working-directory",
            "dotnet-version",
            "configuration",
            "coverage-threshold",
            "artifact-retention-days",
        }
        for workflow, allowed_inputs in (
            (self.gate, allowed_gate_inputs),
            (self.codeql, {"target-path", "working-directory", "dotnet-version"}),
        ):
            trigger = workflow.get("on", {})
            self.assertEqual({"workflow_call"}, set(trigger))
            call = trigger["workflow_call"] or {}
            self.assertNotIn("secrets", call)
            self.assertEqual(allowed_inputs, set(call.get("inputs", {})))
            for name, spec in call.get("inputs", {}).items():
                self.assertIn(spec.get("type"), {"string", "number", "boolean"}, name)

    def test_gate_is_read_only_bounded_and_cancels_superseded_runs(self) -> None:
        self.assertEqual({"contents": "read"}, self.gate.get("permissions"))
        concurrency = self.gate.get("concurrency", {})
        self.assertEqual("true", concurrency.get("cancel-in-progress"))
        self.assertIn("github.workflow", concurrency.get("group", ""))
        for name, job in self.gate["jobs"].items():
            timeout = int(job.get("timeout-minutes", "0"))
            self.assertGreater(timeout, 0, name)
            self.assertLessEqual(timeout, 60, name)

    def test_all_actions_are_immutable_and_checkout_is_read_only(self) -> None:
        for workflow in (self.gate, self.codeql):
            for step in steps(workflow):
                if "uses" in step:
                    self.assertRegex(step["uses"], SHA_REF)
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertEqual("false", step.get("with", {}).get("persist-credentials"))
                    if workflow is self.gate:
                        self.assertEqual("0", step.get("with", {}).get("fetch-depth"))

    def test_gate_commands_cover_the_required_dotnet_and_secret_checks(self) -> None:
        commands = "\n".join(step.get("run", "") for step in steps(self.gate))
        required = (
            "dotnet restore",
            "dotnet build",
            "--no-restore",
            "dotnet test",
            "--collect:\"XPlat Code Coverage\"",
            "dotnet format",
            "--verify-no-changes",
            "--vulnerable",
            "--deprecated",
            "--include-transitive",
            "lines-covered",
            "gitleaks-bin\" detect",
        )
        for expected in required:
            with self.subTest(expected=expected):
                self.assertIn(expected, commands)
        for step in steps(self.gate):
            self.assertNotRegex(step.get("run", ""), r"\$\{\{\s*inputs\.")

    def test_inputs_are_validated_before_untrusted_source_is_checked_out(self) -> None:
        for workflow in (self.gate, self.codeql):
            workflow_steps = steps(workflow)
            self.assertEqual("Validate bounded inputs", workflow_steps[0].get("name"))
            validation = workflow_steps[0].get("run", "")
            self.assertIn("repository-relative", validation)
            self.assertIn("DOTNET_VERSION", validation)
            checkout_index = next(
                index
                for index, step in enumerate(workflow_steps)
                if step.get("uses", "").startswith("actions/checkout@")
            )
            self.assertGreater(checkout_index, 0)

    def test_no_dangerous_expression_or_secret_surfaces_exist(self) -> None:
        forbidden_inputs = {"command", "script", "runner", "token", "secret", "action-ref"}
        for workflow in (self.gate, self.codeql):
            serialized = repr(workflow).lower()
            self.assertNotIn("secrets: inherit", serialized)
            self.assertNotIn("pull_request_target", serialized)
            inputs = workflow["on"]["workflow_call"].get("inputs", {})
            self.assertTrue(forbidden_inputs.isdisjoint(inputs))
            for job in workflow["jobs"].values():
                self.assertNotIn("permissions", job)

    def test_gate_only_caches_nuget_and_always_uploads_bounded_evidence(self) -> None:
        cache_steps = [s for s in steps(self.gate) if s.get("uses", "").startswith("actions/cache@")]
        self.assertEqual(1, len(cache_steps))
        cache = cache_steps[0].get("with", {})
        self.assertEqual("~/.nuget/packages", cache.get("path"))
        self.assertIn("hashFiles", cache.get("key", ""))
        self.assertNotIn("bin", cache.get("path", "").lower())
        self.assertNotIn("obj", cache.get("path", "").lower())

        uploads = [s for s in steps(self.gate) if s.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual(1, len(uploads))
        self.assertEqual("${{ always() }}", uploads[0].get("if"))
        self.assertEqual("${{ inputs.artifact-retention-days }}", uploads[0]["with"].get("retention-days"))

    def test_codeql_has_only_the_additional_permission_it_needs(self) -> None:
        self.assertEqual(
            {"contents": "read", "security-events": "write"},
            self.codeql.get("permissions"),
        )
        used = "\n".join(step.get("uses", "") for step in steps(self.codeql))
        self.assertIn("github/codeql-action/init@", used)
        self.assertIn("github/codeql-action/analyze@", used)

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
