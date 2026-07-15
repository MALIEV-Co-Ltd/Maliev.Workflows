# Maliev.Workflows

Reusable, least-privilege CI workflows for the current MALIEV platform fleet. This public repository is the reviewable distribution point for current-platform workflow code; `Legacy.Maliev.Workflows` remains a separate compatibility surface for legacy fresh-history repositories.

## Available workflows

- `.github/workflows/dotnet-pr-gate.yml` restores, audits, builds, tests with a line-coverage threshold, verifies formatting, scans history with a checksum-verified Gitleaks binary, and uploads bounded evidence.
- `.github/workflows/codeql-dotnet.yml` performs a manual C# CodeQL build and analysis under the additional `security-events: write` permission that CodeQL requires.

Both workflows are reusable through `workflow_call` only. They accept typed, validated inputs and no secrets. The baseline deliberately cannot restore private packages. Repositories that require private dependencies must produce an exact dependency artifact in a separate trusted job without broadening this workflow's trust boundary.

## Consuming a workflow

Pin the call to a reviewed full commit SHA, never a branch or mutable tag:

```yaml
jobs:
  validate:
    uses: MALIEV-Co-Ltd/Maliev.Workflows/.github/workflows/dotnet-pr-gate.yml@0123456789abcdef0123456789abcdef01234567
    with:
      target-path: Maliev.Example.slnx
      dotnet-version: 10.0.x
      configuration: Release
      coverage-threshold: 80
      artifact-retention-days: 7
```

Do not add `secrets: inherit`. Callers should declare only `contents: read` for the PR gate. CodeQL callers must grant `contents: read` and `security-events: write`.

## Validation and versioning

Run the repository contract suite locally:

```powershell
pwsh ./tests/validate.ps1
```

The entry point parses repository YAML, runs the security contract tests, and runs `actionlint` when it is installed. Workflow releases are immutable commit SHAs. Dependabot proposes action-pin updates for review; a pin is changed only after contract validation and release-note review.
