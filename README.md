# Maliev.Workflows

Reusable, least-privilege CI workflows for the current MALIEV platform fleet. This public repository is the reviewable distribution point for current-platform workflow code; `Legacy.Maliev.Workflows` remains a separate compatibility surface for legacy fresh-history repositories.

## Available workflows

- `.github/workflows/dotnet-pr-gate.yml` restores, audits, builds, tests with a line-coverage threshold, verifies formatting, scans history with a checksum-verified Gitleaks binary, and uploads bounded evidence.
- `.github/workflows/codeql-dotnet.yml` performs a manual C# CodeQL build and analysis under the additional `security-events: write` permission that CodeQL requires.
- `.github/workflows/self-validate.yml` validates this repository on pull requests and pushes to `develop` or `main`, then makes live local reusable-workflow calls against the checked-in .NET 10 smoke fixture.

The .NET gate and CodeQL workflows are reusable through `workflow_call` only. They accept typed, validated inputs and no secrets. The baseline deliberately cannot restore private packages. Repositories that require private dependencies must produce an exact dependency artifact in a separate trusted job without broadening this workflow's trust boundary.

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

### Repository self-validation

Use the reviewed actionlint v1.7.12 binary from its checksum-verified release artifact, then run the complete repository contract suite locally:

```powershell
pwsh ./tests/validate.ps1 -ActionlintPath C:\path\to\actionlint.exe
```

The entry point parses every repository workflow YAML file, runs the Python security contracts, requires the supplied actionlint binary, and verifies the diff. The caller additionally installs hash-locked Python dependencies, scans the complete checkout with checksum-verified Gitleaks, and executes both reusable workflows against the deterministic smoke fixture.

The .NET gate writes package audits, test results, and coverage into the visible `ci-results/` workspace directory. Artifact upload is required evidence and fails if required evidence is absent; it never degrades to a warning-only successful run.

The smoke fixture pins SDK `10.0.302` with roll-forward disabled. That version was verified against Microsoft's official [.NET 10 release metadata](https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/10.0/releases.json). Pull-request validation checks `base...head`; push validation checks `before...after`, with an empty-tree fallback for a new branch push.

An ordinary introducing pull request can discover the workflow from its pull request merge ref. Actions UI or API may list zero runs while the default `main` branch does not yet contain the workflow, so a push to `develop` is deterministic proof of the checked-in caller. An actual live run is required before release. Real fork and Dependabot pull requests still run CodeQL analysis but deliberately skip SARIF upload because their tokens cannot receive `security-events: write`; same-repository human pull requests and pushes upload normally.

Workflow releases are immutable commit SHAs. A release commit SHA is eligible for consumers only after all three repository self-validation jobs are green. Record those run URLs and the reviewed commit SHA as release evidence before updating consumer pins. Dependabot proposes action-pin updates for review; a pin changes only after contract validation and release-note review.
