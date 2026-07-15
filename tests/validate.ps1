#!/usr/bin/env pwsh
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ActionlintPath
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    python -c "import yaml" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw 'PyYAML is required for repository validation. Install it with your managed Python environment.'
    }

    python tests/test_workflow_contracts.py
    if ($LASTEXITCODE -ne 0) {
        throw 'Workflow contract tests failed.'
    }

    if (-not (Test-Path -LiteralPath $ActionlintPath -PathType Leaf)) {
        throw "The reviewed actionlint binary does not exist: $ActionlintPath"
    }

    & $ActionlintPath -color
    if ($LASTEXITCODE -ne 0) {
        throw 'actionlint failed.'
    }

    git diff --check
    if ($LASTEXITCODE -ne 0) {
        throw 'git diff --check failed.'
    }
}
finally {
    Pop-Location
}
