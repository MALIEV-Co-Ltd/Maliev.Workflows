#!/usr/bin/env pwsh
[CmdletBinding()]
param()

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

    $actionlint = Get-Command actionlint -ErrorAction SilentlyContinue
    if ($null -ne $actionlint) {
        & $actionlint.Source -color
        if ($LASTEXITCODE -ne 0) {
            throw 'actionlint failed.'
        }
    }
    else {
        Write-Warning 'actionlint is not installed; contract tests and YAML parsing completed.'
    }

    git diff --check
    if ($LASTEXITCODE -ne 0) {
        throw 'git diff --check failed.'
    }
}
finally {
    Pop-Location
}
