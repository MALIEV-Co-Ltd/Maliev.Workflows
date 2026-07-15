# Agent guidance

This public repository owns reusable CI security controls for the current MALIEV platform. `Legacy.Maliev.Workflows` remains isolated for legacy fresh-history repositories; do not copy changes between the two without an explicit compatibility review.

## Change rules

- Keep reusable validation workflows secretless and least privilege.
- Expose only typed, bounded inputs. Never accept arbitrary commands, runners, action references, token names, or secrets.
- Pin every action and every consumer reference to a reviewed full commit SHA.
- Treat permissions, input validation, checkout credential persistence, artifact retention, timeouts, and concurrency as tested contracts.
- Add or update a failing contract test before changing workflow behavior.
- Run `pwsh ./tests/validate.ps1` and `git diff --check` before committing.

Version workflow behavior through immutable commit SHAs. Document breaking input or output changes in the pull request and coordinate consumer updates before merging.
