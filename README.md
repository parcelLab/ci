# CI Pipelines

[![Github workflows](https://github.com/parcelLab/ci/actions/workflows/ci.github-workflows.yaml/badge.svg)](https://github.com/parcelLab/ci/actions/workflows/ci.github-workflows.yaml)
[![JSON](https://github.com/parcelLab/ci/actions/workflows/ci.json.yaml/badge.svg)](https://github.com/parcelLab/ci/actions/workflows/ci.json.yaml)
[![YAML](https://github.com/parcelLab/ci/actions/workflows/ci.yaml.yaml/badge.svg)](https://github.com/parcelLab/ci/actions/workflows/ci.yaml.yaml)

The intention of this repository is to be public, in order to share what we consider
good CI/CD practices to the community.

While the structure is very much solving parcelLab's unique use cases, the files here could be reused by anybody else as they do not have any business logic attached.

## Weekly production rebuilds

Call `deployment.yaml` on a schedule with `env: prod` and `rebuildProduction: true` to rebuild
the release tag or commit in `.chart/prod/values.yaml` (at the `prod` tag with `pushToEnvTag`, else `main`)
with fresh base images and no cache. It deploys as `rebuild-<run-id>.<attempt>-<release>` and is skipped
if another release reaches production first.

## Bypass audit

`bypass-audit.yaml` opens a Jira COM ticket when a push to the default branch skipped review or
required checks: a PR merged without an approval from someone other than the author or with red
required checks, a direct push, a force push, or a bot push that changes files outside
`allowedBotPushes`. The ticket is assigned to the PR author, then the merger, then the human who
triggered the bot's workflow run, else the security owner. Re-runs don't create duplicates.

```yaml
name: Bypass audit
on:
  push:
    branches: [main]
jobs:
  bypass-audit:
    uses: parcelLab/ci/.github/workflows/bypass-audit.yaml@v9
    with:
      appClientId: ${{ vars.BYPASS_AUDIT_APP_CLIENT_ID }}
      allowedBotPushes: |
        .chart/*/values*.yaml
    secrets:
      jiraToken: ${{ secrets.JIRA_GITHUB_CI_AUTOMATION }}
      appPrivateKey: ${{ secrets.BYPASS_AUDIT_APP_PRIVATE_KEY }}
```

## Contributing

[Contribution guidelines](CONTRIBUTING.md)
