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

## Scheduled container vulnerability reports

`container-security.yaml` rebuilds each image from source without cache and scans it with Trivy
(OS and library packages, every severity, unfixed included). JSON and SARIF reports are uploaded
as artifacts and summarized in the run summary. Findings never fail the run; build, scan and
reporting errors do.

With `openPullRequest: true` on the default branch, it keeps one findings PR open from
`automation/container-security-report` while HIGH or CRITICAL findings exist, listing installed
and fixed versions, the advisory date and when each finding first appeared. Unchanged findings
add no commits. When the findings are resolved, it records the clean scan and closes the PR.

It refuses to run in a public repository, where the findings would be public, unless
`allowPublicRepository: true` is set. Past reports stay in the `automation/container-security-report`
branch and in closed findings PRs, so delete that branch, and any report files merged from it, before
making a repository public.

Run it on a schedule, since new advisories affect unchanged images:

```yaml
on:
  schedule:
    - cron: "0 5 * * *"
  workflow_dispatch:
concurrency:
  group: container-security
  cancel-in-progress: false
jobs:
  container-security:
    uses: parcelLab/ci/.github/workflows/container-security.yaml@v9
    permissions:
      contents: write
      pull-requests: write
    with:
      openPullRequest: true
```

GitHub requests review on the findings PR from the code owners of its files when it opens. To
route it to one person rather than a team-wide catch-all rule, add a `CODEOWNERS` entry:

```text
/docs/reports/container-security* @<github-user>
```

GitHub does not request review again when later scans update the PR, and it skips code owners
without write access instead of failing the run.

By default it builds `Containerfile` in the repository root. For other or several images, pass
`images`, for example `'[{"name": "api", "file": "api/Containerfile", "context": "api", "target": "runtime"}]'`.
Builds get no build arguments or registry credentials, so private base images are not supported.
PRs opened with `GITHUB_TOKEN` do not trigger other workflows, so CI on the findings PR has to be
started by hand.

To test changes locally with [act](https://github.com/nektos/act) from a calling repository, map
this repository to your checkout, both at the ref the caller uses and at `@v9`, which the workflow
uses for its action:

```sh
act workflow_dispatch -W .github/workflows/container-security.yaml \
  --local-repository parcelLab/ci@<ref>=<path-to-this-checkout> \
  --local-repository parcelLab/ci@v9=<path-to-this-checkout> \
  --container-architecture linux/amd64 --artifact-server-path /tmp/act-artifacts
```

## Contributing

[Contribution guidelines](CONTRIBUTING.md)
