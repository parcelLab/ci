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

## Contributing

[Contribution guidelines](CONTRIBUTING.md)
