# CI Pipelines

[![Github workflows](https://github.com/parcelLab/ci/actions/workflows/ci.github-workflows.yaml/badge.svg)](https://github.com/parcelLab/ci/actions/workflows/ci.github-workflows.yaml)
[![JSON](https://github.com/parcelLab/ci/actions/workflows/ci.json.yaml/badge.svg)](https://github.com/parcelLab/ci/actions/workflows/ci.json.yaml)
[![YAML](https://github.com/parcelLab/ci/actions/workflows/ci.yaml.yaml/badge.svg)](https://github.com/parcelLab/ci/actions/workflows/ci.yaml.yaml)

The intention of this repository is to be public, in order to share what we consider
good CI/CD practices to the community.

While the structure is very much solving parcelLab's unique use cases, the files here could be reused by anybody else as they do not have any business logic attached.

## Weekly production rebuilds

A scheduled caller can set `rebuildProduction: true` on `deployment.yaml`, with
`env: prod` and the application's usual deployment inputs. This supports apps whose
production image version is in `.chart/prod/values.yaml` in the same repository:
at the `prod` tag when `pushToEnvTag` is true, otherwise on `main`.

The workflow finds a successful deployment matching that image version and rebuilds
its recorded source SHA through the application's existing deployment workflow.
It pulls base images, bypasses build caches, and publishes a unique
`<release>-rebuild-<run-id>-<attempt>` image tag. Original release, SHA and `latest`
tags are preserved. Pinned base digests and locked dependencies still require source updates.

GitOps keeps the current production configuration and changes its image version.
The deployment fails if that configuration changed during the build; tag updates
also use a Git lease to prevent overwriting a concurrent deployment. Production
deployment success still means GitOps was updated, not that Argo finished rollout.

Publish this shared workflow support in `v9` before merging scheduled callers.
The production release's deployment consumer must use that updated `v9`; a
Containerfile migration takes effect only after it is included in a production release.
Local regression checks: `python3 test/rebuild-production.py` (requires `yq`, `jq`, Git and Bash).

## Contributing

[Contribution guidelines](CONTRIBUTING.md)
