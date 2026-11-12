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

## Staging configuration from a feature branch

`kubernetes.yaml` accepts `stagingDeploymentRepoRef` to select the GitOps configuration
revision for staging. When the deployment repository is the application repository,
pass the deployment SHA to use the chart and values from the same commit as the code:

```yaml
uses: parcelLab/ci/.github/workflows/kubernetes.yaml@v9
with:
  deploymentRepoURL: parcelLab/backend
  deploymentRepoPath: .chart/${{ github.event.deployment.payload.env }}
  stagingDeploymentRepoRef: ${{ github.event.deployment.sha }}
```

This requires `pushToEnvTag: true` in the deployment payload or Kubernetes workflow
inputs. The workflow updates the image version on top of the selected revision and
pushes the `staging` tag, which ArgoCD must track. It fails before building if tag
publishing is disabled, to prevent pushing feature branch configuration to `main`.
The ref must exist in `deploymentRepoURL`; it does not select a revision in a
separate infrastructure repository or change the application build revision.

An empty ref keeps staging configuration on `main`. The input is ignored for all
other environments, including production and weekly production rebuilds.

## Contributing

[Contribution guidelines](CONTRIBUTING.md)
