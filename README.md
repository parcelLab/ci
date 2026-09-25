# CI Pipelines

[![Github workflows](https://github.com/parcelLab/ci/actions/workflows/ci.github-workflows.yaml/badge.svg)](https://github.com/parcelLab/ci/actions/workflows/ci.github-workflows.yaml)
[![JSON](https://github.com/parcelLab/ci/actions/workflows/ci.json.yaml/badge.svg)](https://github.com/parcelLab/ci/actions/workflows/ci.json.yaml)
[![YAML](https://github.com/parcelLab/ci/actions/workflows/ci.yaml.yaml/badge.svg)](https://github.com/parcelLab/ci/actions/workflows/ci.yaml.yaml)

The intention of this repository is to be public, in order to share what we consider
good CI/CD practices to the community.

While the structure is very much solving parcelLab's unique use cases, the files here could be reused by anybody else as they do not have any business logic attached.

## ECR Image Tags

Docker Bake builds retain the version and Git SHA tags on their original image indexes,
including build attestations. The `latest` tag points directly to the single runtime
image manifest so Amazon Inspector findings carry that tag. Attestations remain
available through the version/SHA references, not through `latest`.

Bake targets with multiple runtime platforms fail rather than selecting one for
`latest`. Existing images are not retagged; this takes effect on subsequent builds.

## Contributing

[Contribution guidelines](CONTRIBUTING.md)
