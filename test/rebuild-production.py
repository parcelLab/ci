"""Run workflow scripts locally with no GitHub, AWS, or Docker operations."""

import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def workflow_script(workflow: str, job: str, step: str) -> str:
    result = subprocess.run(
        [
            "yq",
            "-o=json",
            f'.jobs.{job}.steps[] | select(.name == "{step}") | .run',
            str(ROOT / ".github/workflows" / workflow),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    script = json.loads(result.stdout)
    assert isinstance(script, str)
    return script


def stub(directory: Path, name: str, script: str) -> None:
    command = directory / name
    command.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + script)
    command.chmod(0o755)


def check_gitops() -> None:
    guard = workflow_script(
        "kubernetes.yaml", "commit", "Require unchanged production configuration"
    )
    push = workflow_script("kubernetes.yaml", "commit", "Commit and push new image tag")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        origin = root / "origin.git"
        seed = root / "seed"

        def git(cwd: Path, *args: str) -> str:
            return subprocess.run(
                ["git", *args],
                cwd=cwd,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

        git(root, "init", "--bare", str(origin))
        git(root, "init", "-b", "main", str(seed))
        git(seed, "config", "user.name", "Test")
        git(seed, "config", "user.email", "test@example.invalid")
        (seed / "values.yaml").write_text("version: v1\nconfig: production\n")
        git(seed, "add", ".")
        git(seed, "commit", "-m", "production")
        git(seed, "tag", "-a", "prod", "-m", "production")
        original = git(seed, "rev-parse", "HEAD")
        git(seed, "remote", "add", "origin", str(origin))
        git(seed, "push", "origin", "main", "refs/tags/prod")
        (seed / "unreleased.txt").write_text("Do not promote through a rebuild\n")
        git(seed, "add", ".")
        git(seed, "commit", "-m", "unreleased")
        git(seed, "push", "origin", "main")
        attempts: list[tuple[Path, dict[str, str]]] = []
        for name in ["winner", "late"]:
            directory = root / name
            directory.mkdir()
            git(directory, "clone", "--branch", "prod", str(origin), "remote")
            env = os.environ | {
                "EXPECTED_COMMIT": original,
                "PUSH_TO_ENV_TAG": "true",
                "GITHUB_OUTPUT": str(directory / "output"),
                "ENV": "prod",
                "VERSION": "v1-rebuild-" + name,
                "GIT_USER_NAME": "Test",
                "GIT_USER_EMAIL": "test@example.invalid",
            }
            subprocess.run(
                ["bash", "-c", guard], cwd=directory / "remote", env=env, check=True
            )
            tag = (directory / "output").read_text().strip().split("=", 1)[1]
            assert tag != original, "Lease must use the annotated tag object"
            env["EXPECTED_TAG_OBJECT"] = tag
            assert not (directory / "remote/unreleased.txt").exists()
            (directory / "remote/values.yaml").write_text(
                f"version: {env['VERSION']}\nconfig: production\n"
            )
            attempts.append((directory, env))
        for index, (directory, env) in enumerate(attempts):
            result = subprocess.run(
                ["bash", "-c", push],
                cwd=directory,
                env=env,
                capture_output=True,
                text=True,
            )
            if index == 0:
                assert result.returncode == 0, result.stderr
            else:
                assert result.returncode != 0 and "stale info" in result.stderr
            contents = git(root, "--git-dir", str(origin), "show", "prod:values.yaml")
            assert "version: v1-rebuild-winner" in contents
        env["EXPECTED_COMMIT"] = "0" * 40
        result = subprocess.run(
            ["bash", "-c", guard],
            cwd=directory / "remote",
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0 and "refusing to deploy" in result.stderr


def main() -> None:
    resolver = workflow_script(
        "deployment.yaml", "kubernetes", "Resolve the successful production deployment"
    )
    bake = workflow_script(
        "build-image.yaml", "build-ecr-bake", "Build images with Docker Bake"
    )
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        output = directory / "output"
        env = os.environ | {
            "PATH": f"{directory}:{os.environ['PATH']}",
            "FIXTURES": temporary,
            "RUNNER_TEMP": temporary,
            "GITHUB_OUTPUT": str(output),
            "GITHUB_REPOSITORY": "parcelLab/example",
            "GITHUB_RUN_ID": "1234",
            "GITHUB_RUN_ATTEMPT": "2",
            "APP_NAME": "example",
            "CURRENT_VERSION": "v1.2.3",
            "EXPECTED_GITOPS": "c" * 40,
            "API_FAILURE": "",
            "GITHUB_SHA": "b" * 40,
        }
        stub(
            directory,
            "git",
            '[[ "$*" == "rev-parse HEAD" ]]\nprintf "%s\\n" "$EXPECTED_GITOPS"\n',
        )
        stub(
            directory,
            "gh",
            r"""
endpoint=${3%%\?*}
if [[ "$endpoint" == */statuses ]]; then
  if [[ "$API_FAILURE" == statuses ]]; then exit 24; fi
  id=${endpoint%/statuses}
  jq -r "$5" "$FIXTURES/${id##*/}.json"
else
  if [[ "$API_FAILURE" == list ]]; then exit 23; fi
  cat "$FIXTURES/deployments.json"
fi
""",
        )
        deployments = [
            {
                "id": 1,
                "ref": "refs/tags/v1.2.3",
                "sha": "1" * 40,
                "payload": {"name": "other"},
            },
            {
                "id": 4,
                "ref": "refs/tags/v9.9.9",
                "sha": "4" * 40,
                "payload": {"name": "example"},
            },
            {
                "id": 2,
                "ref": "refs/tags/v1.2.3",
                "sha": "2" * 40,
                "payload": {"name": "example"},
            },
            {
                "id": 3,
                "ref": "refs/tags/v1.2.3",
                "sha": "a" * 40,
                "payload": {"name": "example"},
            },
        ]
        (directory / "2.json").write_text(
            json.dumps([{"id": 20, "state": "in_progress"}])
        )
        (directory / "3.json").write_text(
            json.dumps(
                [
                    {"id": 31, "state": "inactive"},
                    {"id": 30, "state": "success"},
                ]
            )
        )

        def resolve() -> subprocess.CompletedProcess[str]:
            output.write_text("")
            (directory / "deployments.json").write_text(json.dumps(deployments))
            return subprocess.run(
                ["bash", "-c", resolver], env=env, capture_output=True, text=True
            )

        result = resolve()
        assert result.returncode == 0, result.stderr
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        assert values["ref"] == "a" * 40
        metadata = json.loads(values["metadata"])
        assert metadata == {
            "version": "v1.2.3-rebuild-1234-2",
            "release": "v1.2.3",
            "expectedGitOpsCommit": "c" * 40,
        }

        deployments = [
            {
                "id": 3,
                "ref": "a" * 40,
                "sha": "a" * 40,
                "payload": {"name": "example", "rebuild": metadata},
            }
        ]
        env.update(CURRENT_VERSION=metadata["version"], GITHUB_RUN_ID="5678")
        result = resolve()
        assert result.returncode == 0, result.stderr
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        assert values["ref"] == "a" * 40
        metadata = json.loads(values["metadata"])
        assert metadata["release"] == "v1.2.3"
        assert metadata["version"] == "v1.2.3-rebuild-5678-2"

        for failure, code in [("list", 23), ("statuses", 24)]:
            env["API_FAILURE"] = failure
            assert resolve().returncode == code
            assert output.read_text() == ""
        env["API_FAILURE"] = ""
        (directory / "3.json").write_text('[{"id": 32, "state": "failure"}]')
        result = resolve()
        assert result.returncode != 0
        assert "No successful production deployment matches" in result.stderr
        assert output.read_text() == ""

        stub(directory, "aws", "exit 0\n")
        stub(directory, "docker", 'printf "%s\\n" "$@" > "$DOCKER_ARGS"\n')
        env.update(
            BAKE_FILE="docker-bake.hcl",
            ENVIRONMENT="prod",
            REGISTRY="registry.example",
            IMAGE_TARGETS='[{"target":"backend","imageTarget":"default"},"web"]',
            NPM_GITHUB_TOKEN="unused",
            VERSION="v1.2.3-rebuild-5678-2",
            DOCKER_ARGS=str(directory / "docker-args"),
        )
        for rebuild in ["true", "false"]:
            env["REBUILD"] = rebuild
            result = subprocess.run(
                ["bash", "-c", bake], env=env, capture_output=True, text=True
            )
            assert result.returncode == 0, result.stderr
            args = (directory / "docker-args").read_text().splitlines()
            assert args[:5] == ["buildx", "bake", "-f", "docker-bake.hcl", "--push"]
            assert ("--pull" in args) == (rebuild == "true")
            assert ("--no-cache" in args) == (rebuild == "true")
            assert args[-2:] == ["backend", "web"]
            for target, image in [("backend", "default"), ("web", "web")]:
                prefix = f"{target}.tags=registry.example/example-{image}:"
                tags = {
                    argument
                    for argument in args
                    if argument.startswith(f"{target}.tags=")
                }
                expected = {prefix + env["VERSION"]}
                if rebuild == "false":
                    expected.update({prefix + "latest", prefix + env["GITHUB_SHA"]})
                assert tags == expected, tags
    check_gitops()
    print("Production rebuild resolver, Bake and GitOps race checks passed.")


if __name__ == "__main__":
    main()
