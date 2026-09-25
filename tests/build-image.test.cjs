const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const { mkdtempSync, readFileSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");
const { test } = require("node:test");
const yaml = require("js-yaml");

const workflow = yaml.load(
	readFileSync(".github/workflows/build-image.yaml", "utf8"),
);
const script = workflow.jobs["build-ecr-bake"].steps.find(
	(step) => step.name === "Build images with Docker Bake",
).run;
const indexType = "application/vnd.oci.image.index.v1+json";
const imageType = "application/vnd.oci.image.manifest.v1+json";
const indexDigest = `sha256:${"a".repeat(64)}`;
const imageDigest = `sha256:${"b".repeat(64)}`;
const image = {
	mediaType: imageType,
	digest: imageDigest,
	platform: { os: "linux", architecture: "amd64" },
};
const attestation = {
	mediaType: imageType,
	digest: `sha256:${"c".repeat(64)}`,
	annotations: { "vnd.docker.reference.type": "attestation-manifest" },
};

for (const [name, manifest, expectedDigest] of [
	[
		"OCI index with provenance",
		{ mediaType: indexType, manifests: [attestation, image] },
		imageDigest,
	],
	[
		"Docker manifest list",
		{
			mediaType:
				"application/vnd.docker.distribution.manifest.list.v2+json",
			manifests: [image],
		},
		imageDigest,
	],
	["direct OCI image", { mediaType: imageType }, indexDigest],
	[
		"direct Docker image",
		{ mediaType: "application/vnd.docker.distribution.manifest.v2+json" },
		indexDigest,
	],
	[
		"multiple runtime platforms",
		{
			mediaType: indexType,
			manifests: [
				image,
				{ ...image, platform: { os: "linux", architecture: "arm64" } },
			],
		},
		null,
	],
	[
		"attestation only",
		{ mediaType: indexType, manifests: [attestation] },
		null,
	],
	["unsupported manifest", { mediaType: "unsupported" }, null],
]) {
	test(name, (t) => {
		const directory = mkdtempSync(join(tmpdir(), "ci-image-tags-"));
		t.after(() => rmSync(directory, { recursive: true }));
		const result = spawnSync(
			"bash",
			[
				"-c",
				`
      aws() { return 0; }
      docker() {
        printf '%s\\n' "$*" >> "$RUNNER_TEMP/docker.log"
        case "$1 $2 $3" in
          "buildx bake -f") printf '%s' "$METADATA_JSON" > "$RUNNER_TEMP/bake-metadata.json" ;;
          "buildx imagetools inspect") printf '%s' "$MANIFEST_JSON" ;;
          "buildx imagetools create") ;;
          *) return 1 ;;
        esac
      }
      ${script}
    `,
			],
			{
				encoding: "utf8",
				env: {
					...process.env,
					APP_NAME: "app",
					BAKE_FILE: "docker-bake.hcl",
					ENVIRONMENT: "test",
					GITHUB_SHA: "commit-sha",
					IMAGE_TARGETS:
						'["web", {"target":"worker", "imageTarget":"default"}]',
					REGISTRY: "registry.example.invalid",
					NPM_GITHUB_TOKEN: "",
					VERSION: "v1",
					RUNNER_TEMP: directory,
					MANIFEST_JSON: JSON.stringify(manifest),
					METADATA_JSON: JSON.stringify({
						web: { "containerimage.digest": indexDigest },
						worker: { "containerimage.digest": indexDigest },
					}),
				},
			},
		);
		assert.ifError(result.error);
		assert.equal(
			result.status,
			expectedDigest === null ? 5 : 0,
			result.stderr,
		);
		const commands = readFileSync(join(directory, "docker.log"), "utf8")
			.trim()
			.split("\n");
		assert.match(commands[0], /--metadata-file /);
		assert.doesNotMatch(commands[0], /:latest/);
		const creates = commands.filter((command) =>
			command.startsWith("buildx imagetools create "),
		);
		if (expectedDigest === null) {
			assert.equal(creates.length, 0);
		} else {
			for (const [target, repository] of [
				["web", "app-web"],
				["worker", "app-default"],
			]) {
				const ref = `registry.example.invalid/${repository}`;
				assert.ok(commands[0].includes(`${target}.tags=${ref}:v1`));
				assert.ok(
					commands[0].includes(`${target}.tags=${ref}:commit-sha`),
				);
				assert.ok(
					commands.includes(
						`buildx imagetools inspect --raw ${ref}@${indexDigest}`,
					),
				);
				assert.ok(
					creates.includes(
						`buildx imagetools create --prefer-index=false --tag ${ref}:latest ${ref}@${expectedDigest}`,
					),
				);
			}
			assert.equal(creates.length, 2);
		}
	});
}
