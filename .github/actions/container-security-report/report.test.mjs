import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
	parseTargets,
	prepareReport,
	renderReport,
	reportPath,
	historyPath,
} from "./report.mjs";

const vulnerability = (severity, overrides = {}) => ({
	VulnerabilityID: "CVE-2026-1234",
	PkgName: "example-package",
	InstalledVersion: "1.0",
	Severity: severity,
	...overrides,
});
const image = (vulnerabilities = []) => ({
	SchemaVersion: 2,
	ArtifactType: "container_image",
	CreatedAt: "2026-10-29T10:14:11Z",
	Results: [{ Class: "os-pkgs", Vulnerabilities: vulnerabilities }],
});
const imageName = "app";
const reports = (vulnerabilities = []) => ({
	[imageName]: image(vulnerabilities),
});

test("local preview renders the real CLI without GitHub credentials or writes", async (t) => {
	const directory = await mkdtemp(join(tmpdir(), "container-report-local-"));
	t.after(() => rm(directory, { recursive: true, force: true }));
	for (const [target, report] of Object.entries(
		reports([vulnerability("HIGH")]),
	)) {
		await writeFile(
			join(directory, `trivy-${target}.json`),
			JSON.stringify(report),
		);
	}
	const script = fileURLToPath(new URL("./report.mjs", import.meta.url));
	const output = execFileSync(
		process.execPath,
		[script, "--local", directory, "--targets", imageName],
		{
			cwd: directory,
			env: {},
			encoding: "utf8",
		},
	);
	assert.equal(
		output,
		renderReport(reports([vulnerability("HIGH")])).markdown,
	);
	await assert.rejects(readFile(join(directory, reportPath)), /ENOENT/);
	const stateFile = join(directory, "history.json");
	execFileSync(
		process.execPath,
		[script, "--local", directory, "--state-output", stateFile],
		{ env: { IMAGE_TARGETS: imageName } },
	);
	const state = JSON.parse(await readFile(stateFile, "utf8"));
	assert.equal(state.findings[0].firstFlaggedAt, "2026-10-29T10:14:11.000Z");
	assert.equal(
		execFileSync(
			process.execPath,
			[script, "--local", directory, "--history", stateFile],
			{ env: { IMAGE_TARGETS: imageName }, encoding: "utf8" },
		),
		output,
	);
});

test("includes unfixed findings and counts every severity", () => {
	const result = renderReport(
		reports([
			vulnerability("HIGH"),
			vulnerability("CRITICAL", { VulnerabilityID: "CVE-2026-5678" }),
			vulnerability("LOW", { VulnerabilityID: "CVE-2026-9012" }),
		]),
	);
	assert.equal(result.hasFindings, true);
	assert.match(result.markdown, /app \| 1 \| 1 \| 0 \| 1 \| 0/);
	assert.match(result.markdown, /No fix available/);
});

test("findings are stable across ordering, duplicates and scan provenance", () => {
	const one = vulnerability("HIGH");
	const two = vulnerability("MEDIUM", { VulnerabilityID: "CVE-2026-5678" });
	const before = reports([one, two]);
	const after = reports([two, one, one]);
	after[imageName].Metadata = { ImageID: "rebuilt-image" };
	after[imageName].CreatedAt = "2026-10-30T06:23:00Z";
	const first = renderReport(before);
	assert.equal(
		first.fingerprint,
		renderReport(after, first.history).fingerprint,
	);
	assert.notEqual(
		renderReport(before).markdown,
		renderReport(reports([{ ...one, FixedVersion: "2.0" }, two])).markdown,
	);
});

test("dates distinguish public advisory age from first flagged age and survive upgrades", () => {
	const finding = vulnerability("HIGH", {
		PublishedDate: "2026-08-13T13:17:43Z",
	});
	const first = renderReport(reports([finding]));
	assert.match(first.markdown, /2026-08-13 13:17:43Z \(76d\)/);
	assert.match(first.markdown, /2026-10-29 10:14:11Z \(0d\)/);
	const later = reports([
		{ ...finding, InstalledVersion: "1.1", Severity: "CRITICAL" },
	]);
	later[imageName].CreatedAt = "2026-10-30T10:14:11Z";
	const upgraded = renderReport(later, first.history);
	assert.match(upgraded.markdown, /2026-08-13 13:17:43Z \(77d\)/);
	assert.match(upgraded.markdown, /2026-10-29 10:14:11Z \(1d\)/);
	assert.deepEqual(upgraded.history, first.history);
	const cleared = renderReport(reports(), first.history);
	assert.deepEqual(
		renderReport(later, cleared.history).history,
		first.history,
	);
	assert.match(
		renderReport(reports([vulnerability("HIGH")])).markdown,
		/Unknown/,
	);
	assert.match(
		renderReport(
			reports([vulnerability("HIGH", { PublishedDate: "invalid" })]),
		).markdown,
		/Unknown/,
	);
	const duplicate = reports([
		finding,
		{ ...finding, PublishedDate: undefined },
	]);
	assert.equal(renderReport(duplicate).fingerprint, first.fingerprint);
});

test("invalid history fails rather than resetting first flagged dates", () => {
	for (const history of [
		{},
		{ version: 2, findings: [] },
		{
			version: 1,
			findings: [
				{
					target: imageName,
					pkg: "package",
					id: "CVE-1",
					firstFlaggedAt: "invalid",
				},
			],
		},
	]) {
		assert.throws(
			() => renderReport(reports([vulnerability("HIGH")]), history),
			/history/,
		);
	}
	const valid = renderReport(reports([vulnerability("HIGH")])).history;
	assert.throws(
		() =>
			renderReport(reports(), {
				version: 1,
				findings: [...valid.findings, ...valid.findings],
			}),
		/Duplicate/,
	);
});

test("clean and lower-severity-only scans do not request a new PR", () => {
	assert.equal(renderReport(reports()).hasFindings, false);
	assert.equal(
		renderReport(reports([vulnerability("MEDIUM")])).hasFindings,
		false,
	);
});

test("missing, unsupported and malformed reports fail rather than appearing clean", () => {
	for (const report of [
		undefined,
		{},
		{ ...image(), ArtifactType: "filesystem" },
		{ ...image(), Results: [] },
		image(null),
		image([vulnerability("unexpected")]),
	]) {
		assert.throws(() => renderReport({ [imageName]: report }));
	}
});

test("bounds the PR body, fingerprints hidden rows and fences package metadata", () => {
	const many = Array.from({ length: 120 }, (_, index) =>
		vulnerability("HIGH", { VulnerabilityID: `CVE-2026-${index}` }),
	);
	const original = renderReport(reports(many)).markdown;
	assert.ok(original.length < 50000);
	assert.match(original, /Showing 100 of 120/);
	many[119].FixedVersion = "2.0";
	assert.notEqual(original, renderReport(reports(many)).markdown);
	const escaped = renderReport(
		reports([
			vulnerability("HIGH", { PkgName: "@team|<details>\n`hidden`" }),
		]),
	).markdown;
	assert.ok(escaped.includes("| ``@team\\|<details> `hidden` 1.0`` |"));
});

const originalHead = "a".repeat(40);
const pushedHead = "b".repeat(40);
const mainHead = "c".repeat(40);
const treeHead = "d".repeat(40);
const movedHead = "e".repeat(40);
const openPR = {
	number: 1,
	node_id: "PR_report",
	draft: false,
	state: "open",
	merged_at: null,
	head: {
		sha: originalHead,
		ref: "automation/container-security-report",
		repo: { full_name: "owner/repo" },
	},
	base: { ref: "main" },
	body: renderReport(reports([vulnerability("HIGH")])).markdown,
};
const closedPR = { ...openPR, state: "closed" };
const mergedPR = {
	...closedPR,
	merged_at: "2026-10-29T12:00:00Z",
};
const response = (status, data) => ({
	status,
	ok: status >= 200 && status < 300,
	json: async () => data,
});
const encodedFile = (text) => ({
	encoding: "base64",
	content: Buffer.from(text).toString("base64"),
});
const reportFiles = (snapshot) => [
	[reportPath, snapshot.markdown],
	[historyPath, `${JSON.stringify(snapshot.history, null, 2)}\n`],
];
const committedHistory = (gitWrites) =>
	JSON.parse(
		gitWrites.findLast(({ path }) => path === "trees").body.tree[1].content,
	);
const gitCalls = (gitWrites) =>
	gitWrites.map(({ method, path }) => `${method} ${path}`);
const newBranch = ["POST trees", "POST commits", "POST refs"];
const branchUpdate = [
	"POST trees",
	"POST commits",
	"PATCH refs/heads/automation/container-security-report",
];

// Model remote report/default branches and PR history independently: a branch
// push may succeed even though the later PR API call fails or is cancelled.
// Ref updates behave like GitHub's unforced ones: only a fast-forward lands.
function github({
	branch,
	main,
	pulls = [],
	branchHead = originalHead,
	livePR = pulls[0],
	patchStatus = 200,
	createStatus = 201,
	writes = [],
	gitWrites = [],
	gitStatus = () => 200,
	readyWrites = [],
	readyResult,
	concurrentHead,
} = {}) {
	const listed = structuredClone(pulls);
	let current = structuredClone(livePR);
	const statusOf = (value) => (typeof value === "function" ? value() : value);
	const trees = new Map();
	const commits = new Map();
	let created = 0;
	const newSha = () => (++created).toString(16).padStart(40, "0");
	const known = (sha) =>
		[mainHead, branchHead].includes(sha) || commits.has(sha);
	return async (url, options = {}) => {
		const { pathname, searchParams } = new URL(url);
		if (pathname === "/graphql") {
			assert.equal(options.method, "POST");
			const body = JSON.parse(options.body);
			assert.match(body.query, /markPullRequestReadyForReview/);
			assert.deepEqual(body.variables, { id: current.node_id });
			readyWrites.push("ready");
			if (readyResult) return response(200, readyResult);
			current.draft = false;
			return response(200, {
				data: {
					markPullRequestReadyForReview: {
						pullRequest: { id: current.node_id, isDraft: false },
					},
				},
			});
		}
		// Reviewers come from CODEOWNERS; the reporter never requests them.
		assert.ok(
			!/\/(reviews|requested_reviewers)$/.test(pathname),
			`unexpected reviewer call: ${pathname}`,
		);
		if (pathname.includes("/git/") && options.method) {
			const body = JSON.parse(options.body);
			gitWrites.push({
				path: pathname.split("/git/")[1],
				method: options.method,
				body,
			});
			const status = gitStatus(pathname);
			if (status !== 200) return response(status, {});
			if (pathname.endsWith("/git/trees")) {
				assert.equal(options.method, "POST");
				assert.equal(body.base_tree, treeHead);
				assert.deepEqual(
					body.tree.map((entry) => [
						entry.path,
						entry.type,
						entry.mode,
					]),
					[
						[reportPath, "blob", "100644"],
						[historyPath, "blob", "100644"],
					],
				);
				const sha = newSha();
				trees.set(sha, {
					markdown: body.tree[0].content,
					history: JSON.parse(body.tree[1].content),
				});
				return response(201, { sha });
			}
			if (pathname.endsWith("/git/commits")) {
				assert.equal(options.method, "POST");
				assert.ok(trees.has(body.tree));
				assert.ok(body.parents.length > 0 && body.parents.every(known));
				const sha = newSha();
				commits.set(sha, {
					parents: body.parents,
					snapshot: trees.get(body.tree),
				});
				return response(201, { sha });
			}
			const commit = commits.get(body.sha);
			assert.ok(commit);
			if (pathname.endsWith("/git/refs")) {
				assert.equal(options.method, "POST");
				assert.equal(
					body.ref,
					"refs/heads/automation/container-security-report",
				);
				// Creating a branch that already exists fails.
				if (branch !== undefined) return response(422, {});
			} else {
				assert.ok(
					pathname.endsWith(
						"/git/refs/heads/automation/container-security-report",
					),
				);
				assert.equal(options.method, "PATCH");
				assert.equal(body.force, false);
				// Another writer moved the branch after this run read it.
				if (concurrentHead) branchHead = concurrentHead;
				if (
					branch === undefined ||
					!commit.parents.includes(branchHead)
				)
					return response(422, {});
			}
			branch = commit.snapshot;
			branchHead = body.sha;
			// An open PR follows its head branch.
			for (const pr of [listed[0], current])
				if (pr?.state === "open")
					pr.head = { ...pr.head, sha: branchHead };
			return response(200, {
				object: { type: "commit", sha: branchHead },
			});
		}
		if (pathname.endsWith("/git/ref/heads/main")) {
			return response(200, { object: { type: "commit", sha: mainHead } });
		}
		if (pathname.includes("/git/commits/")) {
			assert.ok(known(pathname.split("/").at(-1)));
			return response(200, { tree: { sha: treeHead } });
		}
		if (pathname.endsWith("/pulls") && options.method === "POST") {
			const body = JSON.parse(options.body);
			writes.push({ method: options.method, body });
			const status = statusOf(createStatus);
			if (status !== 201) return response(status, {});
			// GitHub needs the head branch and allows one open PR per head.
			assert.notEqual(branch, undefined);
			assert.notEqual(listed[0]?.state, "open");
			const pr = {
				number: (listed[0]?.number ?? 0) + 1,
				node_id: "PR_new",
				draft: body.draft,
				state: "open",
				merged_at: null,
				head: {
					sha: branchHead,
					ref: body.head,
					repo: { full_name: "owner/repo" },
				},
				base: { ref: body.base },
				body: body.body,
			};
			listed.unshift(pr);
			current = structuredClone(pr);
			return response(201, structuredClone(pr));
		}
		if (pathname.endsWith("/pulls")) {
			assert.equal(searchParams.get("state"), "all");
			assert.equal(
				searchParams.get("head"),
				"owner:automation/container-security-report",
			);
			assert.equal(searchParams.get("sort"), "created");
			assert.equal(searchParams.get("direction"), "desc");
			assert.equal(searchParams.get("per_page"), "1");
			return response(200, structuredClone(listed.slice(0, 1)));
		}
		if (/\/pulls\/\d+$/.test(pathname)) {
			assert.equal(pathname.split("/").at(-1), String(listed[0].number));
			if (options.method === "PATCH") {
				const body = JSON.parse(options.body);
				writes.push({ method: options.method, body });
				const status = statusOf(patchStatus);
				if (status !== 200) return response(status, {});
				if ("state" in body) {
					assert.deepEqual(body, { state: "closed" });
					current.state = "closed";
					listed[0].state = "closed";
				} else {
					// Body updates keep the title and every other field.
					assert.deepEqual(Object.keys(body), ["body"]);
					current.body = body.body;
					listed[0].body = body.body;
				}
			}
			// Like a real HTTP body, return a copy rather than the live object.
			return response(200, structuredClone(current));
		}
		if (
			pathname.endsWith(
				"/git/ref/heads/automation/container-security-report",
			)
		) {
			return branch === undefined
				? response(404, {})
				: response(200, {
						object: { type: "commit", sha: branchHead },
					});
		}
		const ref = searchParams.get("ref");
		assert.ok(ref === "main" || known(ref));
		const snapshot = ["main", mainHead].includes(ref)
			? main
			: ref === branchHead
				? branch
				: commits.get(ref).snapshot;
		let text;
		if (pathname.endsWith(reportPath)) text = snapshot?.markdown;
		else if (pathname.endsWith(historyPath)) {
			const history = snapshot?.history;
			text = history === undefined ? undefined : JSON.stringify(history);
		} else assert.fail(`Unexpected request: ${url}`);
		return text === undefined
			? response(404, {})
			: response(200, encodedFile(text));
	};
}

async function reportRun(t, input = reports([vulnerability("HIGH")])) {
	const originalDirectory = process.cwd();
	const directory = await mkdtemp(join(tmpdir(), "container-report-test-"));
	t.after(async () => {
		process.chdir(originalDirectory);
		await rm(directory, { recursive: true, force: true });
	});
	process.chdir(directory);
	await mkdir("reports");
	const env = {
		REPORT_DIR: "reports",
		GITHUB_API_URL: "https://api.github.com",
		GITHUB_GRAPHQL_URL: "https://api.github.com/graphql",
		GITHUB_REPOSITORY: "owner/repo",
		GH_TOKEN: "test-token",
		BASE_BRANCH: "main",
		IMAGE_TARGETS: imageName,
		SCAN_SHA: "1234567",
		GITHUB_SERVER_URL: "https://github.com",
		GITHUB_RUN_ID: "123",
		GITHUB_OUTPUT: "outputs",
		GITHUB_STEP_SUMMARY: "summary.md",
	};
	const writeReports = async (input) => {
		for (const [target, report] of Object.entries(input))
			await writeFile(
				`reports/trivy-${target}.json`,
				JSON.stringify(report),
			);
	};
	await writeReports(input);
	return { env, writeReports };
}

test("first findings commit both report files to a new branch and open a ready PR", async (t) => {
	const { env } = await reportRun(t);
	const expected = renderReport(reports([vulnerability("HIGH")]));
	const writes = [];
	const gitWrites = [];
	const remote = github({ writes, gitWrites });
	const result = await prepareReport(env, remote);
	assert.equal(result.publish, true);
	assert.equal(result.committed, true);
	assert.equal(result.pullRequest, 1);
	assert.deepEqual(gitCalls(gitWrites), newBranch);
	const [tree, commit] = gitWrites.map(({ body }) => body);
	assert.deepEqual(
		tree.tree.map((entry) => [entry.path, entry.content]),
		reportFiles(expected),
	);
	assert.equal(
		commit.message,
		"chore(security): update container vulnerability report",
	);
	assert.deepEqual(commit.parents, [mainHead]);
	assert.equal(writes.length, 1);
	const { body, ...fields } = writes[0].body;
	assert.equal(writes[0].method, "POST");
	assert.deepEqual(fields, {
		title: "chore(security): container vulnerability findings",
		head: "automation/container-security-report",
		base: "main",
		draft: false,
	});
	assert.ok(body.startsWith(`${expected.markdown}\n## Scan evidence`));
	assert.match(body, /actions\/runs\/123/);
	assert.equal(await readFile(env.GITHUB_OUTPUT, "utf8"), "resolved=false\n");
	assert.match(
		await readFile(env.GITHUB_STEP_SUMMARY, "utf8"),
		/Opened report PR #1 with a new report commit/,
	);
	// Nothing is written to the checkout.
	await assert.rejects(readFile(reportPath), /ENOENT/);
	// The readiness step in the same run sees a synchronized PR, and an
	// unchanged later scan writes nothing.
	assert.equal(
		(await prepareReport(env, remote, false, { ensureReady: true }))
			.madeReady,
		false,
	);
	assert.equal((await prepareReport(env, remote)).publish, false);
	assert.equal(gitWrites.length, 3);
	assert.equal(writes.length, 1);
});

test("changed findings commit on the branch head and update the open PR body", async (t) => {
	const old = renderReport(reports([vulnerability("HIGH")]));
	const input = reports([vulnerability("HIGH", { FixedVersion: "1.1" })]);
	const expected = renderReport(input, old.history);
	const { env } = await reportRun(t, input);
	const writes = [];
	const gitWrites = [];
	const remote = github({ branch: old, pulls: [openPR], writes, gitWrites });
	const result = await prepareReport(env, remote);
	assert.equal(result.pullRequest, 1);
	assert.deepEqual(gitCalls(gitWrites), branchUpdate);
	assert.deepEqual(gitWrites[1].body.parents, [originalHead]);
	assert.equal(gitWrites[2].body.force, false);
	assert.deepEqual(
		gitWrites[0].body.tree.map((entry) => [entry.path, entry.content]),
		reportFiles(expected),
	);
	assert.deepEqual(
		writes.map(({ method }) => method),
		["PATCH"],
	);
	assert.ok(writes[0].body.body.startsWith(expected.markdown));
	assert.match(
		await readFile(env.GITHUB_STEP_SUMMARY, "utf8"),
		/Updated report PR #1 with a new report commit/,
	);
	assert.equal(
		(await prepareReport(env, remote, false, { ensureReady: true }))
			.madeReady,
		false,
	);
	assert.equal((await prepareReport(env, remote)).publish, false);
	assert.equal(writes.length, 1);
	assert.equal(gitWrites.length, 3);
});

test("report branch updates are never forced, so a concurrent change fails the run", async (t) => {
	const old = renderReport(reports([vulnerability("HIGH")]));
	const { env } = await reportRun(
		t,
		reports([vulnerability("HIGH", { FixedVersion: "1.1" })]),
	);
	const writes = [];
	const gitWrites = [];
	await assert.rejects(
		prepareReport(
			env,
			github({
				branch: old,
				pulls: [openPR],
				writes,
				gitWrites,
				concurrentHead: movedHead,
			}),
		),
		/HTTP 422/,
	);
	assert.deepEqual(gitCalls(gitWrites), branchUpdate);
	assert.equal(gitWrites[2].body.force, false);
	// A branch created by another writer in the meantime is not replaced.
	gitWrites.length = 0;
	await assert.rejects(
		prepareReport(
			env,
			github({
				writes,
				gitWrites,
				gitStatus: (path) => (path.endsWith("/git/refs") ? 422 : 200),
			}),
		),
		/HTTP 422/,
	);
	assert.deepEqual(gitCalls(gitWrites), newBranch);
	assert.deepEqual(writes, []);
});

for (const failure of ["PR creation", "the branch response"]) {
	test(`a report pushed before ${failure} failed gets its PR without a duplicate commit`, async (t) => {
		const high = reports([vulnerability("HIGH")]);
		const first = renderReport(high);
		const { env, writeReports } = await reportRun(t, high);
		const writes = [];
		const gitWrites = [];
		const remote = github({ writes, gitWrites });
		let failing = true;
		const flaky = async (url, options) => {
			const lost =
				failing &&
				(failure === "PR creation"
					? url.endsWith("/pulls") && options?.method === "POST"
					: url.endsWith("/git/refs"));
			if (lost && failure === "PR creation") return response(502, {});
			const result = await remote(url, options);
			return lost ? response(503, {}) : result;
		};
		await assert.rejects(prepareReport(env, flaky), /HTTP 50[23]/);
		assert.deepEqual(gitCalls(gitWrites), newBranch);
		assert.deepEqual(writes, []);
		// The next scan has the same findings; only the clock moved.
		high[imageName].CreatedAt = "2026-10-30T10:14:11Z";
		await writeReports(high);
		failing = false;
		const retried = await prepareReport(env, flaky);
		assert.equal(retried.committed, false);
		assert.equal(gitWrites.length, 3);
		assert.deepEqual(committedHistory(gitWrites), first.history);
		assert.deepEqual(
			writes.map(({ method }) => method),
			["POST"],
		);
		assert.match(writes[0].body.body, /2026-10-29 10:14:11Z \(1d\)/);
		assert.equal((await prepareReport(env, flaky)).publish, false);
	});
}

test("an unconfirmed PR response fails the run", async (t) => {
	const { env } = await reportRun(t);
	const remote = github();
	await assert.rejects(
		prepareReport(env, async (url, options) => {
			const result = await remote(url, options);
			if (!(url.endsWith("/pulls") && options?.method === "POST"))
				return result;
			const pr = await result.json();
			return response(201, {
				...pr,
				head: { ...pr.head, sha: pushedHead },
			});
		}),
		/invalid report pull request/,
	);
});

test("unchanged draft becomes ready once, independently of publication", async (t) => {
	const { env } = await reportRun(t);
	const readyWrites = [];
	const writes = [];
	const remote = github({
		branch: renderReport(reports([vulnerability("HIGH")])),
		pulls: [{ ...openPR, draft: true }],
		readyWrites,
		writes,
	});
	assert.equal((await prepareReport(env, remote)).publish, false);
	assert.deepEqual(writes, []);
	assert.equal(
		(await prepareReport(env, remote, false, { ensureReady: true }))
			.madeReady,
		true,
	);
	assert.deepEqual(readyWrites, ["ready"]);
	assert.equal(
		(await prepareReport(env, remote, false, { ensureReady: true }))
			.madeReady,
		false,
	);
	assert.deepEqual(readyWrites, ["ready"]);
});

test("GraphQL errors fail readiness", async (t) => {
	const { env } = await reportRun(t);
	for (const readyResult of [
		{ errors: [{ message: "Denied" }] },
		{
			data: {
				markPullRequestReadyForReview: {
					pullRequest: { id: "PR_report", isDraft: true },
				},
			},
		},
	]) {
		const readyWrites = [];
		await assert.rejects(
			prepareReport(
				env,
				github({
					branch: renderReport(reports([vulnerability("HIGH")])),
					pulls: [{ ...openPR, draft: true }],
					readyWrites,
					readyResult,
				}),
				false,
				{ ensureReady: true },
			),
			/did not confirm/,
		);
		assert.deepEqual(readyWrites, ["ready"]);
	}
});

test("clean scans and deliberately closed trackers are never made ready or reopened", async (t) => {
	const { env, writeReports } = await reportRun(t);
	const branch = renderReport(reports([vulnerability("HIGH")]));
	const readyWrites = [];
	await prepareReport(
		env,
		github({ branch, pulls: [closedPR], readyWrites }),
		false,
		{ ensureReady: true },
	);
	await writeReports(reports());
	await prepareReport(
		env,
		github({ branch, pulls: [openPR], readyWrites }),
		false,
		{ ensureReady: true },
	);
	assert.deepEqual(readyWrites, []);
});

test("stale summary, mismatched head or unexpected PR identity prevents readiness changes", async (t) => {
	const { env } = await reportRun(t);
	for (const change of [
		{ body: "stale" },
		{ number: 2 },
		{ head: { ...openPR.head, sha: pushedHead } },
		{ head: { ...openPR.head, repo: { full_name: "other/repo" } } },
		{ base: { ref: "other" } },
	]) {
		const readyWrites = [];
		await assert.rejects(
			prepareReport(
				env,
				github({
					branch: renderReport(reports([vulnerability("HIGH")])),
					pulls: [openPR],
					livePR: { ...openPR, ...change },
					readyWrites,
				}),
				false,
				{ ensureReady: true },
			),
			/not synchronized/,
		);
		assert.deepEqual(readyWrites, []);
	}
});

test("keeps an unchanged deliberately closed PR closed until visible findings change", async (t) => {
	const first = renderReport(reports([vulnerability("HIGH")]));
	const { env, writeReports } = await reportRun(t);
	const writes = [];
	const gitWrites = [];
	const remote = github({
		branch: first,
		pulls: [closedPR],
		writes,
		gitWrites,
	});
	assert.equal((await prepareReport(env, remote)).publish, false);
	assert.deepEqual([writes, gitWrites], [[], []]);
	await writeReports(
		reports([vulnerability("HIGH", { FixedVersion: "1.1" })]),
	);
	assert.equal((await prepareReport(env, remote)).pullRequest, 2);
	assert.deepEqual(gitCalls(gitWrites), branchUpdate);
	assert.deepEqual(gitWrites[1].body.parents, [originalHead]);
	assert.deepEqual(committedHistory(gitWrites), first.history);
	assert.deepEqual(
		writes.map(({ method }) => method),
		["POST"],
	);
});

for (const priorPR of [mergedPR, closedPR]) {
	test(`retries findings after an earlier ${priorPR.merged_at ? "merged" : "closed"} PR when a new branch push outlives failed creation`, async (t) => {
		const old = renderReport(reports([vulnerability("HIGH")]));
		const input = reports([vulnerability("HIGH", { FixedVersion: "1.1" })]);
		input[imageName].CreatedAt = "2026-11-03T06:23:00Z";
		const { env, writeReports } = await reportRun(t, input);
		const main = priorPR.merged_at ? old : undefined;
		const writes = [];
		const gitWrites = [];
		let createStatus = 502;
		const remote = github({
			// Merging the earlier PR deleted its branch.
			branch: priorPR.merged_at ? undefined : old,
			main,
			pulls: [priorPR],
			writes,
			gitWrites,
			createStatus: () => createStatus,
		});
		await assert.rejects(prepareReport(env, remote), /HTTP 502/);
		assert.deepEqual(
			gitCalls(gitWrites),
			priorPR.merged_at ? newBranch : branchUpdate,
		);
		assert.deepEqual(gitWrites[1].body.parents, [
			priorPR.merged_at ? mainHead : originalHead,
		]);
		assert.deepEqual(committedHistory(gitWrites), old.history);
		// The new report was pushed, but the PR API failed. The latest
		// merged/closed PR still refers to the old head; equal fingerprints must
		// not stop retries.
		input[imageName].CreatedAt = "2026-11-04T06:23:00Z";
		await writeReports(input);
		await assert.rejects(prepareReport(env, remote), /HTTP 502/);
		createStatus = 201;
		assert.equal((await prepareReport(env, remote)).pullRequest, 2);
		assert.equal(gitWrites.length, 3);
		assert.equal(writes.length, 3);
		assert.equal((await prepareReport(env, remote)).publish, false);
		// Deliberately closing that new PR must leave it closed on later scans.
		const pushed = renderReport(input, old.history);
		for (const state of ["open", "closed"]) {
			const currentPR = {
				number: 2,
				state,
				merged_at: null,
				head: { sha: pushedHead },
				body: pushed.markdown,
			};
			assert.equal(
				(
					await prepareReport(
						env,
						github({
							branch: pushed,
							branchHead: pushedHead,
							main,
							pulls: [currentPR],
						}),
					)
				).publish,
				false,
			);
		}
	});
}

for (const severity of ["HIGH", "cleared"]) {
	test(`retries a stale open PR summary after its ${severity} report push advanced the PR head`, async (t) => {
		const old = renderReport(reports([vulnerability("HIGH")]));
		const input =
			severity === "HIGH"
				? reports([vulnerability("HIGH", { FixedVersion: "1.1" })])
				: reports();
		const pushed = renderReport(input, old.history);
		assert.notEqual(pushed.fingerprint, old.fingerprint);
		input[imageName].CreatedAt = "2026-11-04T06:23:00Z";
		const { env } = await reportRun(t, input);
		// The existing PR follows the new branch head immediately, before its
		// body update fails. Matching SHAs do not acknowledge that API update.
		const stalePR = {
			...openPR,
			head: { ...openPR.head, sha: pushedHead },
			body: old.markdown,
		};
		for (let attempt = 0; attempt < 2; attempt++) {
			const writes = [];
			const gitWrites = [];
			const result = await prepareReport(
				env,
				github({
					branch: pushed,
					branchHead: pushedHead,
					pulls: [stalePR],
					writes,
					gitWrites,
				}),
			);
			assert.equal(result.committed, false);
			assert.deepEqual(gitWrites, []);
			assert.deepEqual(
				writes.map(({ method }) => method),
				["PATCH"],
			);
			assert.ok(
				writes[0].body.body.includes(
					`findings-sha256: ${pushed.fingerprint}`,
				),
			);
		}
		// Once the body contains the current fingerprint, clock/age changes
		// must not trigger another update. Closing it must also stop retries.
		for (const pr of [
			{ ...stalePR, body: pushed.markdown },
			{ ...stalePR, state: "closed" },
		]) {
			assert.equal(
				(
					await prepareReport(
						env,
						github({
							branch: pushed,
							branchHead: pushedHead,
							pulls: [pr],
						}),
					)
				).publish,
				false,
			);
		}
	});
}

test("deleted unmerged report branches fail without resetting history or reopening PRs", async (t) => {
	const { env } = await reportRun(t);
	const oldMergedSnapshot = renderReport(reports());
	const writes = [];
	const gitWrites = [];
	for (const pulls of [[closedPR], [openPR]]) {
		for (const main of [undefined, oldMergedSnapshot]) {
			await assert.rejects(
				prepareReport(env, github({ pulls, main, writes, gitWrites })),
				/Unmerged report branch\/history is missing/,
			);
			await assert.rejects(readFile(env.GITHUB_OUTPUT), /ENOENT/);
		}
	}
	await assert.rejects(
		prepareReport(env, github({ pulls: [mergedPR], writes, gitWrites })),
		/Merged report history is missing/,
	);
	assert.deepEqual([writes, gitWrites], [[], []]);
});

test("after a merged PR deleted its branch, new findings start from the base head in a new PR", async (t) => {
	const first = renderReport(reports([vulnerability("HIGH")]));
	const { env, writeReports } = await reportRun(t);
	const writes = [];
	const gitWrites = [];
	const remote = github({
		main: first,
		pulls: [mergedPR],
		writes,
		gitWrites,
	});
	assert.equal((await prepareReport(env, remote)).publish, false);
	const changed = reports([
		vulnerability("HIGH", { InstalledVersion: "1.1" }),
	]);
	changed[imageName].CreatedAt = "2026-10-31T10:14:11Z";
	await writeReports(changed);
	assert.equal((await prepareReport(env, remote)).pullRequest, 2);
	assert.deepEqual(gitCalls(gitWrites), newBranch);
	assert.deepEqual(gitWrites[1].body.parents, [mainHead]);
	assert.deepEqual(committedHistory(gitWrites), first.history);
	assert.deepEqual(
		writes.map(({ method, body }) => [method, body.base, body.draft]),
		[["POST", "main", false]],
	);
});

test("after a merged PR kept its branch, new findings merge the base head so the new PR applies cleanly", async (t) => {
	const first = renderReport(reports([vulnerability("HIGH")]));
	const { env } = await reportRun(
		t,
		reports([vulnerability("HIGH", { FixedVersion: "1.1" })]),
	);
	const writes = [];
	const gitWrites = [];
	const remote = github({
		branch: first,
		main: first,
		pulls: [mergedPR],
		writes,
		gitWrites,
	});
	assert.equal((await prepareReport(env, remote)).pullRequest, 2);
	assert.deepEqual(gitCalls(gitWrites), branchUpdate);
	assert.deepEqual(gitWrites[1].body.parents, [originalHead, mainHead]);
	assert.deepEqual(
		writes.map(({ method }) => method),
		["POST"],
	);
});

test("clean scans clear open trackers without creating clean PRs after closed or merged reports", async (t) => {
	const { env, writeReports } = await reportRun(t, reports());
	const high = renderReport(reports([vulnerability("HIGH")]));
	const clean = renderReport(reports(), high.history);
	const writes = [];
	const remote = (options) => github({ ...options, writes });
	assert.equal((await prepareReport(env, remote())).publish, false);
	assert.equal(
		(await prepareReport(env, remote({ branch: high, pulls: [openPR] })))
			.pullRequest,
		1,
	);
	assert.match(writes[0].body.body, /No HIGH or CRITICAL vulnerabilities/);
	assert.equal(
		(
			await prepareReport(
				env,
				remote({
					branch: clean,
					pulls: [{ ...openPR, body: clean.markdown }],
				}),
			)
		).publish,
		false,
	);
	assert.equal(
		(await prepareReport(env, remote({ branch: high, pulls: [closedPR] })))
			.publish,
		false,
	);
	for (const branch of [undefined, high, clean]) {
		// Merged reports are historical snapshots, not current tracking PRs.
		// A clean scan must not create a new PR just to archive a resolution.
		assert.equal(
			(
				await prepareReport(
					env,
					remote({
						branch,
						main: high,
						pulls: [mergedPR],
						branchHead:
							branch === clean ? pushedHead : originalHead,
					}),
				)
			).publish,
			false,
		);
	}
	assert.equal(
		(await prepareReport(env, remote({ main: clean, pulls: [mergedPR] })))
			.publish,
		false,
	);
	assert.equal(
		(
			await prepareReport(
				env,
				remote({ branch: clean, main: high, pulls: [closedPR] }),
			)
		).publish,
		false,
	);
	await writeReports(reports([vulnerability("MEDIUM")]));
	assert.equal((await prepareReport(env, remote())).publish, false);
	// Only the open tracker was touched, and only its body.
	assert.deepEqual(
		writes.map(({ method }) => method),
		["PATCH"],
	);
});

test("clean scans do not reopen closed trackers even after a newer report commit", async (t) => {
	const { env } = await reportRun(t, reports());
	const high = renderReport(reports([vulnerability("HIGH")]));
	const clean = renderReport(reports(), high.history);
	assert.equal(
		(
			await prepareReport(
				env,
				github({ branch: high, main: high, pulls: [closedPR] }),
			)
		).publish,
		false,
	);
	assert.equal(
		(
			await prepareReport(
				env,
				github({
					branch: clean,
					branchHead: pushedHead,
					main: high,
					pulls: [closedPR],
				}),
			)
		).publish,
		false,
	);
	const dismissed = { ...closedPR, head: { sha: pushedHead } };
	assert.equal(
		(
			await prepareReport(
				env,
				github({
					branch: clean,
					branchHead: pushedHead,
					main: high,
					pulls: [dismissed],
				}),
			)
		).publish,
		false,
	);
});

test("hidden lower-severity metadata does not change the report fingerprint", () => {
	const first = renderReport(
		reports([vulnerability("HIGH"), vulnerability("MEDIUM")]),
	);
	const changed = reports([
		vulnerability("HIGH"),
		vulnerability("MEDIUM", {
			InstalledVersion: "1.1",
			FixedVersion: "1.2",
			PublishedDate: "2026-08-13T13:17:43Z",
		}),
	]);
	assert.equal(renderReport(changed).fingerprint, first.fingerprint);
	changed[imageName].Results[0].Vulnerabilities.push(vulnerability("LOW"));
	assert.notEqual(renderReport(changed).fingerprint, first.fingerprint);
});

test("scan, API and history errors fail before any write and recover on retry", async (t) => {
	const { env, writeReports } = await reportRun(t);
	const high = renderReport(reports([vulnerability("HIGH")]));
	const writes = [];
	const gitWrites = [];
	const remote = github({ branch: high, pulls: [openPR], writes, gitWrites });
	for (const status of [403, 500]) {
		await assert.rejects(
			prepareReport(env, async () => response(status, {})),
			new RegExp(`HTTP ${status}`),
		);
	}
	await assert.rejects(
		prepareReport(env, async (url) =>
			url.includes("/pulls?") ? response(200, {}) : remote(url),
		),
		/invalid pull request list/,
	);
	await assert.rejects(
		prepareReport(
			env,
			github({
				branch: { markdown: high.markdown },
				pulls: [openPR],
				writes,
				gitWrites,
			}),
		),
		/history is missing/,
	);
	await assert.rejects(
		prepareReport(env, async (url) =>
			url.includes("container-security-history.json")
				? response(200, encodedFile("invalid json"))
				: remote(url),
		),
	);
	await rm(`reports/trivy-${imageName}.json`);
	await assert.rejects(prepareReport(env, remote), /ENOENT/);
	assert.deepEqual([writes, gitWrites], [[], []]);
	await writeReports(reports([vulnerability("HIGH")]));
	// The branch already holds the report; only the missing PR is created.
	assert.equal(
		(await prepareReport(env, github({ branch: high, writes, gitWrites })))
			.pullRequest,
		1,
	);
	assert.deepEqual(gitWrites, []);
	assert.deepEqual(
		writes.map(({ method }) => method),
		["POST"],
	);
});

test("publishes the clean snapshot before closing, retains history, and reports recurrence", async (t) => {
	const high = renderReport(reports([vulnerability("HIGH")]));
	const input = reports([vulnerability("MEDIUM")]);
	const clean = renderReport(input, high.history);
	const { env, writeReports } = await reportRun(t, input);
	const writes = [];
	const gitWrites = [];
	const remote = github({ branch: high, pulls: [openPR], writes, gitWrites });
	await assert.rejects(prepareReport(env, remote, true), /must be published/);
	const stale = { ...openPR, head: { ...openPR.head, sha: pushedHead } };
	await assert.rejects(
		prepareReport(
			env,
			github({
				branch: clean,
				branchHead: pushedHead,
				pulls: [stale],
				writes,
			}),
			true,
		),
		/must be published/,
	);
	assert.equal(writes.length, 0);
	// Publishing the clean report lets the closing step in the same run proceed.
	assert.equal((await prepareReport(env, remote)).pullRequest, 1);
	assert.deepEqual(gitCalls(gitWrites), branchUpdate);
	assert.deepEqual(committedHistory(gitWrites), high.history);
	assert.ok(
		writes[0].body.body.includes(`findings-sha256: ${clean.fingerprint}`),
	);
	assert.equal((await prepareReport(env, remote, true)).closed, true);
	assert.deepEqual(
		writes.map(({ method, body }) => [method, Object.keys(body)]),
		[
			["PATCH", ["body"]],
			["PATCH", ["state"]],
		],
	);
	assert.deepEqual(writes[1].body, { state: "closed" });
	assert.deepEqual(clean.history, high.history);
	assert.match(
		await readFile(env.GITHUB_STEP_SUMMARY, "utf8"),
		/Closed report PR #1/,
	);
	assert.equal((await prepareReport(env, remote, true)).closed, false);
	assert.equal(writes.length, 2);
	// Returning HIGH findings open a new PR with the original first-flagged
	// date; the closed tracker stays closed.
	await writeReports(reports([vulnerability("HIGH")]));
	assert.equal((await prepareReport(env, remote)).pullRequest, 2);
	assert.deepEqual(committedHistory(gitWrites), high.history);
	assert.equal(gitWrites.length, 6);
	assert.equal(writes.at(-1).method, "POST");
});

test("failed closure retries on an unchanged clean scan", async (t) => {
	const high = renderReport(reports([vulnerability("HIGH")]));
	const clean = renderReport(reports(), high.history);
	const { env } = await reportRun(t, reports());
	const ready = { ...openPR, body: clean.markdown };
	const writes = [];
	let status = 503;
	const remote = github({
		branch: clean,
		pulls: [ready],
		writes,
		patchStatus: () => status,
	});
	await assert.rejects(prepareReport(env, remote, true), /HTTP 503/);
	assert.equal((await prepareReport(env, remote)).publish, false);
	assert.match(await readFile(env.GITHUB_OUTPUT, "utf8"), /resolved=true/);
	status = 200;
	assert.equal((await prepareReport(env, remote, true)).closed, true);
	assert.equal(writes.length, 2);
});

test("closure refuses remaining HIGH findings, missing reports, and invalid history", async (t) => {
	const { env, writeReports } = await reportRun(t);
	const high = renderReport(reports([vulnerability("HIGH")]));
	const writes = [];
	const remote = github({ branch: high, pulls: [openPR], writes });
	await assert.rejects(prepareReport(env, remote, true), /findings remain/);
	await writeReports(reports());
	const clean = renderReport(reports(), high.history);
	await assert.rejects(
		prepareReport(
			env,
			github({
				branch: { ...clean, history: {} },
				pulls: [openPR],
				writes,
			}),
			true,
		),
		/Invalid first-flagged history/,
	);
	await rm(`reports/trivy-${imageName}.json`);
	await assert.rejects(prepareReport(env, remote, true), /ENOENT/);
	assert.equal(writes.length, 0);
});

test("closure rechecks PR identity, head and body without deleting its branch", async (t) => {
	const clean = renderReport(reports());
	const { env } = await reportRun(t, reports());
	const ready = { ...openPR, body: clean.markdown };
	const writes = [];
	for (const changed of [
		{ ...ready, head: { ...ready.head, ref: "fix/application" } },
		{
			...ready,
			head: { ...ready.head, repo: { full_name: "other/repo" } },
		},
		{ ...ready, base: { ref: "another-branch" } },
		{ ...ready, head: { ...ready.head, sha: pushedHead } },
		{ ...ready, body: "changed summary" },
	]) {
		await assert.rejects(
			prepareReport(
				env,
				github({
					branch: clean,
					pulls: [ready],
					livePR: changed,
					writes,
				}),
				true,
			),
			/changed before closure/,
		);
	}
	assert.equal(writes.length, 0);
});

test("clean scans leave already closed or absent trackers alone", async (t) => {
	const { env } = await reportRun(t, reports());
	const high = renderReport(reports([vulnerability("HIGH")]));
	const clean = renderReport(reports(), high.history);
	const writes = [];
	for (const remote of [
		github({ writes }),
		github({ branch: clean, pulls: [closedPR], writes }),
		github({ main: clean, pulls: [mergedPR], writes }),
	]) {
		assert.equal((await prepareReport(env, remote, true)).closed, false);
	}
	assert.equal(writes.length, 0);
});

for (const scenario of [
	{ label: "closed tracker", priorPR: closedPR, deleted: false },
	{
		label: "merged tracker with its branch kept",
		priorPR: mergedPR,
		deleted: false,
	},
	{
		label: "merged tracker with its branch deleted",
		priorPR: mergedPR,
		deleted: true,
	},
]) {
	test(`records a clean transition after a ${scenario.label} so identical findings recur`, async (t) => {
		const highInput = reports([vulnerability("HIGH")]);
		const high = renderReport(highInput);
		const { env, writeReports } = await reportRun(t, reports());
		const writes = [];
		const gitWrites = [];
		const remote = github({
			branch: scenario.deleted ? undefined : high,
			main: high,
			pulls: [scenario.priorPR],
			writes,
			gitWrites,
		});
		assert.equal((await prepareReport(env, remote)).publish, false);
		const resolved = await prepareReport(env, remote, true);
		assert.equal(resolved.recorded, true);
		assert.equal(resolved.closed, false);
		assert.equal(
			writes.length,
			0,
			"clean scans must not create, edit or reopen a PR",
		);
		assert.equal(gitWrites.length, 3);
		assert.deepEqual(
			gitWrites[1].body.parents,
			[scenario.deleted ? mainHead : originalHead],
			"recording a clean scan never merges the base branch",
		);
		assert.deepEqual(committedHistory(gitWrites), high.history);
		const recordedHead = gitWrites[2].body.sha;
		assert.equal((await prepareReport(env, remote, true)).recorded, false);
		assert.equal(
			gitWrites.length,
			3,
			"unchanged clean scans do not commit again",
		);
		// Same package, version, CVE and metadata, on a later scan.
		highInput[imageName].CreatedAt = "2026-11-05T06:23:00Z";
		await writeReports(highInput);
		assert.equal((await prepareReport(env, remote)).pullRequest, 2);
		assert.equal(gitWrites.length, 6);
		assert.deepEqual(
			gitWrites[4].body.parents,
			scenario.priorPR.merged_at
				? [recordedHead, mainHead]
				: [recordedHead],
		);
		assert.deepEqual(committedHistory(gitWrites), high.history);
		assert.deepEqual(
			writes.map(({ method }) => method),
			["POST"],
		);
	});
}

test("failed clean branch publication retries without creating a PR or losing history", async (t) => {
	const high = renderReport(reports([vulnerability("HIGH")]));
	const { env, writeReports } = await reportRun(t, reports());
	const writes = [];
	const gitWrites = [];
	let status = 422;
	const remote = github({
		branch: high,
		pulls: [closedPR],
		writes,
		gitWrites,
		gitStatus: (path) => (path.includes("/git/refs/") ? status : 200),
	});
	await assert.rejects(prepareReport(env, remote, true), /HTTP 422/);
	assert.equal((await prepareReport(env, remote)).publish, false);
	status = 200;
	assert.equal((await prepareReport(env, remote, true)).recorded, true);
	assert.equal(gitWrites.length, 6);
	assert.equal(writes.length, 0);
	await writeReports(reports([vulnerability("HIGH")]));
	assert.equal((await prepareReport(env, remote)).publish, true);
	assert.deepEqual(committedHistory(gitWrites), high.history);
});

test("a clean ref update accepted before a lost response is not committed twice", async (t) => {
	const high = renderReport(reports([vulnerability("HIGH")]));
	const { env, writeReports } = await reportRun(t, reports());
	const gitWrites = [];
	const remote = github({ branch: high, pulls: [closedPR], gitWrites });
	const lostResponse = async (url, options) => {
		const result = await remote(url, options);
		return options?.method === "PATCH" ? response(503, {}) : result;
	};
	await assert.rejects(prepareReport(env, lostResponse, true), /HTTP 503/);
	assert.equal((await prepareReport(env, remote, true)).recorded, false);
	assert.equal(gitWrites.length, 3);
	await writeReports(reports([vulnerability("HIGH")]));
	assert.equal((await prepareReport(env, remote)).publish, true);
});

test("image targets accept comma or newline lists and reject unsafe names", () => {
	assert.deepEqual(parseTargets("api, worker\napi\n"), ["api", "worker"]);
	assert.throws(() => parseTargets(" \n"), /IMAGE_TARGETS is empty/);
	assert.throws(() => parseTargets("../etc"), /Invalid image target/);
});

test("reports count each configured image separately", () => {
	const result = renderReport(
		{
			api: image([vulnerability("HIGH")]),
			worker: image([vulnerability("LOW")]),
		},
		undefined,
		["api", "worker"],
	);
	assert.match(result.markdown, /\| api \| 0 \| 1 \| 0 \| 0 \| 0 \|/);
	assert.match(result.markdown, /\| worker \| 0 \| 0 \| 0 \| 1 \| 0 \|/);
	assert.throws(
		() => renderReport({ api: image() }, undefined, ["api", "worker"]),
		/Missing or invalid worker image report/,
	);
});

test("scan evidence links the calling workflow's runs", async (t) => {
	const { env } = await reportRun(t);
	env.GITHUB_WORKFLOW_REF =
		"owner/repo/.github/workflows/security.yaml@refs/heads/main";
	const writes = [];
	await prepareReport(env, github({ writes }));
	assert.match(
		writes[0].body.body,
		/\(https:\/\/github\.com\/owner\/repo\/actions\/workflows\/security\.yaml\)/,
	);
});

test("image targets are sorted and limited to Docker tag syntax", () => {
	assert.deepEqual(parseTargets("worker,API"), ["API", "worker"]);
	assert.throws(() => parseTargets("a".repeat(129)), /Invalid image target/);
	assert.equal(parseTargets("a".repeat(128))[0].length, 128);
});

test("the fingerprint changes when an image is renamed", () => {
	const clean = image([vulnerability("LOW")]);
	assert.notEqual(
		renderReport({ api: clean }).fingerprint,
		renderReport({ worker: clean }).fingerprint,
	);
});

test("package metadata is fenced so it cannot autolink, mention or cross-reference", () => {
	const row = (fields) =>
		renderReport(reports([vulnerability("HIGH", fields)]))
			.markdown.split("\n")
			.find((line) => line.startsWith("| app | HIGH |"));
	assert.equal(
		row({
			VulnerabilityID: "GH-1",
			PkgName: "owner/repo#1 @team",
			InstalledVersion: "_www.example.com",
			FixedVersion: "https://example.com",
		})
			.split(" | ")
			.slice(2, 5)
			.join(" | "),
		"`GH-1` | `owner/repo#1 @team _www.example.com` | `https://example.com`",
	);
	assert.match(row({ PkgName: "`edge" }), /`` `edge 1\.0 ``/);
	assert.match(row({ FixedVersion: "" }), /\| No fix available \|/);
});

test("empty CLI option values are rejected", () => {
	const script = fileURLToPath(new URL("./report.mjs", import.meta.url));
	for (const args of [
		["--local", ""],
		["--targets", ""],
	])
		assert.throws(
			() =>
				execFileSync(process.execPath, [script, ...args], {
					env: {},
					stdio: "pipe",
				}),
			/requires a value/,
		);
});

test("local preview records whether findings remain", async (t) => {
	const directory = await mkdtemp(join(tmpdir(), "container-report-output-"));
	t.after(() => rm(directory, { recursive: true, force: true }));
	await writeFile(
		join(directory, `trivy-${imageName}.json`),
		JSON.stringify(reports([vulnerability("CRITICAL")])[imageName]),
	);
	const output = join(directory, "outputs");
	execFileSync(
		process.execPath,
		[
			fileURLToPath(new URL("./report.mjs", import.meta.url)),
			"--local",
			directory,
			"--targets",
			imageName,
		],
		{ env: { GITHUB_OUTPUT: output } },
	);
	assert.equal(await readFile(output, "utf8"), "resolved=false\n");
});
