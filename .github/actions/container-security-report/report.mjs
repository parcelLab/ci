import { createHash } from "node:crypto";
import { appendFile, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

export const reportPath = "docs/reports/container-security.md";
export const historyPath = "docs/reports/container-security-history.json";
export const reportBranch = "automation/container-security-report";
export const reportTitle = "chore(security): container vulnerability findings";
const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const isActionable = ({ severity }) => ["CRITICAL", "HIGH"].includes(severity);
const isSha = (value) => /^[a-f0-9]{40}$/.test(value ?? "");
const nonEmptyStrings = (values) =>
	values.every((v) => typeof v === "string" && v.length > 0);
const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const toJson = (value) => `${JSON.stringify(value, null, 2)}\n`;

// Image names, one per line or comma separated, as the scan job names its reports.
export function parseTargets(value) {
	const targets = [
		...new Set(
			String(value ?? "")
				.split(/[\s,]+/)
				.filter(Boolean),
		),
	];
	if (targets.length === 0) throw new Error("IMAGE_TARGETS is empty");
	// Names are used as Docker tags and file names.
	for (const target of targets)
		if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(target))
			throw new Error(`Invalid image target: ${target}`);
	return targets.sort();
}

function timestamp(value) {
	return typeof value === "string" && Number.isFinite(Date.parse(value))
		? new Date(value).toISOString()
		: null;
}

function findingKey({ target, pkg, id }) {
	return JSON.stringify([target, pkg, id]);
}

function firstFlags(actionable, reports, previous) {
	const flags = new Map();
	if (previous !== undefined) {
		if (previous?.version !== 1 || !Array.isArray(previous.findings)) {
			throw new Error("Invalid first-flagged history");
		}
		for (const entry of previous.findings) {
			const { target, pkg, id } = entry;
			const firstFlaggedAt = timestamp(entry.firstFlaggedAt);
			if (!nonEmptyStrings([target, pkg, id]) || !firstFlaggedAt)
				throw new Error("Invalid first-flagged history entry");
			const key = findingKey(entry);
			if (flags.has(key))
				throw new Error("Duplicate first-flagged history entry");
			flags.set(key, { target, pkg, id, firstFlaggedAt });
		}
	}
	for (const { target, pkg, id } of actionable) {
		const key = findingKey({ target, pkg, id });
		if (!flags.has(key))
			flags.set(key, {
				target,
				pkg,
				id,
				firstFlaggedAt: timestamp(reports[target].CreatedAt),
			});
	}
	return flags;
}

function datedAge(value, asOf) {
	if (!value) return "Unknown";
	const days = Math.floor((Date.parse(asOf) - Date.parse(value)) / 86400000);
	return `${value.slice(0, 19).replace("T", " ")}Z (${days < 0 ? "after scan" : `${days}d`})`;
}

// Package metadata comes from the scanned image, so it is shown as a code span:
// GitHub does not render links, mentions or issue references inside one. Only
// "|" needs escaping, because GFM splits table cells before parsing code spans.
function code(value) {
	const text = String(value)
		.slice(0, 100)
		.replace(/[\r\n]+/g, " ")
		.replace(/\|/g, "\\|");
	if (!text.trim()) return "";
	const longestRun = Math.max(
		0,
		...(text.match(/`+/g) ?? []).map((run) => run.length),
	);
	const fence = "`".repeat(longestRun + 1);
	const pad = text.startsWith("`") || text.endsWith("`") ? " " : "";
	return `${fence}${pad}${text}${pad}${fence}`;
}

function collectFindings(reports, targets) {
	const unique = new Map();
	for (const target of targets) {
		const report = reports[target];
		if (
			report?.SchemaVersion !== 2 ||
			report.ArtifactType !== "container_image" ||
			!timestamp(report.CreatedAt) ||
			!Array.isArray(report.Results) ||
			!report.Results.some((result) => result.Class === "os-pkgs")
		) {
			throw new Error(`Missing or invalid ${target} image report`);
		}
		for (const result of report.Results) {
			if (
				result.Vulnerabilities !== undefined &&
				!Array.isArray(result.Vulnerabilities)
			) {
				throw new Error(`Invalid ${target} vulnerability list`);
			}
			for (const vulnerability of result.Vulnerabilities ?? []) {
				const {
					VulnerabilityID: id,
					PkgName: pkg,
					InstalledVersion: installed,
					Severity: severity,
				} = vulnerability;
				const fixed = vulnerability.FixedVersion ?? "";
				if (
					!nonEmptyStrings([id, pkg, installed]) ||
					typeof fixed !== "string" ||
					!severities.includes(severity)
				) {
					throw new Error(`Invalid ${target} vulnerability`);
				}
				const published = timestamp(vulnerability.PublishedDate);
				const finding = {
					target,
					severity,
					id,
					pkg,
					installed,
					fixed,
					published,
				};
				const key = JSON.stringify([
					target,
					severity,
					id,
					pkg,
					installed,
					fixed,
				]);
				// Keep the earliest known publication date for a duplicate.
				const existing = unique.get(key);
				if (
					!existing ||
					(published &&
						(!existing.published || published < existing.published))
				) {
					unique.set(key, finding);
				}
			}
		}
	}
	return [...unique.values()].sort(
		(a, b) =>
			severities.indexOf(a.severity) - severities.indexOf(b.severity) ||
			compare(JSON.stringify(a), JSON.stringify(b)),
	);
}

export function renderReport(
	reports,
	previousHistory,
	targets = Object.keys(reports).sort(),
) {
	const findings = collectFindings(reports, targets);
	const actionable = findings.filter(isActionable);
	const flags = firstFlags(actionable, reports, previousHistory);
	const history = {
		version: 1,
		findings: [...flags.entries()]
			.sort(([a], [b]) => compare(a, b))
			.map(([, entry]) => entry),
	};
	const asOf = targets
		.map((target) => timestamp(reports[target].CreatedAt))
		.sort()
		.at(-1);
	const counts = targets.map((target) =>
		severities.map(
			(severity) =>
				findings.filter(
					(finding) =>
						finding.target === target &&
						finding.severity === severity,
				).length,
		),
	);
	// The fingerprint excludes the clock and lower-severity details, so the PR
	// only changes when the counts or HIGH/CRITICAL rows change.
	const fingerprint = createHash("sha256")
		.update(
			JSON.stringify([
				targets,
				counts,
				actionable,
				actionable.map((finding) => flags.get(findingKey(finding))),
			]),
		)
		.digest("hex");
	const lines = [
		"# Container vulnerability report",
		"",
		"This PR tracks scan findings. It contains a report, not remediation changes.",
		"The snapshot updates when severity counts or HIGH/CRITICAL details change. Daily scan artifacts contain the full, latest results.",
		`Ages are whole elapsed days as of ${asOf}. PR ages refer to this snapshot; the daily run summary shows current ages.`,
		"",
		"| Image | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN |",
		"| --- | ---: | ---: | ---: | ---: | ---: |",
	];
	for (const [index, target] of targets.entries()) {
		lines.push(`| ${target} | ${counts[index].join(" | ")} |`);
	}
	lines.push("", "## HIGH and CRITICAL findings", "");
	if (actionable.length === 0) {
		lines.push("No HIGH or CRITICAL vulnerabilities were found.");
	} else {
		lines.push(
			"| Image | Severity | Vulnerability | Package (installed) | Fixed version | Advisory published UTC (age) | First flagged UTC (age) |",
			"| --- | --- | --- | --- | --- | --- | --- |",
		);
		let shown = 0;
		for (const finding of actionable) {
			const firstFlagged = flags.get(findingKey(finding)).firstFlaggedAt;
			const row = `| ${[finding.target, finding.severity, code(finding.id), code(`${finding.pkg} ${finding.installed}`), finding.fixed ? code(finding.fixed) : "No fix available", datedAge(finding.published, asOf), datedAge(firstFlagged, asOf)].join(" | ")} |`;
			if (shown >= 100 || lines.join("\n").length + row.length > 45000)
				break;
			lines.push(row);
			shown++;
		}
		if (shown < actionable.length)
			lines.push(
				"",
				`Showing ${shown} of ${actionable.length} HIGH/CRITICAL findings. Download the full reports for the remainder.`,
			);
	}
	lines.push(
		"",
		"Counts deduplicate the same vulnerability/package/version within each image. Unfixed vulnerabilities are included.",
		"Advisory publication comes from Trivy's vulnerability data; missing dates are Unknown. First flagged records the earliest HIGH/CRITICAL detection by this report, retained across package upgrades and reappearances. Neither date establishes when the application first became vulnerable.",
		"Images are rebuilt from repository source, not rescans of deployed image digests.",
		"",
		`<!-- findings-sha256: ${fingerprint} -->`,
		"<!-- first-flagged-history: 1 -->",
		"",
	);
	return {
		markdown: lines.join("\n"),
		hasFindings: actionable.length > 0,
		fingerprint,
		history,
	};
}

async function loadReports(directory, targets) {
	const entries = await Promise.all(
		targets.map(async (target) => {
			const file = join(directory, `trivy-${target}.json`);
			return [target, JSON.parse(await readFile(file, "utf8"))];
		}),
	);
	return Object.fromEntries(entries);
}

function scanEvidence(env) {
	const repositoryUrl = `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}`;
	// The caller's workflow, e.g. owner/repo/.github/workflows/x.yaml@refs/heads/main.
	const workflow = env.GITHUB_WORKFLOW_REF?.split("@")[0]
		.split("/")
		.slice(2)
		.join("/");
	const workflowDir = ".github/workflows/";
	const runs = workflow?.startsWith(workflowDir)
		? `${repositoryUrl}/actions/workflows/${workflow.slice(workflowDir.length)}`
		: `${repositoryUrl}/actions`;
	return [
		"## Scan evidence",
		`Snapshot prepared: ${new Date().toISOString()}`,
		`Scanned source: ${env.SCAN_SHA}`,
		`[Full JSON/SARIF reports and scan logs](${repositoryUrl}/actions/runs/${env.GITHUB_RUN_ID})`,
		`[Latest scheduled runs](${runs})`,
		"Subscribe to this PR to get notified when it changes.",
	].join("\n\n");
}

function savedFingerprint(markdown) {
	return typeof markdown === "string"
		? markdown.match(/<!-- findings-sha256: ([a-f0-9]{64}) -->/)?.[1]
		: undefined;
}

export async function prepareReport(
	env = process.env,
	fetchImpl = fetch,
	closeResolved = false,
	{ ensureReady = false } = {},
) {
	const targets = parseTargets(env.IMAGE_TARGETS);
	const reports = await loadReports(env.REPORT_DIR, targets);
	const api = `${env.GITHUB_API_URL}/repos/${env.GITHUB_REPOSITORY}`;
	const requestUrl = async (
		url,
		{ allowMissing = false, ...options } = {},
	) => {
		const response = await fetchImpl(url, {
			...options,
			headers: {
				Authorization: `Bearer ${env.GH_TOKEN}`,
				Accept: "application/vnd.github+json",
				"Content-Type": "application/json",
			},
			signal: AbortSignal.timeout(30000),
		});
		if (allowMissing && response.status === 404) return null;
		if (!response.ok)
			throw new Error(
				`GitHub report request failed: HTTP ${response.status}`,
			);
		return response.json();
	};
	const request = (path, options) => requestUrl(`${api}/${path}`, options);
	const summary = (text) => appendFile(env.GITHUB_STEP_SUMMARY, text);
	const readPrevious = async (path, ref) => {
		const file = await request(
			`contents/${path}?ref=${encodeURIComponent(ref)}`,
			{ allowMissing: true },
		);
		if (file === null) return null;
		if (file.encoding !== "base64" || typeof file.content !== "string") {
			throw new Error("GitHub returned an invalid previous report");
		}
		return Buffer.from(file.content, "base64").toString("utf8");
	};
	const readSnapshot = (ref) =>
		Promise.all([
			readPrevious(reportPath, ref),
			readPrevious(historyPath, ref),
		]);
	const readHead = async (branch, allowMissing = false) => {
		const ref = await request(`git/ref/heads/${branch}`, { allowMissing });
		if (ref === null) return undefined;
		if (ref.object?.type !== "commit" || !isSha(ref.object.sha))
			throw new Error("GitHub returned an invalid report branch ref");
		return ref.object.sha;
	};
	const head = `${env.GITHUB_REPOSITORY.split("/")[0]}:${reportBranch}`;
	// Include closed PRs: a pushed branch does not prove the PR was created, and
	// a closed PR means the report was dismissed rather than never opened.
	const pulls = await request(
		`pulls?state=all&head=${encodeURIComponent(head)}&base=${encodeURIComponent(env.BASE_BRANCH)}&sort=created&direction=desc&per_page=1`,
	);
	if (
		!Array.isArray(pulls) ||
		pulls.some(
			(pr) =>
				!Number.isSafeInteger(pr.number) ||
				pr.number < 1 ||
				!["open", "closed"].includes(pr.state) ||
				(pr.merged_at !== null && !timestamp(pr.merged_at)) ||
				!isSha(pr.head?.sha),
		)
	) {
		throw new Error("GitHub returned an invalid pull request list");
	}
	const latestPR = pulls[0];
	const reportHead = await readHead(reportBranch, true);
	let snapshotHead = reportHead;
	// Read both files at the commit compared with the PR head.
	let [previous, storedHistory] = reportHead
		? await readSnapshot(reportHead)
		: [null, null];
	// Merging a report PR can delete its branch; the merged history on the base
	// branch then seeds the next report.
	if (previous === null && storedHistory === null) {
		if (latestPR && !latestPR.merged_at) {
			throw new Error(
				"Unmerged report branch/history is missing; restore automation/container-security-report from its PR head before retrying. Refusing to reset first-flagged dates.",
			);
		}
		snapshotHead = await readHead(env.BASE_BRANCH);
		[previous, storedHistory] = await readSnapshot(snapshotHead);
		if (latestPR && (previous === null || storedHistory === null)) {
			throw new Error(
				"Merged report history is missing; refusing to reset dates",
			);
		}
	}
	if (
		(previous === null && storedHistory !== null) ||
		(previous?.includes("<!-- first-flagged-history: 1 -->") &&
			storedHistory === null)
	) {
		throw new Error(
			"First-flagged history is missing; refusing to reset dates",
		);
	}
	const { markdown, hasFindings, fingerprint, history } = renderReport(
		reports,
		storedHistory === null ? undefined : JSON.parse(storedHistory),
		targets,
	);
	const changed = savedFingerprint(previous) !== fingerprint;
	// A branch head that no PR points at means a push succeeded but PR creation
	// may have failed.
	const unreportedHead =
		reportHead !== undefined && reportHead !== latestPR?.head.sha;
	const prOpen = latestPR?.state === "open";
	// The PR body fingerprint shows whether the last body update landed.
	const openPRNeedsUpdate =
		prOpen && savedFingerprint(latestPR.body) !== fingerprint;
	// A clean scan updates an open PR but never opens a new one.
	const publish = hasFindings
		? changed || !latestPR || unreportedHead || openPRNeedsUpdate
		: (changed || openPRNeedsUpdate) && prOpen;
	// The live PR still matches the published report branch and body.
	const isSynchronized = (current) =>
		current.state === "open" &&
		current.head?.ref === reportBranch &&
		current.head?.repo?.full_name === env.GITHUB_REPOSITORY &&
		current.base?.ref === env.BASE_BRANCH &&
		current.head?.sha === reportHead &&
		savedFingerprint(current.body) === fingerprint;
	// Commits the report and history onto the given parents, starting from
	// the last parent's tree, and moves the report branch to that commit. Not
	// forced, so a concurrent branch update fails instead of being overwritten;
	// creating a branch that appeared meanwhile fails the same way.
	const commitReport = async (parents, message) => {
		const parent = await request(`git/commits/${parents.at(-1)}`);
		if (!isSha(parent.tree?.sha))
			throw new Error("GitHub returned an invalid snapshot tree");
		const tree = await request("git/trees", {
			method: "POST",
			body: JSON.stringify({
				base_tree: parent.tree.sha,
				tree: [
					{ path: reportPath, content: markdown },
					{ path: historyPath, content: toJson(history) },
				].map((entry) => ({ ...entry, mode: "100644", type: "blob" })),
			}),
		});
		if (!isSha(tree.sha))
			throw new Error("GitHub returned an invalid report tree");
		const commit = await request("git/commits", {
			method: "POST",
			body: JSON.stringify({ message, tree: tree.sha, parents }),
		});
		if (!isSha(commit.sha))
			throw new Error("GitHub returned an invalid report commit");
		const ref = await request(
			reportHead ? `git/refs/heads/${reportBranch}` : "git/refs",
			{
				method: reportHead ? "PATCH" : "POST",
				body: JSON.stringify(
					reportHead
						? { sha: commit.sha, force: false }
						: {
								ref: `refs/heads/${reportBranch}`,
								sha: commit.sha,
							},
				),
			},
		);
		if (ref.object?.sha !== commit.sha)
			throw new Error("GitHub did not confirm the report branch update");
		return commit.sha;
	};
	if (ensureReady) {
		// Runs every scan so an unchanged draft or a failed ready transition is
		// retried. Reviewers come from CODEOWNERS when the PR opens or becomes ready.
		if (!hasFindings || !prOpen)
			return { publish: false, madeReady: false };
		const current = await request(`pulls/${latestPR.number}`);
		if (current.state === "closed")
			return { publish: false, madeReady: false };
		if (
			publish ||
			!reportHead ||
			current.number !== latestPR.number ||
			!isSynchronized(current) ||
			typeof current.node_id !== "string" ||
			typeof current.draft !== "boolean"
		) {
			throw new Error(
				"Report PR is not synchronized; refusing readiness changes",
			);
		}
		const wasDraft = current.draft;
		if (wasDraft) {
			const result = await requestUrl(env.GITHUB_GRAPHQL_URL, {
				method: "POST",
				body: JSON.stringify({
					query: "mutation($id: ID!) { markPullRequestReadyForReview(input: {pullRequestId: $id}) { pullRequest { id isDraft } } }",
					variables: { id: current.node_id },
				}),
			});
			const ready =
				result.data?.markPullRequestReadyForReview?.pullRequest;
			if (
				result.errors?.length ||
				ready?.id !== current.node_id ||
				ready.isDraft !== false
			)
				throw new Error(
					"GitHub did not confirm the report PR is ready for review",
				);
		}
		await summary(
			`\nReport PR #${current.number} ${wasDraft ? "was marked" : "is"} ready for review; CODEOWNERS requests its reviewers. Marking it ready from a bot token does not start PR CI; use "Approve workflows to run" if GitHub offers it.\n`,
		);
		return { publish: false, madeReady: wasDraft };
	}
	if (closeResolved) {
		if (hasFindings)
			throw new Error(
				"HIGH/CRITICAL findings remain; refusing to close report",
			);
		if (!prOpen) {
			// Record the clean state even with no open PR. Otherwise findings that
			// return later match the old snapshot and look already dismissed.
			const recorded = changed && previous !== null;
			if (recorded) {
				await commitReport(
					[snapshotHead],
					"chore(security): record resolved container findings",
				);
				await summary(
					"\nRecorded the clean report and history on the report branch without opening a PR.\n",
				);
			}
			return { publish: false, closed: false, recorded, markdown };
		}
		if (publish || unreportedHead || !reportHead) {
			throw new Error(
				"Clean report and history must be published before closing",
			);
		}
		// Recheck the live PR. A failed close is retried on the next clean run.
		const current = await request(`pulls/${latestPR.number}`);
		if (current.state === "closed")
			return { publish: false, closed: false, markdown };
		if (!isSynchronized(current))
			throw new Error(
				"Report PR changed before closure; refusing to close",
			);
		await request(`pulls/${latestPR.number}`, {
			method: "PATCH",
			body: JSON.stringify({ state: "closed" }),
		});
		await summary(
			`\nClosed report PR #${latestPR.number}: no HIGH/CRITICAL findings remain. Report branch and history retained.\n`,
		);
		return { publish: false, closed: true, markdown };
	}
	const body = `${markdown}\n${scanEvidence(env)}\n`;
	// The run summary carries the report even if publication fails below.
	await summary(body);
	await appendFile(env.GITHUB_OUTPUT, `resolved=${!hasFindings}\n`);
	if (!publish) {
		await summary("\nNo report PR update needed.\n");
		return { publish, markdown };
	}
	// The branch can already hold this report when an earlier run pushed it
	// but could not create or update the PR. Retry the PR without stacking a
	// duplicate commit.
	const branchCurrent =
		reportHead !== undefined &&
		snapshotHead === reportHead &&
		!changed &&
		storedHistory !== null &&
		JSON.stringify(JSON.parse(storedHistory)) === JSON.stringify(history);
	let branchHead = reportHead;
	if (!branchCurrent) {
		// Build on the existing branch so the ref update is a fast-forward.
		// After a merged report, also merge the base branch in: a squash or
		// rebase merge leaves the branch's report commits off the base, and
		// the new PR must not conflict with them.
		const parents = [reportHead ?? snapshotHead];
		if (reportHead && latestPR?.merged_at) {
			const baseHead = await readHead(env.BASE_BRANCH);
			if (baseHead !== reportHead) parents.push(baseHead);
		}
		branchHead = await commitReport(
			parents,
			"chore(security): update container vulnerability report",
		);
	}
	// A closed or merged PR is never reopened; findings get a new PR instead.
	const pr = prOpen
		? await request(`pulls/${latestPR.number}`, {
				method: "PATCH",
				body: JSON.stringify({ body }),
			})
		: await request("pulls", {
				method: "POST",
				body: JSON.stringify({
					title: reportTitle,
					head: reportBranch,
					base: env.BASE_BRANCH,
					body,
					draft: false,
				}),
			});
	if (
		!Number.isSafeInteger(pr.number) ||
		pr.number < 1 ||
		(prOpen
			? pr.number !== latestPR.number
			: pr.head?.sha !== branchHead) ||
		savedFingerprint(pr.body) !== fingerprint
	)
		throw new Error("GitHub returned an invalid report pull request");
	await summary(
		`\n${prOpen ? "Updated" : "Opened"} report PR #${pr.number}${branchCurrent ? "" : " with a new report commit"}.\n`,
	);
	return {
		publish,
		markdown,
		pullRequest: pr.number,
		committed: !branchCurrent,
	};
}

if (
	process.argv[1] &&
	import.meta.url === pathToFileURL(process.argv[1]).href
) {
	const { values } = parseArgs({
		options: {
			"close-resolved": { type: "boolean" },
			"ensure-ready": { type: "boolean" },
			local: { type: "string" },
			targets: { type: "string" },
			history: { type: "string" },
			"state-output": { type: "string" },
		},
	});
	for (const [name, value] of Object.entries(values))
		if (value === "") throw new Error(`--${name} requires a value`);
	if (
		values.local === undefined &&
		(values.history ?? values["state-output"] ?? values.targets) !==
			undefined
	) {
		throw new Error("Local options require --local <report-directory>");
	}
	if (values["close-resolved"] || values["ensure-ready"]) {
		if (values.local !== undefined) {
			throw new Error(
				"Remote PR operations cannot be combined with local preview options",
			);
		}
		if (values["close-resolved"] && values["ensure-ready"])
			throw new Error("Choose either --close-resolved or --ensure-ready");
		await prepareReport(process.env, fetch, values["close-resolved"], {
			ensureReady: values["ensure-ready"],
		});
	} else if (values.local !== undefined) {
		const previous = values.history
			? JSON.parse(await readFile(values.history, "utf8"))
			: undefined;
		const targets = parseTargets(
			values.targets ?? process.env.IMAGE_TARGETS,
		);
		const report = renderReport(
			await loadReports(values.local, targets),
			previous,
			targets,
		);
		if (values["state-output"])
			await writeFile(values["state-output"], toJson(report.history));
		if (process.env.GITHUB_OUTPUT)
			await appendFile(
				process.env.GITHUB_OUTPUT,
				`resolved=${!report.hasFindings}\n`,
			);
		process.stdout.write(report.markdown);
	} else {
		await prepareReport();
	}
}
