#!/usr/bin/env python3
"""Bypass audit (INF-4421): open a COM ticket when a push to the default branch skipped review or checks.

Runs from the reusable workflow .github/workflows/bypass-audit.yaml on every push to the caller's
default branch. Stdlib only. A push is a bypass when:
  - it's a merged PR without an approval from someone other than the author, or with a required
    check that wasn't green on the PR head, or
  - it isn't a PR merge at all (direct push or force push), unless it's an allowlisted bot push.

Environment (set by the workflow): GITHUB_EVENT_PATH, GITHUB_REPOSITORY, GH_TOKEN, JIRA_BASE_URL,
JIRA_BROWSE_URL, JIRA_EMAIL, JIRA_TOKEN, FALLBACK_ASSIGNEE_EMAIL, ALLOWED_BOT_PUSHES, USERS_REPO, USERS_PATH, DRY_RUN.
"""
import base64
import fnmatch
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

BOT_LOGINS = {"parcellab-dev-bot"}
PASSING_CONCLUSIONS = {"success", "neutral", "skipped"}  # what branch protection accepts
EMPTY = "<empty>"


# ---------- pure logic (unit-tested in test_bypass_audit.py) ----------


def is_human(user):
    """A GitHub user object (or None) belongs to a human, not an app or the dev-bot."""
    if not user:
        return False
    login = user.get("login", "")
    return user.get("type", "User") == "User" and not login.endswith("[bot]") and login not in BOT_LOGINS


def parse_allowlist(text):
    return [line.strip() for line in (text or "").splitlines() if line.strip() and not line.strip().startswith("#")]


def bot_push_allowed(files, patterns):
    """All changed files match a pattern. An empty file list only matches an explicit <empty>."""
    if not files:
        return EMPTY in patterns
    globs = [p for p in patterns if p != EMPTY]
    # ponytail: fnmatch's * also matches "/", so ".chart/**/values*.yaml" works without a ** parser.
    return all(any(fnmatch.fnmatchcase(f, g) for g in globs) for f in files)


def has_approval(reviews, author):
    """Latest non-comment review per reviewer; one APPROVED from someone other than the author."""
    latest = {}
    for r in reviews:  # API returns reviews in chronological order
        login = (r.get("user") or {}).get("login")
        if login and r.get("state") in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
            latest[login] = r["state"]
    return any(state == "APPROVED" and login != author for login, state in latest.items())


def failing_checks(required, check_runs, statuses):
    """Required contexts that are not green on the PR head (check run or commit status)."""
    green = {c["name"] for c in check_runs if c.get("conclusion") in PASSING_CONCLUSIONS}
    green |= {s["context"] for s in statuses if s.get("state") == "success"}
    return sorted(set(required) - green)


def triggering_human(runs, pushed_at):
    """The human who triggered the one workflow run that was active when the bot commit was made.
    Scheduled runs have no responsible human. Returns a login, or None when there's no unique match."""
    t = datetime.fromisoformat(pushed_at)  # commit timestamps carry an offset, run times use Z
    candidates = {
        r["triggering_actor"]["login"]
        for r in runs
        if r.get("event") != "schedule"
        and is_human(r.get("triggering_actor"))
        and datetime.fromisoformat(r["created_at"]) <= t <= datetime.fromisoformat(r["updated_at"])
    }
    return candidates.pop() if len(candidates) == 1 else None


def assignee_login(pr, pusher, bot_actor):
    """PR author -> merged_by -> human pusher -> triggering human of the bot run -> None (fallback)."""
    if pr:
        for user in (pr.get("user"), pr.get("merged_by")):
            if is_human(user):
                return user["login"]
        return None
    if is_human(pusher):
        return pusher["login"]
    return bot_actor


def email_for(login, users):
    """users = parsed tf/users.yaml (name -> {github: {username}, profile: {email}})."""
    for u in users.values():
        if ((u or {}).get("github") or {}).get("username", "").lower() == (login or "").lower():
            return (u.get("profile") or {}).get("email")
    return None


# ---------- I/O ----------


def http(method, url, headers, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={**headers, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
        return (json.loads(raw) if raw else None), resp.headers


class GitHub:
    def __init__(self, token, repo):
        self.repo = repo
        self.headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28"}

    def get(self, path, key=None):
        """GET with pagination. key selects the list inside an object response (e.g. check_runs)."""
        url, items = f"https://api.github.com/{path}", []
        while url:
            data, headers = http("GET", url, self.headers)
            if key is None and not isinstance(data, list):
                return data
            items += data if key is None else data[key]
            url = next((part.split(";")[0].strip(" <>") for part in headers.get("Link", "").split(",")
                        if 'rel="next"' in part), None)
        return items

    def required_contexts(self, branch):
        try:
            data = self.get(f"repos/{self.repo}/branches/{urllib.parse.quote(branch)}/protection/required_status_checks")
        except urllib.error.HTTPError as e:
            if e.code == 404:  # no required checks
                return []
            raise
        return sorted(set(data.get("contexts", [])) | {c["context"] for c in data.get("checks", [])})


class Jira:
    def __init__(self, base, email, token):
        auth = base64.b64encode(f"{email}:{token}".encode()).decode()
        self.base, self.headers = base.rstrip("/"), {"Authorization": f"Basic {auth}", "Accept": "application/json"}

    def account_id(self, email):
        if not email:
            return None
        users, _ = http("GET", f"{self.base}/rest/api/3/user/search?query={urllib.parse.quote(email)}", self.headers)
        exact = [u for u in users or [] if (u.get("emailAddress") or "").lower() == email.lower()]
        return (exact or users or [{}])[0].get("accountId")

    def exists(self, label):
        data, _ = http("POST", f"{self.base}/rest/api/3/search/jql", self.headers,
                       {"jql": f'project = COM AND labels = "{label}"', "maxResults": 1, "fields": ["key"]})
        return bool(data.get("issues"))

    def create(self, fields):
        data, _ = http("POST", f"{self.base}/rest/api/3/issue", self.headers, {"fields": fields})
        return data["key"]


def adf(lines):
    """Minimal Atlassian Document Format: one paragraph per line; (text, url) tuples become links."""
    def node(part):
        if isinstance(part, tuple):
            return {"type": "text", "text": part[0], "marks": [{"type": "link", "attrs": {"href": part[1]}}]}
        return {"type": "text", "text": part}
    return {"type": "doc", "version": 1,
            "content": [{"type": "paragraph", "content": [node(p) for p in line]} for line in lines]}


def load_users(gh):
    meta = gh.get(f"repos/{os.environ['USERS_REPO']}/contents/{os.environ['USERS_PATH']}")
    yaml_text = base64.b64decode(meta["content"]).decode()
    return json.loads(subprocess.run(["yq", "-o=json", "."], input=yaml_text, capture_output=True,
                                     text=True, check=True).stdout)


def main():
    event = json.load(open(os.environ["GITHUB_EVENT_PATH"]))
    repo, sha, before = os.environ["GITHUB_REPOSITORY"], event["after"], event["before"]
    branch, default = event["ref"].removeprefix("refs/heads/"), event["repository"]["default_branch"]
    if branch != default or event.get("deleted"):
        print(f"Not a push to the default branch ({event['ref']}); nothing to audit.")
        return
    dry_run = os.environ.get("DRY_RUN", "false").lower() == "true"
    gh = GitHub(os.environ["GH_TOKEN"], repo)
    server = f"https://github.com/{repo}"
    pusher_login = (event.get("sender") or {}).get("login") or event["pusher"]["name"]
    pusher = {"login": pusher_login, "type": (event.get("sender") or {}).get("type", "User")}

    prs = [p for p in gh.get(f"repos/{repo}/commits/{sha}/pulls")
           if p.get("merged_at") and p.get("merge_commit_sha") == sha]
    pr = gh.get(f"repos/{repo}/pulls/{prs[0]['number']}") if prs else None  # full object has merged_by
    reasons, bot_actor = [], None

    if event.get("forced"):
        reasons.append("force push to the default branch")
    if pr:
        if not has_approval(gh.get(f"repos/{repo}/pulls/{pr['number']}/reviews?per_page=100"), pr["user"]["login"]):
            reasons.append("merged without an approval from someone other than the author")
        head = pr["head"]["sha"]
        failing = failing_checks(gh.required_contexts(branch),
                                 gh.get(f"repos/{repo}/commits/{head}/check-runs?per_page=100", "check_runs"),
                                 gh.get(f"repos/{repo}/commits/{head}/status").get("statuses", []))
        if failing:
            reasons.append("required checks not green on the PR head: " + ", ".join(failing))
    elif not event.get("forced"):
        if is_human(pusher):
            reasons.append("direct push without a pull request")
        else:
            files = [f["filename"] for f in gh.get(f"repos/{repo}/compare/{before}...{sha}").get("files", [])]
            if bot_push_allowed(files, parse_allowlist(os.environ.get("ALLOWED_BOT_PUSHES"))):
                print(f"Allowlisted bot push by {pusher_login} ({len(files)} files); nothing to report.")
                return
            reasons.append(f"bot push by {pusher_login} changes files outside allowedBotPushes: "
                           + (", ".join(files[:10]) or "(empty commit)"))
            runs = gh.get(f"repos/{repo}/actions/runs?head_sha={before}&per_page=100", "workflow_runs")
            bot_actor = triggering_human(runs, event["head_commit"]["timestamp"]) if event.get("head_commit") else None

    if not reasons:
        print(f"{'PR #' + str(pr['number']) if pr else sha[:7]}: approved and green; nothing to report.")
        return

    login = assignee_login(pr, pusher, bot_actor)
    summary = (f"[Bypass merge] {repo.split('/')[1]}#{pr['number']}: {pr['title']}" if pr
               else f"[Bypass push] {repo.split('/')[1]}@{sha[:7]}")[:250]
    label = f"bypass-sha-{sha[:12]}"
    link = (f"PR #{pr['number']}", pr["html_url"]) if pr else (f"commit {sha[:7]}", f"{server}/commit/{sha}")
    description = [
        ["A change reached the default branch of ", (repo, server), " without the required review or checks: ", link, "."],
        ["Reasons: " + "; ".join(reasons) + "."],
        [f"Pushed by {pusher_login}" + (f", merged by {pr['merged_by']['login']}" if pr and pr.get("merged_by") else "")
         + f". Responsible: {login or 'not determined (fallback assignee)'}."],
        ["Please comment with a justification (e.g. incident, emergency fix, automation) and close this ticket."],
    ]
    try:
        email = email_for(login, load_users(gh)) if login else None
    except Exception as e:  # any lookup failure -> fallback, never a missing ticket
        print(f"::warning::users.yaml lookup for {login} failed ({e}); using the fallback.")
        email = None
    print(f"Bypass detected: {summary}\n  reasons: {reasons}\n  responsible: {login} <{email or 'fallback'}>")
    if dry_run:
        print("Dry run: no Jira calls, no ticket.")
        return

    jira = Jira(os.environ["JIRA_BASE_URL"], os.environ["JIRA_EMAIL"], os.environ["JIRA_TOKEN"])
    if jira.exists(label):
        print(f"A COM ticket with label {label} already exists; not creating a duplicate.")
        return
    fallback = jira.account_id(os.environ["FALLBACK_ASSIGNEE_EMAIL"])
    try:
        assignee = jira.account_id(email)
    except urllib.error.HTTPError as e:
        print(f"::warning::Jira user lookup for {email} failed ({e.code}); using the fallback.")
        assignee = None
    fields = {"project": {"key": "COM"}, "issuetype": {"name": "Task"}, "summary": summary,
              "labels": ["bypass-merge", label], "description": adf(description),
              "assignee": {"accountId": assignee or fallback}}
    try:
        key = jira.create(fields)
    except urllib.error.HTTPError as e:
        if e.code != 400 or fields["assignee"]["accountId"] == fallback:
            raise
        print(f"::warning::Creating with assignee {login} failed ({e.read().decode()[:200]}); using the fallback.")
        fields["assignee"] = {"accountId": fallback}
        key = jira.create(fields)
    print(f"Created {key}: {os.environ['JIRA_BROWSE_URL'].rstrip('/')}/browse/{key}")


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as e:
        sys.exit(f"::error::{e.code} {e.url}: {e.read().decode()[:500]}")
