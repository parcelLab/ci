"""Unit tests for bypass_audit.py's decision logic. Run: python3 -m unittest scripts/test_bypass_audit.py"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import bypass_audit as ba  # noqa: E402

HUMAN = {"login": "alice", "type": "User"}
DEV_BOT = {"login": "parcellab-dev-bot", "type": "User"}
APP = {"login": "renovate[bot]", "type": "Bot"}


class AllowlistTest(unittest.TestCase):
    patterns = ba.parse_allowlist(".chart/**/values*.yaml\n# comment\nCHANGELOG.md\n")

    def test_all_files_must_match(self):
        self.assertTrue(ba.bot_push_allowed([".chart/app/prod/values.yaml", "CHANGELOG.md"], self.patterns))
        self.assertFalse(ba.bot_push_allowed([".chart/app/prod/values.yaml", "src/main.py"], self.patterns))

    def test_root_pattern_does_not_match_nested_file(self):
        self.assertFalse(ba.bot_push_allowed(["docs/CHANGELOG.md"], self.patterns))

    def test_empty_commit_needs_explicit_marker(self):
        self.assertFalse(ba.bot_push_allowed([], self.patterns))
        self.assertTrue(ba.bot_push_allowed([], self.patterns + ["<empty>"]))
        self.assertFalse(ba.bot_push_allowed([], []))


class ApprovalTest(unittest.TestCase):
    def review(self, login, state):
        return {"user": {"login": login}, "state": state}

    def test_approval_by_other_counts(self):
        self.assertTrue(ba.has_approval([self.review("bob", "APPROVED")], "alice"))

    def test_self_approval_and_comments_do_not_count(self):
        self.assertFalse(ba.has_approval([self.review("alice", "APPROVED"), self.review("bob", "COMMENTED")], "alice"))

    def test_latest_state_wins(self):
        self.assertFalse(ba.has_approval([self.review("bob", "APPROVED"), self.review("bob", "DISMISSED")], "alice"))
        self.assertTrue(ba.has_approval([self.review("bob", "CHANGES_REQUESTED"), self.review("bob", "APPROVED"),
                                         self.review("bob", "COMMENTED")], "alice"))


class ChecksTest(unittest.TestCase):
    def test_check_runs_and_statuses(self):
        runs = [{"name": "test", "conclusion": "success"}, {"name": "lint", "conclusion": "failure"},
                {"name": "docs", "conclusion": "skipped"}]
        statuses = [{"context": "ci/legacy", "state": "success"}]
        self.assertEqual(ba.failing_checks(["test", "lint", "docs", "ci/legacy", "missing"], runs, statuses),
                         ["lint", "missing"])

    def test_no_required_checks(self):
        self.assertEqual(ba.failing_checks([], [], []), [])


class TriggeringHumanTest(unittest.TestCase):
    def run_(self, login, event="workflow_dispatch", start="2026-11-11T09:00:00Z", end="2026-11-11T09:10:00Z"):
        return {"triggering_actor": {"login": login, "type": "User"}, "event": event,
                "created_at": start, "updated_at": end}

    def test_unique_human_with_offset_timestamp(self):
        self.assertEqual(ba.triggering_human([self.run_("alice")], "2026-11-11T10:05:00+01:00"), "alice")

    def test_scheduled_run_has_no_human(self):
        self.assertIsNone(ba.triggering_human([self.run_("alice", event="schedule")], "2026-11-11T09:05:00Z"))

    def test_outside_window_or_ambiguous(self):
        self.assertIsNone(ba.triggering_human([self.run_("alice")], "2026-11-11T09:20:00Z"))
        self.assertIsNone(ba.triggering_human([self.run_("alice"), self.run_("bob")], "2026-11-11T09:05:00Z"))
        self.assertEqual(ba.triggering_human([self.run_("alice"), self.run_("alice")], "2026-11-11T09:05:00Z"), "alice")


class AssigneeTest(unittest.TestCase):
    def test_chain(self):
        self.assertEqual(ba.assignee_login({"user": HUMAN, "merged_by": {"login": "bob"}}, DEV_BOT, None), "alice")
        self.assertEqual(ba.assignee_login({"user": APP, "merged_by": {"login": "bob", "type": "User"}}, DEV_BOT, None), "bob")
        self.assertIsNone(ba.assignee_login({"user": APP, "merged_by": DEV_BOT}, DEV_BOT, "carol"))
        self.assertEqual(ba.assignee_login(None, HUMAN, None), "alice")
        self.assertEqual(ba.assignee_login(None, DEV_BOT, "carol"), "carol")
        self.assertIsNone(ba.assignee_login(None, DEV_BOT, None))

    def test_email_lookup(self):
        users = {"Alice A": {"github": {"username": "Alice"}, "profile": {"email": "alice@example.com"}},
                 "No Github": {"profile": {"email": "x@example.com"}}}
        self.assertEqual(ba.email_for("alice", users), "alice@example.com")
        self.assertIsNone(ba.email_for("nobody", users))


if __name__ == "__main__":
    unittest.main()
