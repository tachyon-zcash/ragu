"""Exercise inline publication, exact diff anchors, and duplicate recovery."""

import copy
import os
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import findings
import github
import runner
import test_audit
from test_audit import APP, BASE, HEAD, candidate, native
from test_findings import group


class InlineTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_audit.AuditTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.api, self.out = self.fixture.api, self.fixture.out
        self.api.files = [{"filename": "src/lib.rs", "status": "modified", "patch": "@@ -1 +1 @@\n-old\n+new"}]
        self.run = github.queue(self.api, 9, HEAD, 12)

    def reports(self, *items):
        result = native()
        result["structured_output"]["findings"] = list(items or [candidate()])
        self.fixture.reports(self.run, {name: copy.deepcopy(result) for name in runner.SKILLS})

    def publish(self, result="success"):
        github.publish(self.api, self.run, self.out, result)

    def test_diff_parser_tracks_head_lines_across_hunks_and_deletions(self):
        files = [{"filename": "renamed.rs", "previous_filename": "old.rs", "status": "renamed",
                  "patch": "@@ -2,3 +2,4 @@\n context\n-old\n+new\n+extra\n context\n@@ -20 +30 @@\n-old\n+new\n\\ No newline at end of file"},
                 {"filename": "deleted.rs", "status": "removed", "patch": "@@ -1 +0,0 @@\n-old"},
                 {"filename": "binary", "status": "modified"}]
        self.assertEqual(github.diff_lines(files), {("renamed.rs", line) for line in (2, 3, 4, 5, 30)})

    def test_combined_finding_is_inline_once_with_all_reviewers_and_evidence(self):
        self.reports()
        self.publish()
        self.assertEqual(len(self.api.reviews), 1)
        self.assertEqual(len(self.api.review_comments), 1)
        comment = self.api.review_comments[0]
        self.assertEqual((comment["path"], comment["line"], comment["side"], comment["commit_id"]),
                         ("src/lib.rs", 1, "RIGHT", HEAD))
        self.assertTrue(comment["body"].startswith(
            "**Must-fix** · Code review, Sean, Tal, Alex\n\n**Incorrect result**\n\nA concrete cause.\n\n**Fix:** Correct the operation."))
        for text in ("A reachable counterexample.", "[P", "Locations", "src/lib.rs"):  # Validation notes stay in the reports.
            self.assertNotIn(text, comment["body"])
        bundle = runner.candidates(self.run, self.out)
        self.assertEqual(comment["body"], findings.inline_body(bundle, findings.combined(bundle)[0]))
        summary = self.api.comments[0]["body"]
        self.assertIn("**Must-fix: 1 · Suggestions: 0** · 1 finding posted inline", summary)
        self.assertIn("#pullrequestreview-200", summary)
        self.assertIn("### For humans\n\n**Must-fix: 1 · Suggestions: 0**", summary)
        for text in ("**Incorrect result**", "#### Must-fix", "#### Suggestions"):
            self.assertNotIn(text, summary)
        self.assertIn("### For agents", summary)
        self.assertEqual(self.api.checks[0]["conclusion"], "success")

    def test_reconciliation_controls_disposition_location_and_disagreement(self):
        self.reports()
        item = group(*[f"{name}:1" for name in runner.SKILLS], disposition="suggestion", title="Reconciled concern",
                     locations=[{"path": "outside.rs", "line": 99}, {"path": "src/lib.rs", "line": 1}],
                     disagreement="The evidence does not settle this concern.")
        self.fixture.reconciliation(self.run, [item])
        self.publish()
        comment = self.api.review_comments[0]
        self.assertEqual((comment["path"], comment["line"]), ("src/lib.rs", 1))
        self.assertIn("**Suggestion** · ", comment["body"])
        self.assertIn("Reconciled concern", comment["body"])
        self.assertIn("**Disagreement:** The evidence does not settle", comment["body"])
        self.assertNotIn("outside.rs:99", comment["body"])
        self.assertIn("Must-fix: 0 · Suggestions: 1", self.api.comments[0]["body"])

    def test_dismissed_findings_do_not_create_reviews(self):
        self.reports()
        self.fixture.reconciliation(self.run, [group(*[f"{name}:1" for name in runner.SKILLS], disposition="dismissed")])
        self.publish()
        self.assertEqual(self.api.reviews, [])
        body = self.api.comments[0]["body"]
        self.assertIn("### For humans\n\n**Must-fix: 0 · Suggestions: 0**", body)
        self.assertIn("1 finding group dismissed", body)
        self.assertNotIn("#### Must-fix", body)

    def test_anchor_prefers_exact_lines_then_the_nearest_line_of_a_cited_file(self):
        available = {("a.rs", 10), ("a.rs", 20), ("b.rs", 5)}
        outside, near, exact = {"path": "c.rs", "line": 1}, {"path": "a.rs", "line": 16}, {"path": "b.rs", "line": 5}
        self.assertEqual(github.anchor([outside, near, exact], available), ("b.rs", 5, None))
        self.assertEqual(github.anchor([outside, near], available), ("a.rs", 20, near))
        self.assertEqual(github.anchor([{"path": "a.rs", "line": 15}], available), ("a.rs", 10, {"path": "a.rs", "line": 15}))
        self.assertEqual(github.anchor([outside], available), ("a.rs", 10, outside))
        self.assertIsNone(github.anchor([outside], set()))

    def test_findings_citing_untouched_files_anchor_to_the_nearest_changed_file(self):
        available = {("src/x/a.rs", 3), ("src/b.rs", 9), ("src/b.rs", 7), ("other/c.rs", 1)}
        sibling = {"path": "src/y.rs", "line": 40}
        self.assertEqual(github.anchor([sibling], available), ("src/b.rs", 7, sibling))
        nested = {"path": "src/x/z.rs", "line": 2}
        self.assertEqual(github.anchor([sibling, nested], available), ("src/x/a.rs", 3, nested))
        self.assertEqual(github.anchor([{"path": "other/d.rs", "line": 5}, sibling], available),
                         ("other/c.rs", 1, {"path": "other/d.rs", "line": 5}))

    def test_findings_outside_hunks_anchor_to_the_nearest_line_and_link_the_cited_line(self):
        self.reports(candidate(), candidate(title="Outside hunk", cause="Different cause",
                                           locations=[{"path": "src/lib.rs", "line": 90}]))
        self.publish()
        self.assertEqual(len(self.api.review_comments), 2)
        moved = next(item for item in self.api.review_comments if "Outside hunk" in item["body"])
        self.assertEqual((moved["path"], moved["line"]), ("src/lib.rs", 1))
        self.assertIn(f"[lib.rs:90](https://github.com/tachyon-zcash/ragu/blob/{HEAD}/src/lib.rs#L90)", moved["body"])
        exact = next(item for item in self.api.review_comments if "Incorrect result" in item["body"])
        self.assertNotIn("lib.rs:", exact["body"])
        summary = self.api.comments[0]["body"]
        self.assertIn("2 findings posted inline", summary)
        for text in ("**Outside hunk**", "**Incorrect result**", "outside this PR's diff", "#### Must-fix"):
            self.assertNotIn(text, summary)

    def test_findings_citing_only_files_outside_the_diff_are_posted_inline(self):
        self.reports(candidate(), candidate(title="Untouched file", cause="Different cause",
                                           locations=[{"path": "src/other.rs", "line": 3}]))
        self.publish()
        self.assertEqual(len(self.api.review_comments), 2)
        moved = next(item for item in self.api.review_comments if "Untouched file" in item["body"])
        self.assertEqual((moved["path"], moved["line"]), ("src/lib.rs", 1))
        self.assertIn(f"[other.rs:3](https://github.com/tachyon-zcash/ragu/blob/{HEAD}/src/other.rs#L3)", moved["body"])
        summary = self.api.comments[0]["body"]
        self.assertIn("### For humans\n\n**Must-fix: 2 · Suggestions: 0** · 2 findings posted inline", summary)
        self.assertIn("### For agents", summary)
        for text in ("**Untouched file**", "**Incorrect result**", "kept here", "#### Must-fix", "#### Suggestions"):
            self.assertNotIn(text, summary)

    def test_a_diff_without_commentable_lines_keeps_findings_in_the_summary(self):
        self.api.files = [{"filename": "src/lib.rs", "status": "removed", "patch": "@@ -1 +0,0 @@\n-old"}]
        self.reports()
        self.publish()
        self.assertEqual(self.api.review_comments, [])
        summary = self.api.comments[0]["body"]
        self.assertIn("### For humans\n\n**Must-fix: 1 · Suggestions: 0**", summary)
        self.assertIn("The reviewed diff has no commentable lines, so these findings are kept here.", summary)
        self.assertIn("**Incorrect result**", summary)
        self.assertIn("### For agents", summary)

    def test_republication_and_reused_reports_do_not_duplicate_inline_threads(self):
        self.reports()
        self.publish()
        self.publish()
        summary = copy.deepcopy(self.api.comments[0])
        threads = copy.deepcopy(self.api.review_comments)
        with patch.dict(os.environ, {"GITHUB_RUN_ID": str(self.run["run_id"] + 1)}):
            self.run = github.queue(self.api, 9, HEAD, 12)
            self.reports()
            self.publish()
        self.assertEqual(len(self.api.reviews), 1)
        self.assertEqual(len(self.api.review_comments), 1)
        self.assertEqual(self.api.review_comments, threads)
        self.assertEqual(len(self.api.comments), 2)
        self.assertEqual(self.api.comments[0], summary)
        for comment in self.api.comments:
            self.assertIn("1 finding posted inline", comment["body"])

    def test_new_snapshot_preserves_earlier_summary_and_inline_threads(self):
        self.reports()
        self.publish()
        summary = copy.deepcopy(self.api.comments[0])
        thread = copy.deepcopy(self.api.review_comments[0])
        self.api.target["head"]["sha"] = "c" * 40
        with patch.dict(os.environ, {"GITHUB_RUN_ID": str(self.run["run_id"] + 1)}):
            self.run = github.queue(self.api, 9, "c" * 40, 12)
            self.reports()
            self.publish()
        self.assertEqual(len(self.api.comments), 2)
        self.assertEqual(len(self.api.reviews), 2)
        self.assertEqual(len(self.api.review_comments), 2)
        self.assertEqual(self.api.comments[0], summary)
        self.assertEqual(self.api.review_comments[0], thread)
        self.assertEqual(self.api.review_comments[1]["commit_id"], "c" * 40)
        self.assertIn(github.invocation_marker(self.run), self.api.comments[1]["body"])

    def test_lost_creation_response_recovers_without_another_post(self):
        self.reports()
        call = self.api.call

        def lose_response(path, data=None, method=None):
            result = call(path, data, method)
            if path.endswith("/reviews") and method == "POST":
                raise OSError("response lost after creation")
            return result

        with patch.object(self.api, "call", side_effect=lose_response):
            self.publish()
        self.assertEqual(len(self.api.reviews), 1)
        self.assertEqual(self.api.checks[0]["conclusion"], "success")

    def test_human_replies_do_not_prevent_reusing_an_existing_review(self):
        self.reports()
        self.publish()
        comment = self.api.review_comments[0]
        self.api.review_comments.append({**comment, "id": 999, "in_reply_to_id": comment["id"],
                                         "user": {"type": "User", "login": "alice"}, "body": "Fixed."})
        self.publish()
        self.assertEqual(len(self.api.reviews), 1)
        self.assertEqual(self.api.checks[0]["conclusion"], "success")

    def test_failed_creation_keeps_verified_findings_and_fails_completion(self):
        self.reports()
        call = self.api.call

        def reject(path, data=None, method=None):
            if path.endswith("/reviews"):
                raise HTTPError(path, 422, "Invalid comment", {}, None)
            return call(path, data, method)

        with patch.object(self.api, "call", side_effect=reject), self.assertRaises(HTTPError):
            self.publish()
        self.assertEqual(self.api.checks[0]["conclusion"], "failure")
        self.assertIn("audit: publication failed", self.api.comments[0]["body"])
        self.assertIn("**Incorrect result**", self.api.comments[0]["body"])

    def test_missing_or_modified_remote_comments_cannot_grant_completion(self):
        self.reports()
        self.publish()
        reviews, comments = copy.deepcopy(self.api.reviews), copy.deepcopy(self.api.review_comments)
        for change in ("missing", "body", "commit", "author", "review_state"):
            with self.subTest(change=change):
                self.api.reviews, self.api.review_comments = copy.deepcopy(reviews), copy.deepcopy(comments)
                if change == "missing":
                    self.api.review_comments.clear()
                elif change == "review_state":
                    self.api.reviews[0]["state"] = "PENDING"
                else:
                    key, value = {"body": ("body", "modified"), "commit": ("commit_id", "c" * 40),
                                  "author": ("user", {"type": "Bot", "login": "another-app[bot]"})}[change]
                    self.api.review_comments[0][key] = value
                with self.assertRaises(ValueError):
                    self.publish()
                self.assertEqual(len(self.api.reviews), 1)
                self.assertEqual(self.api.checks[0]["conclusion"], "failure")

    def test_human_or_foreign_marker_is_not_reused(self):
        self.reports()
        self.publish()
        self.api.reviews[0]["user"] = {"type": "User", "login": APP["slug"] + "[bot]"}
        self.publish()
        self.assertEqual(len(self.api.reviews), 2)

    def test_branch_updates_publish_the_same_findings_on_the_frozen_diff(self):
        self.reports()
        self.api.comparisons[f"{BASE}...{HEAD}"] = copy.deepcopy(self.api.files)
        self.api.target["head"]["sha"] = "c" * 40
        self.api.main_sha = "d" * 40
        self.api.files = [{"filename": "src/lib.rs", "status": "modified", "patch": "@@ -90 +90 @@\n-old\n+new"}]
        call = self.api.call

        def frozen_only(path, data=None, method=None):
            if data is None and ("/compare/" in path or "/pulls/" in path):
                self.assertEqual(path, f"/repos/{github.REPOSITORY}/compare/{BASE}...{HEAD}?per_page=1")
            return call(path, data, method)

        with patch.object(self.api, "call", side_effect=frozen_only):
            self.publish()
        comment = self.api.review_comments[0]
        self.assertEqual((comment["path"], comment["line"], comment["commit_id"]), ("src/lib.rs", 1, HEAD))
        self.assertIn("1 finding posted inline", self.api.comments[0]["body"])
        self.assertNotIn("**Incorrect result**", self.api.comments[0]["body"])
        self.assertNotIn("stale", self.api.comments[0]["body"])
        self.assertEqual(self.api.checks[0]["conclusion"], "success")

    def test_head_movement_before_review_creation_preserves_inline_publication(self):
        self.reports()
        call = self.api.call

        def move_head(path, data=None, method=None):
            result = call(path, data, method)
            if "/compare/" in path:
                self.api.target["head"]["sha"] = "c" * 40
            return result

        with patch.object(self.api, "call", side_effect=move_head):
            self.publish()
        self.assertEqual(self.api.review_comments[0]["commit_id"], HEAD)
        self.assertIn("audit: completed", self.api.comments[0]["body"])
        self.assertEqual(self.api.checks[0]["conclusion"], "success")

    def test_outdated_or_moved_threads_are_verified_at_their_original_location(self):
        self.reports()
        self.publish()
        comment = self.api.review_comments[0]
        comment.update(original_commit_id=HEAD, original_line=1, commit_id="c" * 40)
        self.api.target["head"]["sha"] = "c" * 40
        for line in (None, 90):
            with self.subTest(line=line):
                comment["line"] = line
                self.publish()
                self.assertEqual(len(self.api.reviews), 1)
                self.assertEqual(self.api.checks[0]["conclusion"], "success")
        comment["original_line"] = 2
        with self.assertRaisesRegex(ValueError, "inline review comments were not confirmed"):
            self.publish()

    def test_cancelled_command_does_not_create_inline_comments(self):
        self.reports()
        self.api.comment = None
        with self.assertRaises(github.CancelledReview):
            self.publish()
        self.assertEqual(self.api.reviews, [])

    def test_partial_reviews_publish_only_verified_completed_findings(self):
        self.reports()
        receipt = runner.read_json(self.out / "receipt.json")
        receipt["phases"] = receipt["phases"][:1]
        runner.write_json(self.out / "receipt.json", receipt)
        with self.assertRaisesRegex(ValueError, "audit did not complete"):
            self.publish("failure")
        self.assertEqual(len(self.api.review_comments), 1)
        self.assertIn("Code review", self.api.review_comments[0]["body"])
        self.assertNotIn("Sean", self.api.review_comments[0]["body"])
        self.assertEqual(self.api.checks[0]["conclusion"], "failure")

    def test_inline_text_escapes_mentions_html_and_images(self):
        self.reports(candidate(cause="<script>unsafe</script> @team ![image](https://example.com/image)"))
        self.publish()
        body = self.api.review_comments[0]["body"]
        self.assertNotIn("<script>", body)
        self.assertNotIn("@team", body)
        self.assertNotIn("![", body)
        self.assertIn("&lt;script&gt;", body)

    def test_large_finding_sets_are_batched_and_every_comment_is_preserved(self):
        self.reports(*[candidate(title=f"Concern {n}", cause=f"Cause {n}") for n in range(64)])
        self.publish()
        self.assertEqual(len(self.api.reviews), 2)
        self.assertEqual(len(self.api.review_comments), 64)
        self.assertIn("64 findings posted inline", self.api.comments[0]["body"])
        self.publish()
        self.assertEqual(len(self.api.reviews), 2)

    def test_large_unicode_and_escaped_finding_fits_the_comment_limit(self):
        locations = [{"path": "/".join(["界" * 30] * 9) + f"/{n}.rs", "line": 1} for n in range(8)]
        self.api.files[0]["filename"] = locations[0]["path"]
        self.reports(candidate(locations=locations))
        item = group(*[f"{name}:1" for name in runner.SKILLS], locations=locations,
                     cause="<" * 1600, evidence="<" * 2400, impact="<" * 1600,
                     correction="<" * 1600, rationale="<" * 2400, disagreement="<" * 2400)
        self.fixture.reconciliation(self.run, [item])
        self.publish()
        body = self.api.review_comments[0]["body"]
        self.assertLess(len(body.encode()), 65536)
        self.assertNotIn("…", body)  # Nothing is cut off; the schema bounds each field.


if __name__ == "__main__":
    unittest.main()
