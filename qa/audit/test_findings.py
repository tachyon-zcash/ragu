"""Check evidence accounting, disagreement retention, and bounded publication."""

import copy
import html
import unittest

import findings


def finding(**changes):
    return {"title": "Incorrect output", "kind": "defect", "priority": "P2", "category": "correctness",
            "locations": [{"path": "src/lib.rs", "line": 12}], "cause": "Wrong branch selected.",
            "evidence": "The zero input follows the nonzero branch.", "impact": "Produces a wrong result.",
            "correction": "Handle zero before selecting the branch.", **changes}


def review(*items, assessments=()):
    return {"complete": True, "report": "Source and affected callers reviewed; benchmark results weren't assessed.",
            "findings": list(items), "assessments": list(assessments)}


def group(*ids, **changes):
    item = finding()
    del item["kind"]
    return {**item, "finding_ids": list(ids), "disposition": "must-fix",
            "rationale": "Source supports the same cause and correction.", "disagreement": "", **changes}


class FindingsTests(unittest.TestCase):
    def setUp(self):
        self.run = {"head": "a" * 40}
        self.bundle = findings.bundle(self.run, {
            "code-review": review(finding()), "sean-review": review(finding()),
        })

    def reconcile(self, *groups):
        return findings.reconcile({"complete": True, "report": "Checked source.", "groups": list(groups)}, self.bundle)

    def test_ids_and_order_are_controller_assigned(self):
        self.assertEqual([item["id"] for item in self.bundle["findings"]], ["code-review:1", "sean-review:1"])
        forged = finding(id="code-review:9")
        with self.assertRaises(ValueError):
            findings.review(review(forged), "code-review")

    def test_duplicates_merge_and_keep_all_original_attribution(self):
        groups = self.reconcile(group("code-review:1", "sean-review:1"))
        text = "\n".join(findings.shortlist(self.bundle, groups))
        self.assertEqual(text.count("**Incorrect output**"), 1)
        self.assertIn("Code review, Sean", text)
        self.assertIn("### Must-fix", text)
        self.assertIn("### Suggestions", text)

    def test_combined_summary_merges_clear_duplicates_without_a_model(self):
        groups = findings.combined(self.bundle)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["finding_ids"], ["code-review:1", "sean-review:1"])
        text = "\n".join(findings.shortlist(self.bundle))
        self.assertEqual(text.count("**Incorrect output**"), 1)
        self.assertIn("Code review, Sean", text)

    def test_combination_does_not_guess_semantic_duplicates(self):
        self.bundle["findings"][1]["correction"] = "Use a different branch selection algorithm."
        self.assertEqual(len(findings.combined(self.bundle)), 2)

    def test_combination_keeps_classification_disagreements_visible(self):
        self.bundle["findings"][1]["kind"] = "question"
        text = "\n".join(findings.shortlist(self.bundle))
        self.assertNotIn("Incorrect output", text.split("### Suggestions")[0])
        self.assertIn("Reviewers differ", text)
        self.assertIn("Code review, Sean", text)

    def test_omitted_duplicate_and_unknown_ids_are_rejected(self):
        for groups in ((group("code-review:1"),), (group("code-review:1", "code-review:1", "sean-review:1"),),
                       (group("code-review:1", "sean-review:1", "invented:1"),),
                       (group("code-review:1", "sean-review:1"), group("sean-review:1"))):
            with self.subTest(groups=groups), self.assertRaises(ValueError):
                self.reconcile(*groups)

    def test_assessments_only_reference_unique_existing_core_ids(self):
        assessment = {"finding_id": "code-review:1", "verdict": "challenge", "evidence": "Existing test covers this case."}
        findings.review(review(assessments=[assessment]), "tal-review", ["code-review:1"])
        for ids, values in (([], [assessment]), (["code-review:1"], [assessment, assessment])):
            with self.assertRaises(ValueError):
                findings.review(review(assessments=values), "tal-review", ids)

    def test_challenges_cannot_disappear_from_decisions(self):
        self.bundle["assessments"] = [{"finding_id": "code-review:1", "reviewer": "tal-review", "verdict": "challenge",
                                       "evidence": "Existing test covers the case."}]
        with self.assertRaisesRegex(ValueError, "disagreement"):
            self.reconcile(group("code-review:1", "sean-review:1"))
        groups = self.reconcile(group("code-review:1", "sean-review:1", disposition="dismissed",
                                      disagreement="Tal's cited existing test defeats the test-gap claim."))
        text = "\n".join(findings.shortlist(self.bundle, groups))
        self.assertIn("None after reconciliation.", text)
        self.assertNotIn("**Incorrect output**", text)

    def test_fallback_keeps_challenged_claim_visible_as_a_suggestion(self):
        self.bundle["assessments"] = [{"finding_id": "code-review:1", "reviewer": "tal-review", "verdict": "challenge",
                                       "evidence": "Existing test covers the case."}]
        text = "\n".join(findings.shortlist(self.bundle))
        suggestions = text.split("### Suggestions")[1]
        self.assertIn("Incorrect output", suggestions)
        self.assertIn("Existing test covers the case.", suggestions)
        self.assertIn("**Disagreement:**", suggestions)

    def test_source_links_are_pinned_and_paths_cannot_escape_checkout(self):
        text = "\n".join(findings.shortlist(self.bundle))
        self.assertIn(f"/blob/{self.run['head']}/src/lib.rs#L12", text)
        for path in ("/private/key", "../key", "src/../key", "src//lib.rs", "./src/lib.rs", ".", "src\\key", "src/\nkey"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                findings.review(review(finding(locations=[{"path": path, "line": 1}])), "code-review")
        with self.assertRaises(ValueError):
            findings.review(review(finding(locations=[{"path": "lib.rs", "line": True}])), "code-review")

    def test_multiline_titles_and_oversized_findings_fail_validation(self):
        for changes in ({"title": "Fake\n### Status"}, {"evidence": "x" * 2401}, {"priority": "urgent"}):
            with self.assertRaises(ValueError):
                findings.review(review(finding(**changes)), "code-review")
        with self.assertRaises(ValueError):
            findings.review(review(*[finding()] * 65), "code-review")

    def test_compact_view_retains_all_256_findings_and_stays_bounded(self):
        # Keep titles within the schema's character cap but stress UTF-8 bytes.
        for kind in ("defect", "suggestion"):
            with self.subTest(kind=kind):
                bundle = findings.bundle(self.run, {name: review(*[
                    finding(kind=kind, title=f"Finding {index}: " + "界" * 120, cause=f"Unique cause: {name}:{index}")
                    for index in range(64)]) for name in findings.REVIEWERS})
                text = "\n".join(findings.shortlist(bundle, compact=True))
                self.assertEqual(text.count("- **"), 256)
                self.assertLess(len(text.encode()), 54000)

    def test_all_suggestions_and_disagreements_remain_visible(self):
        bundle = findings.bundle(self.run, {"code-review": review(*[finding(kind="suggestion", title=f"Suggestion {n}", cause=f"Cause {n}") for n in range(6)])})
        bundle["assessments"] = [{"finding_id": "code-review:6", "reviewer": "tal-review", "verdict": "challenge", "evidence": "Disputed."}]
        text = "\n".join(findings.shortlist(bundle))
        self.assertEqual(text.count("- **"), 6)
        for n in range(6):
            self.assertIn(f"Suggestion {n}", text)
        self.assertIn("Disputed.", text)
        self.assertNotIn("Additional suggestions", text)

    def test_publication_escapes_html_mentions_and_remote_images(self):
        bundle = findings.bundle(self.run, {"code-review": review(finding(title="<script>alert(1)</script> @team ![track](https://example.invalid/x)"))})
        text = "\n".join(findings.shortlist(bundle))
        self.assertNotIn("<script>", text)
        self.assertNotIn("@team", text)
        self.assertNotIn("![", text)
        self.assertIn("&lt;script&gt;", text)

    def test_markup_cannot_be_reassembled_from_untrusted_text(self):
        # Each payload once escaped into a live image, raw HTML, or a mention on GitHub.
        payloads = [
            "!![x](https://e.example/a.png) !!![x](u) [!![x](u)](l)",
            "&#64;octocat &commat;octocat @octocat",
            "\\`<img src=\"https://e.example/b.png\" width=\"900\">` and \\`@octocat` ping",
            "double ``@octocat` here and ``<img src=\"https://e.example/c.png\">` there",
            "Badge \\`![badge](https://e.example/d.png)`",
            "`<b>X</b>`CamelCase`x",
            "\\`<details><summary>Verified by maintainers</summary>`",
            "Odd `quote",
        ]
        def assert_inert(text):
            text = text.replace("<code>", "").replace("</code>", "")
            self.assertNotIn("<", text)
            self.assertNotIn("![", text)
            # GitHub decodes entities before it links mentions.
            self.assertNotRegex(html.unescape(text), r"@\w")
        for payload in payloads:
            with self.subTest(payload=payload):
                assert_inert(findings.safe(payload))
                text = findings.prose(payload)
                assert_inert(text)
                # Nothing left that Markdown could pair or escape across fields.
                self.assertNotIn("`", text)
                self.assertNotIn("\\", text)
                bundle = findings.bundle(self.run, {"code-review": review(finding(title=payload, cause=payload, correction=payload))})
                assert_inert("\n".join(findings.shortlist(bundle)))
                assert_inert("\n".join(findings.shortlist(bundle, compact=True)))

    def test_raw_markdown_review_is_preserved_with_metadata_separate(self):
        markdown = """## General review

**Verdict:** One must-fix.

### Must-fix
1. **Incorrect output.** The zero input selects the wrong branch.
   - `src/lib.rs:12`: handle zero before selecting the branch.

### Suggestions
None.

### Checks and limitations
Source and affected callers reviewed. Benchmark results weren't assessed.
"""
        output = review(finding())
        output["report"] = markdown
        text = findings.render_review("code-review", output)
        self.assertEqual(text, markdown)
        self.assertNotIn("**Cause:**", text)
        records, _ = findings.review(output, "code-review")
        self.assertEqual(records[0]["cause"], "Wrong branch selected.")
        bundle = findings.bundle(self.run, {"code-review": output})
        self.assertEqual(bundle["reviews"], [{"reviewer": "code-review"}])
        self.assertEqual(bundle["findings"], records)

    def test_decision_artifact_preserves_dismissal_reasons(self):
        output = {"complete": True, "report": "Source checked.", "groups": [group("code-review:1", "sean-review:1", disposition="dismissed", rationale="Existing test proves coverage.")]}
        text = findings.render_reconciliation(output, self.bundle)
        self.assertIn("Existing test proves coverage.", text)
        self.assertIn("code-review:1, sean-review:1", text)
        changed = copy.deepcopy(output)
        changed["groups"][0]["rationale"] = "Different reason."
        self.assertNotEqual(findings.fingerprint(output), findings.fingerprint(changed))

    def test_prose_marks_identifiers_and_keeps_code_spans_literal(self):
        text = findings.prose("RegistryTags keeps `Vec<u32>` and with_registry_tags; NATIVE_EXTENSION = 0 in\n"
                              "tests/profile_layout.rs, see #[doc(hidden)] and Application::context on GitHub <b>@team</b>")
        self.assertEqual(text, "<code>RegistryTags</code> keeps <code>Vec&lt;u32&gt;</code> and <code>with&#95;registry&#95;tags</code>; "
                               "<code>NATIVE&#95;EXTENSION</code> = 0 in tests/profile_layout.rs, see <code>#&#91;doc(hidden)&#93;</code> "
                               "and <code>Application::context</code> on GitHub &lt;b&gt;@\u200bteam&lt;/b&gt;")
        self.assertEqual((findings.prose("`<a>` <a>"), findings.safe("`<a>`")), ("<code>&lt;a&gt;</code> &lt;a&gt;", "`&lt;a&gt;`"))
        self.assertTrue(findings.safe("`long code span here`", 8).endswith("…`"))


if __name__ == "__main__":
    unittest.main()
