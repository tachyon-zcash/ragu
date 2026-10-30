"""Structured review evidence and exhaustive reconciliation; no model or GitHub access."""

import hashlib
import html
import json
import re
from pathlib import PurePosixPath
from urllib.parse import quote

REVIEWERS = ("code-review", "sean-review", "tal-review", "alex-review")
REVIEWER_NAMES = dict(zip(REVIEWERS, ("Code review", "Sean", "Tal", "Alex")))
RECONCILER = "reconcile"
MAX_FINDINGS = 64
PRIORITIES = ("P0", "P1", "P2", "P3")
CATEGORIES = ("correctness", "security", "documentation", "design", "performance", "testing")
DISPOSITIONS = ("must-fix", "suggestion", "dismissed")


def text_schema(limit, *, empty=False):
    return {"type": "string", "minLength": 0 if empty else 1, "maxLength": limit}


def obj(properties):
    return {"type": "object", "properties": properties, "required": list(properties), "additionalProperties": False}


LOCATION = obj({"path": text_schema(300), "line": {"type": "integer", "minimum": 1}})
DETAILS = {
    "title": text_schema(160), "priority": {"type": "string", "enum": list(PRIORITIES)},
    "category": {"type": "string", "enum": list(CATEGORIES)},
    "locations": {"type": "array", "items": LOCATION, "minItems": 1, "maxItems": 8},
    "cause": text_schema(1600), "evidence": text_schema(2400),
    "impact": text_schema(1600), "correction": text_schema(1600),
}
FINDING = obj({**DETAILS, "kind": {"type": "string", "enum": ["defect", "suggestion", "question"]}})
ASSESSMENT = obj({"finding_id": text_schema(80), "verdict": {"type": "string", "enum": ["support", "challenge"]},
                  "evidence": text_schema(2400)})
REVIEW_SCHEMA = obj({
    "complete": {"type": "boolean"}, "report": text_schema(64000),
    "findings": {"type": "array", "items": FINDING, "maxItems": MAX_FINDINGS},
    "assessments": {"type": "array", "items": ASSESSMENT, "maxItems": MAX_FINDINGS},
})
GROUP = obj({
    **DETAILS,
    "finding_ids": {"type": "array", "items": text_schema(80), "minItems": 1, "maxItems": MAX_FINDINGS * 4},
    "disposition": {"type": "string", "enum": list(DISPOSITIONS)},
    "rationale": text_schema(2400), "disagreement": text_schema(2400, empty=True),
})
RECONCILE_SCHEMA = obj({
    "complete": {"type": "boolean"}, "report": text_schema(8000),
    "groups": {"type": "array", "items": GROUP, "maxItems": MAX_FINDINGS * 4},
})


def validate(value, schema):
    """Check the bounded schema again in the controller, independent of the CLI."""
    kind = schema["type"]
    if kind == "object":
        if not isinstance(value, dict) or set(value) != set(schema["properties"]):
            raise ValueError("invalid structured report fields")
        for key, child in schema["properties"].items():
            validate(value[key], child)
    elif kind == "array":
        if not isinstance(value, list) or not schema.get("minItems", 0) <= len(value) <= schema["maxItems"]:
            raise ValueError("invalid structured report array")
        for child in value:
            validate(child, schema["items"])
    elif kind == "string":
        if not isinstance(value, str) or not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 32000):
            raise ValueError("invalid structured report text")
        if schema.get("minLength", 0) and not value.strip():
            raise ValueError("empty structured report text")
    elif kind == "integer":
        if type(value) is not int or value < schema["minimum"]:
            raise ValueError("invalid source line")
    elif kind == "boolean":
        if type(value) is not bool:
            raise ValueError("invalid completion value")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError("invalid structured report classification")


def locations(records):
    for record in records:
        if "\n" in record["title"] or "\r" in record["title"]:
            raise ValueError("finding titles must be a single line")
        for location in record["locations"]:
            path = location["path"]
            parts = PurePosixPath(path)
            if (parts.is_absolute() or ".." in parts.parts or str(parts) != path
                    or path == "." or "\\" in path or any(ord(char) < 32 for char in path)):
                raise ValueError("finding location must be a repository-relative path")
            yield location


def review(output, reviewer, core_ids=()):
    validate(output, REVIEW_SCHEMA)
    if reviewer not in REVIEWERS:
        raise ValueError("unknown reviewer")
    list(locations(output["findings"]))
    records = [{"id": f"{reviewer}:{index}", "reviewer": reviewer, **item}
               for index, item in enumerate(output["findings"], 1)]
    assessments = []
    seen = set()
    for item in output["assessments"]:
        if item["finding_id"] not in core_ids or item["finding_id"] in seen:
            raise ValueError("assessment must reference a unique core finding")
        seen.add(item["finding_id"])
        assessments.append({"reviewer": reviewer, **item})
    return records, assessments


def bundle(run, outputs):
    records, assessments, reviews = [], [], []
    core_ids = ()
    for reviewer in REVIEWERS:
        if reviewer not in outputs:
            continue
        output = outputs[reviewer]
        new, changes = review(output, reviewer, core_ids)
        if reviewer == REVIEWERS[0]:
            core_ids = [item["id"] for item in new]
        records.extend(new)
        assessments.extend(changes)
        reviews.append({"reviewer": reviewer})
    return {"run": run, "reviews": reviews, "findings": records, "assessments": assessments}


def reconcile(output, candidates):
    validate(output, RECONCILE_SCHEMA)
    list(locations(output["groups"]))
    known = {item["id"] for item in candidates["findings"]}
    challenged = {item["finding_id"] for item in candidates["assessments"] if item["verdict"] == "challenge"}
    seen = set()
    for group in output["groups"]:
        refs = group["finding_ids"]
        if len(set(refs)) != len(refs) or not set(refs) <= known or set(refs) & seen:
            raise ValueError("reconciliation contains duplicate or unknown finding references")
        if (set(refs) & challenged) and not group["disagreement"].strip():
            raise ValueError("reconciliation must account for a disagreement")
        seen.update(refs)
    if seen != known:
        raise ValueError("reconciliation must account for every finding exactly once")
    return output["groups"]


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


CODE_SPAN = re.compile(r"`[^`\n]+`")
# Bare code in prose: attributes, paths, calls, CONSTANTS, snake_case, and CamelCase names.
IDENTIFIER = re.compile(r"""(?<![\w/.`#-])(?:
    \#\[[^\[\]\s]+\]
  | [A-Za-z_]\w*(?:::[\w<>]+)+
  | [A-Za-z_]\w*\([\w, ]*\)
  | [A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+
  | [a-z][a-z0-9]*(?:_[a-z0-9]+)+
  | [A-Z][a-z0-9]+(?:[A-Z][a-z0-9]*)+
)(?![\w/]|\.\w)""", re.X)
PROPER_NOUNS = {"GitHub", "GitLab", "LaTeX", "OpenSSL", "JavaScript", "TypeScript", "WebAssembly", "MacOS"}


def escape(text):
    return html.escape(text, quote=False).replace("@", "&#64;").replace("![", "[")


def spans(text, transform):
    """Apply `transform` to the text between code spans; GitHub renders span contents literally."""
    parts, end = [], 0
    for match in CODE_SPAN.finditer(text):
        parts += [transform(text[end:match.start()]), match.group()]
        end = match.end()
    return "".join(parts + [transform(text[end:])])


def safe(text, limit=None):
    """Escape untrusted report text whole; verified reports are digested in this form."""
    text = escape(text)
    if limit is not None and len(text.encode()) > limit:
        text = text.encode()[:limit].decode("utf-8", errors="ignore") + "…"
        if text.count("`") % 2:
            text += "`"
    return text


def prose(text):
    """Untrusted finding prose for readers: single spaced, code identifiers in backticks, escaped."""
    mark = lambda part: IDENTIFIER.sub(lambda m: m.group() if m.group() in PROPER_NOUNS else f"`{m.group()}`", part)
    return spans(" ".join(text.split()), lambda part: escape(mark(part)))


def detail_lines(item):
    places = ", ".join(f"{safe(loc['path']).replace('`', '&#96;')}:{loc['line']}" for loc in item["locations"])
    return [f"Locations: {places}", "", *[
        f"**{label}:** {safe(item[key])}\n" for label, key in
        (("Cause", "cause"), ("Evidence", "evidence"), ("Impact", "impact"), ("Correction", "correction"))]]


def render_review(reviewer, output, core_ids=()):
    """Preserve the reviewer's Markdown; structured evidence stays in JSON."""
    review(output, reviewer, core_ids)
    return safe(output["report"]).rstrip() + "\n"


def render_reconciliation(output, candidates):
    groups = reconcile(output, candidates)
    lines = ["# Reconciliation", "", safe(output["report"]), ""]
    for index, item in enumerate(groups, 1):
        lines += [f"## R{index} · {item['disposition']} · {item['priority']}: {safe(item['title'])}", "",
                  "Original findings: " + ", ".join(item["finding_ids"]), "", *detail_lines(item), "",
                  "**Rationale:** " + safe(item["rationale"]), ""]
        if item["disagreement"]:
            lines += ["**Disagreement:** " + safe(item["disagreement"]), ""]
    return "\n".join(lines).rstrip() + "\n"


def combined(candidates):
    """Combine structured evidence without requiring another successful model call.

    Only exact causes/corrections at the same locations are merged. Different
    wording stays separate until the optional source check can adjudicate it.
    """
    challenges = {}
    for assessment in candidates["assessments"]:
        if assessment["verdict"] == "challenge":
            challenges.setdefault(assessment["finding_id"], []).append(assessment)
    buckets = {}
    for item in candidates["findings"]:
        key = (item["cause"].strip(), item["correction"].strip(),
               tuple(sorted({(loc["path"], loc["line"]) for loc in item["locations"]})))
        buckets.setdefault(key, []).append(item)
    groups = []
    for records in buckets.values():
        first = min(records, key=lambda item: PRIORITIES.index(item["priority"]))
        objections = [obj for item in records for obj in challenges.get(item["id"], [])]
        disagreements = [f"{obj['reviewer']}: {obj['evidence']}" for obj in objections]
        kinds = {item["kind"] for item in records}
        if "defect" in kinds and len(kinds) > 1:
            disagreements.append("Reviewers differ on whether this is a defect or a suggestion; verify the evidence before treating it as required.")
        places = []
        for item in records:
            for location in item["locations"]:
                if location not in places:
                    places.append(location)
        groups.append({**{key: first[key] for key in DETAILS}, "locations": places[:8],
                       "finding_ids": [item["id"] for item in records],
                       "disposition": "must-fix" if kinds == {"defect"} and not objections else "suggestion",
                       "disagreement": " ".join(disagreements),
                       "rationale": "Combined matching causes and corrections from the original reviewers; no additional source adjudication."})
    return groups


def attribution(candidates, item):
    originals = {record["id"]: record for record in candidates["findings"]}
    return ", ".join(REVIEWER_NAMES[name] for name in REVIEWERS
                     if any(originals[ref]["reviewer"] == name for ref in item["finding_ids"]))


def entry(candidates, item, *, located=True, location=None):
    """One retained finding for a reader: kind and reviewers, title, cause, fix, and any disagreement.

    A located entry links `location`, or the finding's first location by default.
    Validation notes and the priority stay in the reports; the priority only orders the list.
    """
    label = "Must-fix" if item["disposition"] == "must-fix" else "Suggestion"
    kind = f"**{label}** · {attribution(candidates, item)}"
    if located:
        loc = location or item["locations"][0]
        path = safe(PurePosixPath(loc["path"]).name).replace("[", "&#91;").replace("]", "&#93;")
        url = f"https://github.com/tachyon-zcash/ragu/blob/{candidates['run']['head']}/{quote(loc['path'], safe='/')}#L{loc['line']}"
        kind += f" · [{path}:{loc['line']}]({url})"
    lines = [kind, f"**{prose(item['title'])}**", prose(item["cause"]), "**Fix:** " + prose(item["correction"])]
    if item["disagreement"]:
        lines.append("**Disagreement:** " + prose(item["disagreement"]))
    return lines


def inline_body(candidates, item, cited=None):
    """The summary's entry as paragraphs, anchored to the finding's line instead of linking it.

    A comment anchored away from its finding, because the cited line or file is
    outside the diff, links the `cited` location instead.
    """
    return "\n\n".join(entry(candidates, item, located=cited is not None, location=cited))


def shortlist(candidates, groups=None, *, compact=False, heading_level=3, headings=True):
    """Show every retained finding, with merged attribution and bounded detail.

    Without `headings`, the must-fix and suggestion entries follow one another
    without their counted section headings, each still labelled by kind.
    """
    reconciled = groups is not None
    if not reconciled:
        groups = combined(candidates)
    active = [item for item in groups if item["disposition"] != "dismissed"]
    fixes = [item for item in active if item["disposition"] == "must-fix"]
    key = lambda item: (PRIORITIES.index(item["priority"]), item["title"])
    suggestions = sorted((item for item in active if item["disposition"] == "suggestion"), key=key)
    lines = []
    for label, items in (("Must-fix", sorted(fixes, key=key)), ("Suggestions", suggestions)):
        if headings:
            lines += [f"{'#' * heading_level} {label} ({len(items)})", ""]
            if not items:
                lines += ["None reported." if not reconciled else "None after reconciliation.", ""]
        for item in items:
            if compact:
                kind = "" if headings else ("Must-fix: " if label == "Must-fix" else "Suggestion: ")
                lines += [f"- {kind}**{safe(item['title'], 120)}** — {attribution(candidates, item)}", ""]
            else:
                first, *rest = entry(candidates, item)
                lines += [f"- {first}  ", *(f"  {line}  " for line in rest), ""]
    if compact:
        lines += ["Compact view: locations, evidence, corrections and disagreement details are in the full reports.", ""]
    return lines
