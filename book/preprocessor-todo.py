#!/usr/bin/env python3
"""mdBook preprocessor: highlights TODO pages in the sidebar.

Mark pages as in-progress in SUMMARY.md by adding <!-- todo --> to the line:

    - [Getting Started](guide/getting_started.md) <!-- todo -->

The preprocessor injects a JSON list of todo paths into each page, which
todo.js reads to add badge elements that custom.css styles.
"""

import json
import re
import sys
from pathlib import Path


def collect_todo_paths(summary_path):
    """Return a sorted list of .html paths tagged with <!-- todo -->."""
    paths = []
    with open(summary_path) as f:
        for line in f:
            if "<!-- todo -->" in line.lower():
                m = re.search(r"\]\(([^)]+\.md)\)", line)
                if m:
                    paths.append(m.group(1).removesuffix(".md") + ".html")
    return sorted(paths)


def inject_todo_data(items, script_tag):
    for item in items:
        if not isinstance(item, dict):
            continue
        ch = item.get("Chapter")
        if ch is None:
            continue
        ch["content"] += script_tag
        inject_todo_data(ch.get("sub_items", []), script_tag)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "supports":
        sys.exit(0)

    context, book = json.loads(sys.stdin.read())

    root = Path(context["root"])
    src = context["config"]["book"].get("src", "src")
    summary_path = root / src / "SUMMARY.md"

    todo_paths = collect_todo_paths(summary_path)
    if todo_paths:
        data = json.dumps(todo_paths)
        script_tag = (
            f'\n<script class="todo-data" type="application/json">{data}</script>\n'
        )
        inject_todo_data(book["sections"], script_tag)

    print(json.dumps(book))


if __name__ == "__main__":
    main()
