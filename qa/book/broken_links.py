#!/usr/bin/env python3
"""Find broken markdown links in the Ragu book."""

import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple


class Link(NamedTuple):
    """A markdown link found in a file."""
    line_num: int
    text: str
    target: str


@dataclass
class BrokenLink:
    """A broken link with context."""
    source_file: Path
    line_num: int
    link_text: str
    target: str
    reason: str


def find_book_root() -> Path:
    """Find the book root directory (where book.toml lives) relative to this script."""
    script_dir = Path(__file__).resolve().parent
    # Script is in qa/book/, book root is in book/
    book_root = script_dir.parent.parent / "book"
    if not (book_root / "book.toml").exists():
        raise FileNotFoundError(f"book.toml not found at {book_root}")
    return book_root


def find_book_src() -> Path:
    """Find the book source directory relative to this script."""
    book_src = find_book_root() / "src"
    if not book_src.exists():
        raise FileNotFoundError(f"Book source directory not found at {book_src}")
    return book_src


def build_book(book_root: Path) -> Path:
    """Run mdbook build and return the path to the built output."""
    print("Building book with mdbook...")
    result = subprocess.run(
        ["mdbook", "build"],
        cwd=book_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"mdbook build failed:\n{result.stderr}", file=sys.stderr)
        raise RuntimeError("mdbook build failed")

    # Default output directory is 'book/' relative to book.toml
    build_dir = book_root / "book"
    if not build_dir.exists():
        raise FileNotFoundError(f"Build output not found at {build_dir}")
    return build_dir


def extract_anchors_from_html(html_file: Path) -> set[str]:
    """Extract all id attributes from an HTML file."""
    anchors = set()
    content = html_file.read_text()

    # Match id="..." attributes
    id_pattern = re.compile(r'\bid="([^"]+)"')
    for match in id_pattern.finditer(content):
        anchors.add(match.group(1))

    return anchors


def build_anchor_map(book_src: Path, build_dir: Path) -> dict[Path, set[str]]:
    """Build a map from source .md files to their HTML anchors."""
    anchor_map: dict[Path, set[str]] = {}

    for md_file in book_src.rglob('*.md'):
        # Map source path to HTML path
        # book/src/foo.md -> book/book/foo.html
        rel_path = md_file.relative_to(book_src)
        html_path = build_dir / rel_path.with_suffix('.html')

        if html_path.exists():
            anchor_map[md_file.resolve()] = extract_anchors_from_html(html_path)
        else:
            # File might not be in SUMMARY.md and thus not built
            anchor_map[md_file.resolve()] = set()

    return anchor_map


def parse_summary(summary_path: Path) -> set[Path]:
    """Extract all .md file paths listed in SUMMARY.md."""
    files = set()
    content = summary_path.read_text()

    # Match markdown links: [text](path.md) or [text](path.md#anchor)
    link_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')

    for match in link_pattern.finditer(content):
        target = match.group(2)
        # Strip anchor if present
        if '#' in target:
            target = target.split('#')[0]
        # Skip external URLs
        if target.startswith(('http://', 'https://', 'mailto:')):
            continue
        # Skip empty targets (anchor-only links)
        if not target:
            continue

        # Resolve relative to SUMMARY.md location
        resolved = (summary_path.parent / target).resolve()
        files.add(resolved)

    return files


def extract_links(md_file: Path) -> list[Link]:
    """Extract all internal markdown links from a file."""
    links = []
    content = md_file.read_text()
    lines = content.split('\n')

    # Pattern for inline links: [text](target)
    inline_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')

    # Pattern for reference definitions: [ref]: target
    ref_def_pattern = re.compile(r'^\[([^\]]+)\]:\s*(.+)$')

    # Pattern for reference usage: [text][ref] or [text][]
    ref_use_pattern = re.compile(r'\[([^\]]+)\]\[([^\]]*)\]')

    # Build reference map
    ref_map: dict[str, str] = {}
    for line in lines:
        match = ref_def_pattern.match(line.strip())
        if match:
            ref_name = match.group(1).lower()
            ref_target = match.group(2).strip()
            ref_map[ref_name] = ref_target

    for line_num, line in enumerate(lines, start=1):
        # Find inline links
        for match in inline_pattern.finditer(line):
            text = match.group(1)
            target = match.group(2)

            # Skip external URLs
            if target.startswith(('http://', 'https://', 'mailto:')):
                continue

            # Skip Rust crate references (contain ::)
            # These are processed by mdbook-rustdoc-link preprocessor
            if '::' in target:
                continue

            links.append(Link(line_num, text, target))

        # Find reference-style links
        for match in ref_use_pattern.finditer(line):
            text = match.group(1)
            ref_name = match.group(2) if match.group(2) else text
            ref_name = ref_name.lower()

            if ref_name in ref_map:
                target = ref_map[ref_name]

                # Skip external URLs
                if target.startswith(('http://', 'https://', 'mailto:')):
                    continue

                # Skip Rust crate references (contain ::)
                if '::' in target:
                    continue

                links.append(Link(line_num, text, target))

    return links


def validate_links(
    book_src: Path,
    summary_files: set[Path],
    anchor_map: dict[Path, set[str]],
) -> list[BrokenLink]:
    """Validate all links in the book and return broken ones."""
    broken = []

    # Find all markdown files in the book
    md_files = list(book_src.rglob('*.md'))

    for md_file in md_files:
        links = extract_links(md_file)

        for link in links:
            target = link.target
            anchor = None

            # Split target and anchor
            if '#' in target:
                parts = target.split('#', 1)
                target = parts[0]
                anchor = parts[1]

            # Handle anchor-only links (same file)
            if not target:
                target_path = md_file
            else:
                # Resolve relative path
                target_path = (md_file.parent / target).resolve()

            # Check if file exists
            if not target_path.exists():
                broken.append(BrokenLink(
                    source_file=md_file,
                    line_num=link.line_num,
                    link_text=link.text,
                    target=link.target,
                    reason="file not found"
                ))
                continue

            # Check if file is in SUMMARY.md (only for .md files, skip SUMMARY.md itself)
            if (target_path.suffix == '.md'
                    and target_path.name != 'SUMMARY.md'
                    and target_path not in summary_files):
                broken.append(BrokenLink(
                    source_file=md_file,
                    line_num=link.line_num,
                    link_text=link.text,
                    target=link.target,
                    reason="not in SUMMARY.md"
                ))
                # Continue to also check anchor if present

            # Check anchor if present (using HTML-extracted anchors)
            if anchor and target_path.suffix == '.md':
                valid_anchors = anchor_map.get(target_path, set())
                if anchor not in valid_anchors:
                    broken.append(BrokenLink(
                        source_file=md_file,
                        line_num=link.line_num,
                        link_text=link.text,
                        target=link.target,
                        reason=f"invalid anchor '#{anchor}'"
                    ))

    return broken


def main() -> int:
    """Main entry point."""
    try:
        book_root = find_book_root()
        book_src = find_book_src()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    summary_path = book_src / "SUMMARY.md"
    if not summary_path.exists():
        print(f"Error: SUMMARY.md not found at {summary_path}", file=sys.stderr)
        return 1

    print(f"Checking links in: {book_src}")

    # Build the book to get accurate anchor information
    try:
        build_dir = build_book(book_root)
    except (RuntimeError, FileNotFoundError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    # Parse SUMMARY.md to get list of included files
    summary_files = parse_summary(summary_path)
    print(f"Found {len(summary_files)} files in SUMMARY.md")

    # Build anchor map from HTML output
    anchor_map = build_anchor_map(book_src, build_dir)
    print(f"Extracted anchors from {len(anchor_map)} HTML files")

    # Validate all links
    broken = validate_links(book_src, summary_files, anchor_map)

    if not broken:
        print("\nNo broken links found!")
        return 0

    # Group by reason
    by_reason: dict[str, list[BrokenLink]] = {}
    for b in broken:
        by_reason.setdefault(b.reason, []).append(b)

    print(f"\nFound {len(broken)} broken link(s):\n")

    for reason, links in sorted(by_reason.items()):
        print(f"=== {reason.upper()} ({len(links)}) ===")
        for b in links:
            rel_source = b.source_file.relative_to(book_src)
            print(f"  {rel_source}:{b.line_num}")
            print(f"    [{b.link_text}]({b.target})")
        print()

    return 1


if __name__ == "__main__":
    sys.exit(main())
