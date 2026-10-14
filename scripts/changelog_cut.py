#!/usr/bin/env python3
"""Cut the CHANGELOG.md [Unreleased] section for a release.

Reads CHANGELOG.md on stdin and writes it on stdout, with a new
`## [VERSION] — DATE` section right under `## [Unreleased]`.

Usage: changelog_cut.py VERSION DATE NOTE [CHANGELOG_AT_TAG]

- Without CHANGELOG_AT_TAG, the whole [Unreleased] body moves under the new
  heading.
- With CHANGELOG_AT_TAG (the file as it was at the release tag), only the
  entries that were already in [Unreleased] at the tag move. An entry merged
  after the tag stays under [Unreleased], in its `### Category`. So the
  release PR can start from the current main, and does not conflict with the
  entries other PRs added since the tag. An entry is matched by its exact
  text, so an entry edited after the tag also stays under [Unreleased].
- NOTE is written under the new heading when no entry moves.

Called by scripts/release-bump.sh. Exit 1 when stdin has no `## [Unreleased]`.
"""

from __future__ import annotations

import sys

UNRELEASED = "## [Unreleased]"


def split(lines: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Lines up to and including `## [Unreleased]`, its body, and the rest."""
    start = lines.index(UNRELEASED)
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
        len(lines),
    )
    return lines[: start + 1], lines[start + 1 : end], lines[end:]


def is_blank(line: str) -> bool:
    return line.strip() == ""


def is_indented(line: str) -> bool:
    return line[:1] in (" ", "\t")


def is_item(line: str) -> bool:
    return line.startswith(("- ", "* "))


def blocks(body: list[str]) -> list[tuple[list[str], list[str], str]]:
    """Split a section body into blocks of (blank lines before, lines, kind).

    kind is `heading` (a `### Category` line), `item` (a top-level list entry
    with its indented continuation lines), or `other` (a paragraph or an HTML
    comment). A blank line belongs to a block only when an indented line
    follows it.
    """
    out = []
    i, n = 0, len(body)
    while i < n:
        start = i
        while i < n and is_blank(body[i]):
            i += 1
        blanks = body[start:i]
        if i == n:
            break
        first = body[i]
        i += 1
        if first.startswith("### "):
            out.append((blanks, [first], "heading"))
            continue
        kind = "item" if is_item(first) else "other"
        lines = [first]
        while i < n:
            line = body[i]
            if is_blank(line):
                j = i
                while j < n and is_blank(body[j]):
                    j += 1
                if j < n and is_indented(body[j]):
                    lines.extend(body[i:j])
                    i = j
                    continue
                break
            if is_indented(line) or (
                kind == "other" and not is_item(line) and not line.startswith("### ")
            ):
                lines.append(line)
                i += 1
                continue
            break
        out.append((blanks, lines, kind))
    return out


def key(lines: list[str]) -> str:
    return "\n".join(line.rstrip() for line in lines)


def select(found, released: set[str], want_released: bool) -> list[str]:
    """The lines of the blocks on one side of the cut.

    A `### Category` heading is kept only above a block it keeps.
    """
    out: list[str] = []
    heading = None
    for blanks, lines, kind in found:
        if kind == "heading":
            heading = blanks + lines
            continue
        if (key(lines) in released) != want_released:
            continue
        if heading is not None:
            out.extend(heading)
            heading = None
        out.extend(blanks + lines)
    return out


def trim(lines: list[str]) -> list[str]:
    start, end = 0, len(lines)
    while start < end and is_blank(lines[start]):
        start += 1
    while end > start and is_blank(lines[end - 1]):
        end -= 1
    return lines[start:end]


def main() -> int:
    if len(sys.argv) not in (4, 5):
        print(__doc__.splitlines()[5], file=sys.stderr)
        return 2
    version, date, note = sys.argv[1:4]
    lines = sys.stdin.read().split("\n")
    try:
        before, body, after = split(lines)
    except ValueError:
        print("changelog_cut: no '## [Unreleased]' heading", file=sys.stderr)
        return 1

    if len(sys.argv) == 5:
        with open(sys.argv[4], encoding="utf-8") as f:
            at_tag = f.read().split("\n")
        try:
            tag_body = split(at_tag)[1]
        except ValueError:
            tag_body = []
        released = {key(b) for _, b, kind in blocks(tag_body) if kind != "heading"}
        found = blocks(body)
        unreleased = trim(select(found, released, want_released=False))
        moved = trim(select(found, released, want_released=True))
    else:
        unreleased, moved = [], trim(body)

    out = list(before)
    if unreleased:
        out += [""] + unreleased
    out += ["", f"## [{version}] — {date}", ""]
    out += moved if moved else [note]
    if after:
        out += [""] + after
    else:
        out.append("")
    sys.stdout.write("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
