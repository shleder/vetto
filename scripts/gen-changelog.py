#!/usr/bin/env python3
"""
Conventional Commits Changelog Generator for Vetto.
Categorizes commits into Added, Fixed, Changed, Performance, and Security sections.
"""

import sys
import re
import subprocess
import argparse
import unittest


def parse_commit_line(line: str):
    """
    Parse a commit line in format 'hash subject' into category and description.
    Returns (category, clean_description, hash) or None.
    """
    line = line.strip()
    if not line:
        return None

    parts = line.split(" ", 1)
    if len(parts) == 2:
        chash, msg = parts[0], parts[1]
    else:
        chash, msg = "", parts[0]

    # Conventional commit regex: type(scope)?: description
    match = re.match(r"^([a-zA-Z]+)(?:\(([^)]+)\))?(!)?:\s*(.+)$", msg)
    if not match:
        return ("Other", msg, chash)

    ctype = match.group(1).lower()
    scope = match.group(2)
    breaking = match.group(3)
    desc = match.group(4).strip()

    if scope:
        formatted_desc = f"**{scope}**: {desc}"
    else:
        formatted_desc = desc

    if breaking:
        formatted_desc = f"**BREAKING**: {formatted_desc}"

    if ctype in ("feat", "feature"):
        category = "Added"
    elif ctype in ("fix", "bugfix"):
        category = "Fixed"
    elif ctype in ("perf", "performance"):
        category = "Performance"
    elif ctype in ("sec", "security"):
        category = "Security"
    elif ctype in ("refactor", "change", "style"):
        category = "Changed"
    elif ctype in ("docs", "doc"):
        category = "Documentation"
    elif ctype in ("chore", "ci", "test", "build"):
        category = "Maintenance"
    else:
        category = "Other"

    return (category, formatted_desc, chash)


def generate_changelog(commits: list) -> str:
    """Generate Markdown changelog from a list of raw commit lines."""
    categorized = {
        "Security": [],
        "Added": [],
        "Fixed": [],
        "Changed": [],
        "Performance": [],
        "Documentation": [],
        "Maintenance": [],
        "Other": []
    }

    for line in commits:
        res = parse_commit_line(line)
        if res:
            cat, desc, _ = res
            categorized[cat].append(desc)

    lines = []
    for section in ["Security", "Added", "Fixed", "Changed", "Performance", "Documentation"]:
        entries = categorized[section]
        if entries:
            lines.append(f"### {section}")
            for entry in entries:
                lines.append(f"- {entry}")
            lines.append("")

    return "\n".join(lines).strip()


def get_git_commits(commit_range: str = None) -> list:
    """Get commit lines from git log."""
    cmd = ["git", "log", "--oneline", "--no-merges"]
    if commit_range:
        cmd.append(commit_range)
    else:
        cmd.extend(["-n", "50"])

    try:
        out = subprocess.check_output(cmd, encoding="utf-8")
        return out.splitlines()
    except Exception as e:
        print(f"Error executing git log: {e}", file=sys.stderr)
        return []


class TestCommitParser(unittest.TestCase):
    def test_feat_commit(self):
        cat, desc, _ = parse_commit_line("abc1234 feat(tui): add full screen dashboard")
        self.assertEqual(cat, "Added")
        self.assertEqual(desc, "**tui**: add full screen dashboard")

    def test_fix_commit(self):
        cat, desc, _ = parse_commit_line("def5678 fix(sandbox): prevent Landlock bypass on procfs")
        self.assertEqual(cat, "Fixed")
        self.assertEqual(desc, "**sandbox**: prevent Landlock bypass on procfs")

    def test_sec_commit(self):
        cat, desc, _ = parse_commit_line("1112223 sec(credentials): scrub AWS keys from environment")
        self.assertEqual(cat, "Security")
        self.assertEqual(desc, "**credentials**: scrub AWS keys from environment")

    def test_breaking_commit(self):
        cat, desc, _ = parse_commit_line("9998887 feat(cli)!: change default net mode to off")
        self.assertEqual(cat, "Added")
        self.assertIn("**BREAKING**", desc)

    def test_changelog_generation(self):
        commits = [
            "111 feat(core): new capability",
            "222 fix(net): resolve dns leak",
            "333 perf(startup): reduce spawn latency"
        ]
        res = generate_changelog(commits)
        self.assertIn("### Added", res)
        self.assertIn("### Fixed", res)
        self.assertIn("### Performance", res)


def main():
    parser = argparse.ArgumentParser(description="Generate CHANGELOG.md entries from conventional commits.")
    parser.add_argument("range", nargs="?", help="Git commit range, e.g. v0.2.4..HEAD or HEAD~20..HEAD")
    parser.add_argument("--test", action="store_true", help="Run internal unit tests")

    args = parser.parse_args()

    if args.test:
        suite = unittest.TestLoader().loadTestsFromTestCase(TestCommitParser)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)

    commits = get_git_commits(args.range)
    if not commits:
        print("No commits found.")
        return

    print(generate_changelog(commits))


if __name__ == "__main__":
    main()
