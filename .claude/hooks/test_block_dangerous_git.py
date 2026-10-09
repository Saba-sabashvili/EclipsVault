"""Tests for block-dangerous-git.py, driven through its real interface: JSON on stdin, exit code out.

Run: python3 -m unittest discover -s .claude/hooks -p 'test_*.py'
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

HOOK = Path(__file__).with_name("block-dangerous-git.py")

BLOCKED = [
    "git push --force",
    "git push -f origin main",
    "git push -uf origin feature",
    "git push origin feature --force-with-lease",
    "git push origin +main",
    "git push origin +HEAD:main",
    "git push -d origin old-branch",
    "git push --delete origin old-branch",
    "git push origin --delete old-branch",
    "git push origin :old-branch",
    "git push --mirror",
    "git push --prune origin",
    "git -C /tmp/repo push --force",
    "git -c core.sshCommand=ssh push -f",
    "/usr/bin/git push --force",
    "FOO=1 git push --force",
    "cd repo && git push --force",
    "git status; git push --force",
    "git status\ngit push --force",
    'bash -c "git push --force"',
    "sh -c 'git -C x push origin +main'",
    'zsh -lc "git reset --hard"',
    'eval "git push --force"',
    "echo $(git push --force)",
    "echo `git push --force`",
    "git push origin main > /tmp/log --force",
    "git push origin main 2>&1 --force",
    "(git status);git push -f",
    "git branch -D old",
    "git branch --delete --force old",
    "git branch -d -f old",
    "git branch -f main HEAD~3",
    "git branch -M main",
    "git reset --hard",
    "git reset HEAD~1 --hard",
    "git -C . reset --hard origin/main",
    "git clean -fdx",
    "git clean -n",
    "git difftool -y -x true HEAD~1",
    "git log -1 --output=/tmp/x",
    "git diff --output /tmp/x",
    "git checkout .",
    "git checkout -- src/File.cs",
    "git checkout main -- src/File.cs",
    "git checkout -f main",
    "git switch -f main",
    "git switch --discard-changes main",
    "git switch -C main",
    "git restore .",
    "git restore src/File.cs",
    "git restore --staged --worktree src/File.cs",
    "git stash drop",
    "git stash clear",
]

ALLOWED = [
    "git status",
    "git log --oneline -5",
    "git diff --stat main...HEAD",
    "git show HEAD",
    "git push",
    "git push -u origin chore/claude-setup",
    "git push --set-upstream origin feature",
    "git push --follow-tags",
    "git push origin v1.5.0",
    "git push origin HEAD:refs/heads/feature",
    "git -C /tmp/repo push origin feature",
    "git branch",
    "git branch -d merged-branch",
    "git branch new-branch",
    "git reset --soft main",
    "git reset HEAD src/File.cs",
    "git checkout -b feature",
    "git checkout main",
    "git switch main",
    "git switch -c feature",
    "git restore --staged src/File.cs",
    "git stash",
    "git stash pop",
    "git commit -m 'Explain why we never force-push'",
    'echo "git push --force"',
    'gh pr create --title "Guard" --body "Blocks git push --force and git reset --hard"',
    "dotnet build EclipsVault.slnx -c Release",
    "ls -la",
    "",
]


def run_hook(command):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    return subprocess.run([sys.executable, "-I", str(HOOK)], input=payload, capture_output=True, text=True)


class BlockDangerousGitTests(unittest.TestCase):
    def test_destructive_commands_are_blocked(self):
        for command in BLOCKED:
            with self.subTest(command=command):
                result = run_hook(command)
                self.assertEqual(result.returncode, 2, f"not blocked: {command!r}")
                self.assertIn("BLOCKED", result.stderr)

    def test_everyday_commands_are_allowed(self):
        for command in ALLOWED:
            with self.subTest(command=command):
                result = run_hook(command)
                self.assertEqual(result.returncode, 0, f"wrongly blocked: {command!r} -> {result.stderr}")

    def test_a_heredoc_with_an_apostrophe_does_not_crash_the_hook(self):
        command = "git commit -F - <<'EOF'\nDon't block a normal commit message\nEOF"
        self.assertEqual(run_hook(command).returncode, 0)


if __name__ == "__main__":
    unittest.main()
