"""Tests for block-dangerous-git.py, driven through its real interface: JSON on stdin, exit code out.

Run: python3 -m unittest discover -s .claude/hooks -p 'test_*.py'
"""

import json
import shlex
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
    # The shell rewrites these after the hook has looked, so they are refused as unverifiable.
    "git push $(echo --force)",
    "F=--force; git push origin main $F",
    "git push origin main $'--force'",
    "git push {-f,} origin main",
    "git push origin main --forc*",
    "git $SUB --force",
    "G=git; $G push --force",
    # Scripts the hook cannot see into.
    'echo "git push --force" | bash',
    'bash <<< "git push --force"',
    "python3 -c \"import os; os.system('git push --force')\"",
    "python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['git', 'push', '--force'])\nEOF",
    "echo --force | xargs git push origin main",
    'echo "git push --force" | bash 2>&1',
    "cat <<'EOF' | sh\ngit push --force\nEOF",
    "node -e \"require('child_process').execSync('git push --force')\"",
    # Aliases.
    'git -c alias.p="push --force" p origin main',
    "git -c 'alias.p=!git push --force' p",
    'git config alias.p "push --force"',
    # History and ref destruction beyond push.
    "git update-ref -d refs/heads/main",
    "git reflog expire --expire=now --all",
    "git gc --prune=now",
    "git filter-branch --tree-filter true HEAD",
    "git worktree remove --force ../wt",
    "git rm -f src/File.cs",
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
    "git restore --staged src/*.cs",
    "git branch --list 'feat/*'",
    "git log --format='%H %s' -3",
    "git worktree add ../wt -b feature",
    "git rm --cached src/File.cs",
    "git gc",
    "git reflog",
    "git config user.name 'A Person'",
    "git config --get alias.st",
    "python3 -I -m unittest discover -s .claude/hooks -p 'test_*.py'",
    # A module or script file is not read, so running one beside a normal push is fine.
    "python3 -I -m unittest discover -s .claude/hooks && git push origin feature",
    "bash scripts/build.sh && git push origin feature",
    "python3 tools/report.py --since main && git push origin feature",
    'export PATH="/usr/local/share/dotnet:$PATH"',
    'TOKEN=$(curl -s "https://example.com/token") && echo done',
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

    def test_shells_nested_too_deeply_to_check_are_refused(self):
        command = "git push --force"
        for _ in range(8):
            command = f"bash -c {shlex.quote(command)}"
        self.assertEqual(run_hook(command).returncode, 2)

    def test_input_the_hook_cannot_read_is_refused_rather_than_allowed(self):
        result = subprocess.run([sys.executable, "-I", str(HOOK)], input="not json", capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)

    def test_the_registered_hook_command_refuses_everything_if_the_script_is_missing(self):
        settings = json.loads((HOOK.parent.parent / "settings.json").read_text())
        command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        payload = json.dumps({"tool_input": {"command": "git status"}})
        result = subprocess.run(["bash", "-c", command], input=payload, capture_output=True, text=True,
                                env={"CLAUDE_PROJECT_DIR": "/nonexistent", "PATH": "/usr/bin:/bin"})
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
