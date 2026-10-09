#!/usr/bin/env python3
"""Claude Code PreToolUse hook: refuse git commands that destroy work or rewrite shared history.

The Bash tool call arrives as JSON on stdin. Exit code 2 blocks it and shows stderr to the agent;
exit 0 lets it through. The permission deny list in settings.json only matches the start of a
command, so `git -C dir push -f` or `bash -c "git push -f"` slips past it. This hook splits the
command the way the shell does, looks inside `sh -c` / `eval` scripts, and checks every git
invocation it finds. It is a seatbelt against mistakes, not a sandbox against deliberate evasion.

Tests: .claude/hooks/test_block_dangerous_git.py (run in CI).
"""

import json
import re
import shlex
import sys

SHELLS = {"sh", "bash", "zsh", "dash"}
SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "|&", ";;"}
# git's own options that take a separate value, e.g. `git -C <dir> push`.
GIT_OPTIONS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}


def tokenize(command):
    """Split into shell words. Newlines and backticks separate commands, like `;` does."""
    lexer = shlex.shlex(command.replace("\n", " ; ").replace("`", " ; "), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    return list(lexer)


def segments(tokens):
    """Split on command separators only. A redirection (`>`, `2>&1`) can sit between a command's
    arguments, so splitting on it would hide the flags that follow it."""
    current = []
    for token in tokens:
        if token in SEPARATORS:
            if current:
                yield current
            current = []
        else:
            current.append(token)
    if current:
        yield current


def short_flags(args):
    """Letters from single-dash flag clusters: `-fu` gives {'f', 'u'}. `--long` options are excluded."""
    letters = set()
    for arg in args:
        if re.fullmatch(r"-[A-Za-z]+", arg):
            letters.update(arg[1:])
    return letters


def operands(args):
    return [a for a in args if not a.startswith("-")]


def check_git(args):
    """Return why the git invocation is refused, or None. `args` follow the word `git`."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        i += 2 if args[i] in GIT_OPTIONS_WITH_VALUE else 1
    if i >= len(args):
        return None
    sub, rest = args[i], args[i + 1:]
    flags = short_flags(rest)

    if any(a.startswith("--output") for a in rest):
        return "--output writes to an arbitrary file"
    if sub in {"difftool", "mergetool"}:
        return f"git {sub} runs external programs"
    if sub == "push":
        if any(a.startswith("--force") for a in rest) or "f" in flags:
            return "force-push rewrites shared history"
        if any(a.startswith("+") for a in operands(rest)):
            return "a +refspec is a force-push"
        if {"--delete", "--mirror", "--prune"} & set(rest) or "d" in flags:
            return "this push deletes remote branches"
        if any(re.fullmatch(r":.+", a) for a in operands(rest)):
            return "pushing :<ref> deletes a remote branch"
    if sub == "branch" and ("--force" in rest or flags & {"D", "f", "M", "C"}):
        return "force-deleting, -moving or -overwriting a branch can lose commits"
    if sub == "reset" and "--hard" in rest:
        return "reset --hard discards uncommitted work"
    if sub == "clean":
        return "git clean deletes untracked files"
    if sub == "checkout" and ({".", "--", "--force"} & set(rest) or "f" in flags):
        return "this checkout discards uncommitted changes"
    if sub == "switch" and ({"--force", "--discard-changes"} & set(rest) or flags & {"f", "C"}):
        return "this switch discards changes or resets a branch"
    if sub == "restore":
        staged_only = ("--staged" in rest or "S" in flags) and not ("--worktree" in rest or "W" in flags)
        if not staged_only:
            return "git restore discards uncommitted changes"
    if sub == "stash" and rest[:1] in (["drop"], ["clear"]):
        return "this deletes stashed work"
    return None


def check(command, depth=0):
    if depth > 5:
        return None
    try:
        tokens = tokenize(command)
    except ValueError:
        # Unbalanced quotes, typically an apostrophe inside a heredoc. Fall back to a coarse scan
        # with quotes removed, which can only over-block, never under-block.
        tokens = tokenize(re.sub(r"[\"']", " ", command))
    for seg in segments(tokens):
        for n, word in enumerate(seg):
            name = word.rsplit("/", 1)[-1]
            rest = seg[n + 1:]
            if name == "git":
                reason = check_git(rest)
            elif name in SHELLS:
                script = next((rest[k + 1] for k, a in enumerate(rest[:-1])
                               if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", a)), None)
                reason = check(script, depth + 1) if script else None
            elif name == "eval":
                reason = check(" ".join(rest), depth + 1)
            else:
                continue
            if reason:
                return reason
    return None


def main():
    command = json.load(sys.stdin).get("tool_input", {}).get("command", "")
    reason = check(command)
    if reason:
        print(
            f"BLOCKED by .claude/hooks/block-dangerous-git.py: {reason}. Only the repository owner may "
            "run this. Ask them to run it in a terminal. If the command only mentions git in a message "
            "or file body, rephrase it.",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()
