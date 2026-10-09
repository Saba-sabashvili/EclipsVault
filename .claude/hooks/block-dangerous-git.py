#!/usr/bin/env python3
"""Claude Code PreToolUse hook: refuse git commands that destroy work or rewrite shared history.

Input is the Bash tool call as JSON on stdin. Exit 2 blocks the call and shows stderr to the agent;
exit 0 lets it through. Any error inside the hook also exits 2: it is a guard, so it fails closed.

Scope: a seatbelt for a cooperating agent that might run the wrong command, not a sandbox for one
trying to escape. It splits the command the way the shell does, follows `sh -c`, `eval` and git
aliases, and refuses what it cannot verify: an argument the shell would expand, or a script fed to
a shell or interpreter that mentions a destructive git verb. It does not read script files run by
path. The real boundary for shared history is branch protection on the server.

Tests: .claude/hooks/test_block_dangerous_git.py (run in CI).
"""

import json
import re
import shlex
import subprocess
import sys

MAX_DEPTH = 5
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
INTERPRETER = re.compile(r"python[0-9.]*|perl|ruby|node|php|osascript|pwsh")
SEPARATORS = {";", "&&", "||", "|", "&", "(", ")", "|&", ";;"}
# git's own options that take a separate value, e.g. `git -C <dir> push`.
GIT_OPTIONS_WITH_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}
GUARDED = {
    "push", "reset", "clean", "branch", "checkout", "switch", "restore", "stash", "difftool",
    "mergetool", "rm", "update-ref", "reflog", "gc", "filter-branch", "filter-repo", "worktree", "config",
}
VERB = re.compile(r"\b(" + "|".join(sorted(GUARDED, key=len, reverse=True)) + r")\b")
GIT_THEN_VERB = re.compile(r"\bgit\b.*?" + VERB.pattern, re.S)
# Builtins cannot be shadowed by an alias, so only other names need an alias lookup.
BUILTINS = GUARDED | {
    "status", "log", "diff", "show", "add", "commit", "fetch", "pull", "merge", "rebase", "tag",
    "remote", "rev-parse", "rev-list", "ls-files", "ls-remote", "ls-tree", "blame", "grep",
    "describe", "init", "clone", "mv", "cherry-pick", "revert", "bisect", "shortlog", "cat-file",
    "merge-base", "for-each-ref", "show-ref", "check-ignore", "help", "version", "submodule", "notes",
}
READ_ONLY_CONFIG = {"--get", "--get-all", "--get-regexp", "--list", "-l", "--show-origin"}
RISKY_CONFIG = ("alias.", "core.hookspath", "core.sshcommand", "core.pager", "core.editor",
                "core.fsmonitor", "diff.external")


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


def expands(word):
    """True if the shell would rewrite this word before git saw it: a variable, a command
    substitution, ANSI-C quoting, a brace list, or a glob in a flag."""
    return (
        "$" in word
        or "`" in word
        or re.search(r"\{[^}]*(,|\.\.)[^}]*\}", word) is not None
        or (word.startswith("-") and re.search(r"[*?\[]", word) is not None)
    )


def short_flags(args):
    """Letters from single-dash flag clusters: `-fu` gives {'f', 'u'}. `--long` options are excluded."""
    letters = set()
    for arg in args:
        if re.fullmatch(r"-[A-Za-z]+", arg):
            letters.update(arg[1:])
    return letters


def operands(args):
    return [a for a in args if not a.startswith("-")]


def program_source(name, rest):
    """Where a shell or interpreter gets its program: ("code", text) when it is inline, ("stdin", None)
    when it comes from a pipe, heredoc or here-string in this same command, ("file", None) for a
    module or script file, which this hook does not read."""
    for k, arg in enumerate(rest[:-1]):
        if arg in {"-e", "-E", "-r", "--eval", "-Command"} or re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", arg):
            return "code", rest[k + 1]
    if "-m" in rest:
        return "file", None
    words, k = [], 0
    while k < len(rest):
        arg = rest[k]
        is_redirect = bool(arg) and set(arg) <= set("<>&|")
        if is_redirect or (arg.isdigit() and k + 1 < len(rest) and set(rest[k + 1]) <= set("<>&|")):
            k += 1 if not is_redirect else 2  # an fd number belongs to the redirect; the redirect eats a word
            continue
        if not arg.startswith("-"):
            words.append(arg)
        k += 1
    if not words or words[0] == "-" or (name in SHELLS and "-s" in rest):
        return "stdin", None
    return "file", None


def configured_alias(name, location):
    try:
        result = subprocess.run(["git", *location, "config", "--get", f"alias.{name}"],
                                capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def check_git(args, depth):
    """Return why the git invocation is refused, or None. `args` follow the word `git`."""
    if depth > MAX_DEPTH:
        return "git aliases nest too deeply to check"
    i, inline_aliases, location = 0, {}, []
    while i < len(args) and args[i].startswith("-"):
        option, value = args[i], args[i + 1] if i + 1 < len(args) else ""
        if option in GIT_OPTIONS_WITH_VALUE:
            if expands(value):
                return "a git option is a shell expansion, so the command can't be checked"
            if option == "-c" and value.lower().startswith("alias."):
                name, _, body = value[len("alias."):].partition("=")
                inline_aliases[name] = body
            if option == "-C":
                location = ["-C", value]
            i += 2
        else:
            i += 1
    if i >= len(args):
        return None
    sub, rest = args[i], args[i + 1:]

    if expands(sub):
        return "the git subcommand is a shell expansion, so it can't be checked"
    alias = inline_aliases.get(sub)
    if alias is None and sub not in BUILTINS:
        alias = configured_alias(sub, location)
    if alias:
        if alias.startswith("!"):
            return check(alias[1:] + " " + " ".join(shlex.quote(a) for a in rest), depth + 1)
        try:
            return check_git(location + shlex.split(alias) + rest, depth + 1)
        except ValueError:
            return "a git alias could not be parsed, so it can't be checked"
    if sub in GUARDED and any(expands(a) for a in rest):
        return "an argument is a shell expansion, so the command can't be checked"

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
    if sub == "rm" and ("--force" in rest or "f" in flags):
        return "git rm --force discards uncommitted changes"
    if sub == "update-ref" and ("-d" in rest or "--delete" in rest):
        return "update-ref -d deletes a ref"
    if sub == "reflog" and rest[:1] in (["expire"], ["delete"]):
        return "this destroys the reflog, the record that makes lost commits recoverable"
    if sub == "gc" and any(a.startswith("--prune") for a in rest):
        return "gc --prune deletes unreachable commits"
    if sub in {"filter-branch", "filter-repo"}:
        return f"git {sub} rewrites history"
    if sub == "worktree" and rest[:1] == ["remove"] and ("--force" in rest or "f" in flags):
        return "worktree remove --force discards that worktree's changes"
    if sub == "config" and not READ_ONLY_CONFIG & set(rest) and any(a.lower().startswith(RISKY_CONFIG) for a in rest):
        return "this git config change could disguise or run commands"
    return None


def check(command, depth=0):
    """Return why the shell command is refused, or None."""
    if depth > MAX_DEPTH:
        return "the command nests shells too deeply to check"
    try:
        tokens = tokenize(command)
    except ValueError:
        # Unbalanced quotes, typically an apostrophe inside a heredoc. Retry with quotes removed;
        # that can only make more of the text visible to the checks below.
        tokens = tokenize(re.sub(r"[\"']", " ", command))
    for seg in segments(tokens):
        names = [w.rsplit("/", 1)[-1] for w in seg]
        first = 0
        while first < len(seg) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", seg[first]):
            first += 1
        if first < len(seg) and expands(seg[first]) and VERB.search(command):
            return "the program to run is a shell expansion, so the command can't be checked"
        for n, name in enumerate(names):
            rest = seg[n + 1:]
            if name == "git":
                if "xargs" in names[:n] and VERB.search(" ".join(rest)):
                    return "git run by xargs takes arguments from stdin, so it can't be checked"
                reason = check_git(rest, depth)
            elif name in SHELLS or INTERPRETER.fullmatch(name):
                kind, code = program_source(name, rest)
                if kind == "code" and name in SHELLS:
                    reason = check(code, depth + 1)
                elif kind == "code" and GIT_THEN_VERB.search(code):
                    reason = "code run by an interpreter mentions git, so it can't be checked"
                elif kind == "stdin" and GIT_THEN_VERB.search(command):
                    reason = "a program fed to a shell or interpreter on stdin mentions git, so it can't be checked"
                else:
                    reason = None
            elif name == "eval":
                reason = check(" ".join(rest), depth + 1)
            else:
                continue
            if reason:
                return reason
    return None


def main():
    try:
        command = json.load(sys.stdin).get("tool_input", {}).get("command", "")
        reason = check(command) if isinstance(command, str) else "the command is not text"
    except Exception as error:  # noqa: BLE001 - a guard must fail closed on anything unexpected
        reason = f"the guard itself failed ({type(error).__name__}), so nothing is let through"
    if reason:
        print(
            f"BLOCKED by .claude/hooks/block-dangerous-git.py: {reason}. Only the repository owner may "
            "run this. Ask them to run it in a terminal. If the command only mentions git in a message "
            "or file body, write that text to a file instead.",
            file=sys.stderr,
        )
        sys.exit(2)


if __name__ == "__main__":
    main()
