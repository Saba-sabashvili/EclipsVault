@AGENTS.md

## Claude Code

- Subagents in `.claude/agents/`: `test-runner` (Haiku) builds and tests and reports only failures;
  `security-reviewer` (Opus) reviews any change to encryption, authorization, the audit chain, MFA,
  or licensing before it merges.
- `/release` cuts a release. Only the owner starts it.
- `.claude/hooks/block-dangerous-git.py` refuses git commands that destroy work or rewrite shared
  history, and anything it cannot verify: arguments the shell expands, or scripts fed to a shell or
  interpreter that mention git. It fails closed, so it needs `python3`. If it blocks something you
  need, ask the owner to run it. Write commit messages and PR bodies to a file (`git commit -F`,
  `gh pr create --body-file`), because text that mentions git commands inline gets refused.
  When editing the hook, run its tests (see `AGENTS.md`).
- Pick the model by the job: Haiku to search and run tests, Sonnet to implement a decided change,
  Opus to plan, debug hard problems, and review security.
