@AGENTS.md

## Claude Code

- Subagents in `.claude/agents/`: `test-runner` (Haiku) builds and tests and reports only failures;
  `security-reviewer` (Opus) reviews any change to encryption, authorization, the audit chain, MFA,
  or licensing before it merges.
- `/release` cuts a release. Only the owner starts it.
- Pick the model by the job: Haiku to search and run tests, Sonnet to implement a decided change,
  Opus to plan, debug hard problems, and review security.
