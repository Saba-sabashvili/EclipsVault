# Security Policy

## Reporting a vulnerability

Email **sabashvili13@icloud.com** with the details. Please do **not** open a public issue for a
security report. Include: what you found, the impact, and the steps to reproduce it. If you can,
suggest a fix.

You can expect an acknowledgement within a few business days. This is a small project maintained by
one person, so response is best-effort — but security reports are triaged ahead of everything else.

## Supported versions

Security fixes are provided for the latest released version. Older versions are not patched; upgrade
to receive fixes.

## Scope

In scope: the EclipsVault application code in this repository — cryptography, authentication,
authorization (ABAC), auditing, session handling, and the API. Out of scope: how a given deployment
is configured, hosted, key-managed, or networked (that is the operator's responsibility, as stated
in the LICENSE and the install guide), and third-party dependencies (report those upstream).

## Safe harbor

Good-faith security research — testing against your own evaluation instance, not accessing other
people's data, and giving reasonable time to fix before disclosure — is welcome and will not be
pursued. Do not test against a deployment you do not own.

## Continuity

EclipsVault is source-available and maintained by an individual. If maintenance ever stops, the
intent is that customers keep the source and the right to run and patch what they have deployed — so
a paused project never strands a running vault. The exact terms are in the commercial agreement.
