# EclipsVault Max — commercial licence & terms

**v1.0 · 28 July 2026**

> These terms govern **EclipsVault Max** — the six Licensed Capabilities. They are **not** what permits
> you to run EclipsVault in production: the repository [`LICENSE`](../LICENSE) grants that outright,
> free, with no time limit and no seat limit. You only need this document if you are buying Max.
>
> The authoritative published copy is at ⟨site⟩/terms. Not yet reviewed by a lawyer — that pass is
> outstanding and tracked in `docs/internal/FIX_PLAN.md`.

**Between** Saba Sabashvili, sole proprietor / individual entrepreneur, Georgia (the "Licensor"), and
the individual or entity that purchases a licence (the "Customer").

By completing a purchase, or by using a Licensed Capability in production, the Customer agrees to
these terms.

## 1. Definitions

- **Software** — EclipsVault, in source or compiled form, including its documentation.
- **Production Use** — any use that is not evaluation, including holding, protecting, or serving any
  real credential, or use in the operation of a business.
- **Licensed Capabilities** — the six capabilities these terms cover, and only these: single sign-on
  via OIDC; sealing the master key with an external KMS; Redis-backed high availability across
  replicas; dynamic secrets; managed rotation; and signed audit attestation. Everything else in the
  Software is free to use in production under the repository `LICENSE`.
- **Node** — one running instance of the Software. Replicas of a single logical deployment behind a
  load balancer count as one Node unless the Order says otherwise.
- **Order** — the purchase record identifying the Node count and the update window.

## 2. Licence grant

Subject to payment and these terms, the Licensor grants the Customer a **non-exclusive,
non-sublicensable** licence to use the Licensed Capabilities in Production Use, for the Node count in
the Order.

EclipsVault Max is a **perpetual licence** to the purchased version, bundled with **12 months of
updates** from the issue date. When that window lapses the Software keeps running and continues to
receive security patches — a lapse affects the right to *new feature* updates and to support, not the
Customer's access to their own data.

The licence **transfers to a successor entity on written notice** — if the Customer is acquired,
merges, or reorganises, the licence follows the deployment it was bought for. It may not otherwise be
assigned, resold, or transferred to a third party.

**Enforcement is soft.** An expired, missing, or invalid licence never blocks decryption or locks the
Customer out of their own data.

## 3. Restrictions

The Customer may not: redistribute, resell, rent, lease, or host the Software for third parties; offer
it as a service; remove or alter notices; use the Licensed Capabilities beyond the Node count
purchased; or reverse engineer except to the extent the law permits regardless of contract. No rights
are granted by implication.

## 4. Fees, taxes, and refunds

Fees are those in the Order. Where payment is collected by a Merchant of Record, that party is
responsible for charging and remitting any applicable sales tax or VAT.

**Refunds: a 14-day money-back guarantee.** A Customer may request a full refund within 14 days of
purchase, for any reason, by emailing the address below. A refund **terminates the licence**: because
enforcement is soft and verification runs entirely offline, there is no remote kill switch — the
Software keeps running and removing it is the Customer's action — but use of the Licensed Capabilities
after a refund is unlicensed (see §11).

## 5. Support

The Licensor provides **best-effort** support to Customers with a current licence, by email. **There is
no service-level agreement and no promised response time.** Read that before buying rather than after.

The Licensor is one person, with obligations that can require immediate absence at no notice, and **may
be unreachable for up to seven consecutive days**. No response target is stated because none could be
honoured, and a number the Licensor already knew he might miss would be worth less than saying so
plainly.

**What makes that survivable is the software, not a promise.** Nothing in EclipsVault depends on the
Licensor being reachable. Licence verification is entirely offline; there is no activation server, no
phone-home, and no kill switch; and enforcement never disables a capability or withholds access to the
Customer's data. A vendor who is unreachable — for a week, or permanently — cannot cause an outage in
the Customer's vault. Support answers questions; it is not in the path of anything working. That is the
reason this clause can afford to be honest.

Security reports are triaged ahead of all other work. **If your organisation requires a contractual
response time, EclipsVault is not a fit** — and the Licensor would rather say so before a purchase than
after one.

Support covers: defects in the Software, licence and installation help, and security questions. It does
**not** cover the Customer's infrastructure, deployment, network, database, key management, or
third-party systems the Software is configured to use.

## 6. Security and vulnerability handling

The Licensor handles reported vulnerabilities per [`SECURITY.md`](../SECURITY.md) and
[`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md), and will notify licensed Customers of security-relevant
releases through the channel provided at purchase. Because the Software is self-hosted, applying a fix
is the Customer's action; the Licensor cannot patch a Customer's instance.

## 7. Customer responsibilities

The Customer is solely responsible for the security of its deployment — hosting, network exposure, TLS,
database hardening, OS patching, and in particular **custody and backup of the master key (KEK)**. As
stated in [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`BACKUP_AND_RECOVERY.md`](BACKUP_AND_RECOVERY.md),
**loss of the KEK renders data permanently unrecoverable, and there is no vendor recovery path.**

## 8. Data protection

The Software is self-hosted; the Licensor does not receive, access, or store the Customer's secrets,
keys, database, or vault contents, and the Software transmits no telemetry to the Licensor. The limited
data the Licensor holds (contact and licence record) is handled per [`PRIVACY.md`](PRIVACY.md). The
Customer is the data controller for the contents of its vault; the Licensor is not a processor of it.

## 9. Warranty disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. EclipsVault is software for
protecting credentials; it is not a guarantee that they will be protected. The security of a deployment
depends on how it is configured, operated, and hosted — none of which is within the Licensor's control.

## 10. Limitation of liability

TO THE MAXIMUM EXTENT PERMITTED BY LAW: the Licensor is not liable for indirect, incidental, special,
consequential, or punitive damages, or for lost profits, data, or goodwill; and the Licensor's total
aggregate liability arising out of or relating to the Software or these terms **shall not exceed the
total fees the Customer paid under the Order.** Some jurisdictions do not allow certain limitations;
where so, the limitation applies to the fullest extent permitted, and nothing here excludes liability
that cannot lawfully be excluded.

> Stated as **total fees paid** rather than the more usual *"fees paid in the preceding twelve months"*,
> because Max is a one-time perpetual purchase: under the usual wording a Customer in year three would
> have paid nothing in the preceding twelve months and the cap would be **zero**. A cap of zero is not a
> cap — it is the kind of clause a court strikes out entirely, leaving the Licensor with no limit at all.
> This version stays at the price paid, permanently, for both parties.

## 11. Term and termination

This licence terminates automatically if the Customer breaches it. On termination the Customer's
contractual right to use the Licensed Capabilities and to updates and support ends; **the right to run
EclipsVault itself is granted by the repository `LICENSE` and is unaffected.** Sections 7, 9, 10, and 12
survive termination. Termination does not, by itself, disable the Customer's running instance —
enforcement is soft — but continued use of the Licensed Capabilities after termination is unlicensed.

## 12. General

**Governing law: Georgia. Disputes are subject to the courts of Georgia.** These terms, with the Order
and the repository `LICENSE`, are the entire agreement and supersede prior discussions. The Licensor may
update these terms for new purchases; a Customer's existing licence is governed by the terms in force at
its purchase. If any provision is unenforceable, the rest stand.

---

_Contact for commercial licensing: sabasabashvili86@gmail.com_
