# Commercial licence & terms — DRAFT FOR LEGAL REVIEW

> **This is a draft, not a binding agreement, and not legal advice.** It exists so a qualified lawyer
> in your jurisdiction can red-line a real starting point instead of drafting from zero. Do not present
> it to a customer or link it at checkout until a lawyer has reviewed it. Bracketed `[…]` items are
> decisions only you can make. Your `LICENSE` file repeatedly defers production use to "the applicable
> commercial agreement" — **this is meant to become that agreement.**

---

## EclipsVault Commercial Licence Agreement (v0.1 draft)

**Between** Saba Sabashvili, sole proprietor / individual entrepreneur, Georgia (the "Licensor"), and
the individual or entity that purchases a licence (the "Customer").

By completing a purchase, or by putting the Software to Production Use, the Customer agrees to these
terms. These terms govern Production Use; the repository `LICENSE` governs evaluation and the source.

### 1. Definitions

- **Software** — EclipsVault, in source or compiled form, including its documentation.
- **Production Use** — any use that is not evaluation, including holding, protecting, or serving any
  real credential, or use in the operation of a business.
- **Node** — one running instance of the Software (one deployment; replicas of a single logical
  deployment behind a load balancer count as one Node unless the order says otherwise).
- **Order** — the purchase record from the payment processor identifying the tier, Node count, and term.

### 2. Licence grant

Subject to payment and these terms, the Licensor grants the Customer a **non-exclusive,
non-transferable, non-sublicensable** licence to install and run the Software in Production Use, for the
**tier and Node count** in the Order, for the **term** in the Order.

- **[Perpetual-fallback / continuity]** — Licensing enforcement in the Software is **soft**: an expired,
  missing, or invalid licence never blocks decryption or locks the Customer out of their own data (see
  [`THREAT_MODEL.md`](THREAT_MODEL.md) invariants). A lapse in licence affects the right to updates and
  support, and the contractual right to run the Software — not the Customer's access to their secrets.
- **[Choose your model]** — either (a) a **subscription**: the licence and the right to updates/support
  run for the Order term and renew per the Order; or (b) a **perpetual licence to the version(s)
  purchased**, with updates/support for a defined maintenance window. State one clearly in the Order.

### 3. Restrictions

The Customer may not: redistribute, resell, rent, lease, or host the Software for third parties; offer
it as a service; remove or alter notices; use it beyond the Node count or term purchased; or reverse
engineer except to the extent the law permits regardless of contract. No rights are granted by
implication.

### 4. Fees, taxes, and refunds

- Fees are those in the Order. Payment is collected by **[Payment processor / Merchant of Record]**,
  which acts as merchant of record and is responsible for charging and remitting any applicable sales
  tax or VAT.
- **Refunds:** the Licensor offers a **14-day money-back guarantee** — a Customer may request a full
  refund within **14 days** of the purchase date, for any reason, by emailing the address below. Refunds
  are processed by the Merchant of Record named above, per its standard mechanism. A refund
  **terminates the licence**: because enforcement is soft and licence verification runs entirely offline
  (there is no remote "kill switch"), the Software keeps running — it is the Customer's to remove — but
  any Production Use of paid features after a refund is **unlicensed** (see §11). Renewals are subject to
  the same 14-day policy measured from each renewal date. This policy states plainly what the Licensor
  will honor; the Merchant of Record's checkout terms are matched to it.

### 5. Support

- The Licensor provides **[best-effort]** support to Customers with a current licence, via
  sabasabashvili86@gmail.com, during **[business days, GMT+4]**.
- Target first response: **[e.g. 2 business days]**. These are targets, **not** a guaranteed
  service-level agreement, and the Licensor is a single maintainer.
- Support covers: defects in the Software, licence and installation help, and security questions. It
  does **not** cover: the Customer's infrastructure, deployment, network, database, key management, or
  third-party systems the Software is configured to use (see [`THREAT_MODEL.md`](THREAT_MODEL.md) and
  [`INSTALL.md`](INSTALL.md)).

### 6. Security and vulnerability handling

The Licensor handles reported vulnerabilities per [`SECURITY.md`](../SECURITY.md) and
[`INCIDENT_RESPONSE.md`](INCIDENT_RESPONSE.md), and will notify licensed Customers of security-relevant
releases through the channel provided at purchase. Because the Software is self-hosted, applying a fix
is the Customer's action; the Licensor cannot patch a Customer's instance.

### 7. Customer responsibilities

The Customer is solely responsible for the security of its deployment — hosting, network exposure, TLS,
database hardening, OS patching, and in particular **custody and backup of the master key (KEK)**. As
stated in [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`BACKUP_AND_RECOVERY.md`](BACKUP_AND_RECOVERY.md),
**loss of the KEK renders data permanently unrecoverable, and there is no vendor recovery path.**

### 8. Data protection

The Software is self-hosted; the Licensor does not receive, access, or store the Customer's secrets,
keys, database, or vault contents, and the Software transmits no telemetry to the Licensor. The limited
data the Licensor holds (contact and licence record) is handled per [`PRIVACY.md`](PRIVACY.md). The
Customer is the data controller for the contents of its vault.

### 9. Warranty disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. EclipsVault is software for
protecting credentials; it is not a guarantee that they will be protected. The security of a deployment
depends on how it is configured, operated, and hosted — none of which is within the Licensor's control.

### 10. Limitation of liability

TO THE MAXIMUM EXTENT PERMITTED BY LAW: the Licensor is not liable for indirect, incidental, special,
consequential, or punitive damages, or for lost profits, data, or goodwill; and the Licensor's total
aggregate liability arising out of or relating to the Software or these terms **shall not exceed the
fees the Customer paid in the [twelve (12) months] preceding the event giving rise to the claim.** Some
jurisdictions do not allow certain limitations; where so, the limitation applies to the fullest extent
permitted.

### 11. Term and termination

This licence terminates automatically if the Customer breaches it, or at the end of the Order term if
not renewed. On termination the Customer's contractual right to Production Use and to updates/support
ends. Sections 9, 10, and 12 survive termination. (Termination does not, by itself, disable the
Customer's running instance — enforcement is soft — but continued Production Use after termination is
unlicensed.)

### 12. General

Governing law: **Georgia**. Disputes: **[courts of Georgia / arbitration — choose]**. These terms, with
the Order and the repository `LICENSE`, are the entire agreement and supersede prior discussions. The
Licensor may update these terms for new purchases; a Customer's existing term is governed by the terms
in force at its purchase. If any provision is unenforceable, the rest stand.

---

_Contact for commercial licensing: sabasabashvili86@gmail.com_
