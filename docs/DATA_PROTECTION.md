# Data protection — position statement for procurement

**v1.0 · 28 July 2026**

> For a buyer's legal, privacy, or procurement team. If you were sent here after asking for a Data
> Processing Agreement, **§1 is the answer** and **Annex A is the signable document** if your process
> requires one anyway.
>
> Not legal advice, and not yet reviewed by a lawyer. Written to be checkable rather than reassuring —
> every claim below is one you can verify from the source, which is public.

---

## 1. The short answer: there is no processor relationship to paper

**EclipsVault is self-hosted. The vendor never receives, accesses, or stores any personal data your
instance holds.** There is no network path by which it could: the software contains no telemetry, no
analytics, and no usage tracking, and licence verification is entirely offline against a public key
shipped in the product. It runs unchanged in an air-gapped network.

Under GDPR Article 28, a Data Processing Agreement governs a **controller engaging a processor** —
someone who processes personal data *on the controller's behalf*. That relationship does not exist
here in either direction:

| Data | Controller | Vendor's role |
|---|---|---|
| Everything in your vault — secrets, users, audit trail, end-user data | **You** | **None.** Not a processor. The vendor never receives it. |
| Your contact email, licence record, support correspondence | **The vendor**, for its own purposes (licence delivery, security advisories, tax records) | **Controller in its own right** — not your processor |

So there is nothing for an Article 28 DPA to attach to. Signing one anyway would be worse than not
signing one: it would have the vendor accept processor obligations — documented-instruction limits,
audit and inspection rights, deletion-on-termination duties — **over data it does not have and cannot
produce.** An agreement that cannot be performed is not a protection.

**This is a stronger position than a DPA, not a weaker one.** A SaaS competitor needs a DPA precisely
because your secrets sit on their infrastructure. Here, the guarantee is structural: there is no
copy to mishandle.

## 2. What the vendor actually holds

Only what you send in order to buy and be supported:

| Data | Source | Purpose | Lawful basis | Retention |
|---|---|---|---|---|
| Business email address | You, at purchase or by email | Deliver the licence, send security advisories, answer support | Performance of contract | Life of the licence + statutory record-keeping |
| Licence record (id, tier, purchase date, update window) | Payment processor | Issue and honour the licence | Performance of contract | As above |
| Support correspondence | You | Answer the issue, keep a record | Performance of contract / legitimate interests | Until resolved, then on request |
| Sale and tax records | Payment processor | Legal and tax obligations in Georgia | Legal obligation | As Georgian law requires |

**Never held, under any circumstance:** vault contents, master keys, database contents, audit trails,
your end-users' data, or payment card details.

No profiling. No advertising. No sale or sharing of data. No marketing beyond security advisories
about the product you run — which are safety-critical and kept to that.

## 3. International transfers — stated plainly

The vendor is established in **Georgia**, which **does not benefit from an EU adequacy decision**.

For **vault data this is irrelevant**: no transfer occurs, because no data leaves your infrastructure.

For the **contact and licence data in §2**, personal data does leave the EEA. In practice this is a
small, occasional, controller-to-controller transfer of business contact details that you provide in
order to conclude a purchase — the situation Article 49(1)(b) (transfer necessary for the performance
of a contract with the data subject) is written for. Where a Merchant of Record is used, that party is
the seller of record and the transfer to the vendor is narrower still.

**If your privacy team requires Article 46 safeguards rather than an Article 49 derogation, say so and
the vendor will sign Standard Contractual Clauses (Module One, controller-to-controller) covering that
data.** This is the one item on this page where a reasonable reviewer might disagree with the analysis,
so it is flagged rather than buried.

*Also under review with counsel: whether an Article 27 EU representative is required, or whether the
Article 27(2)(a) exemption for occasional, low-risk processing applies. The honest answer today is
that it has not been confirmed.*

## 4. Security of the data the vendor holds

Article 32 measures, proportionate to a contact list and a licence ledger:

- Business mail and records on accounts protected by **multi-factor authentication** with hardware-key
  or passkey second factors.
- The **licence signing key is held offline** and never transits a shared machine, chat, command
  history, or cloud clipboard. It is the only genuinely sensitive asset the vendor holds, and it is
  not personal data.
- No customer database, no CRM, no analytics platform, no marketing tooling — the attack surface is
  a mailbox and a ledger, deliberately.
- Access limited to one person. That is a concentration risk and it is stated rather than hidden.

For the security of **the software** — which is what a security questionnaire usually means — see
[`THREAT_MODEL.md`](THREAT_MODEL.md), including what it explicitly does *not* defend against, and the
pre-answered security questionnaire on the website.

## 5. Sub-processors

For the contact and licence data only:

| Sub-processor | Purpose | Location |
|---|---|---|
| ⟨Merchant of Record — Paddle⟩ | Payment, tax remittance, order record | ⟨confirm⟩ |
| ⟨Email provider⟩ | Licence and advisory delivery | ⟨confirm⟩ |

None of them receives vault data, because the vendor does not have it. The list is kept current and
material changes are noted in the product's release notes.

## 6. Your rights, and breach notification

You may ask to see, correct, export, or delete the limited data in §2 — email
`sabasabashvili86@gmail.com`. A response will be provided within one month, the GDPR statutory period.
Deleting the licence record ends entitlement to updates and support; **it does not affect the software
already running on your infrastructure**, which needs nothing from the vendor to keep working.

**On breach notification, read §A.6 before assuming the usual clause.** The vendor is one person and
does not promise a fixed notification window, for the same reason the commercial terms promise no
support SLA. A commitment already known to be unmeetable is worth less than an honest limit.

---

# Annex A — Data Processing Agreement (contact data only)

> Offered for procurement processes that require a signed Article 28 artifact. **Its scope is
> deliberately narrow: it covers only the data in §2 above.** It does not, and cannot, extend to vault
> contents, because the vendor has no access to them. A DPA purporting to cover them would be
> unperformable.
>
> To execute: the Customer signs and returns; the vendor countersigns. It supplements, and does not
> replace, [`COMMERCIAL_TERMS.md`](COMMERCIAL_TERMS.md).

**A.1 Subject matter and duration.** Processing of the Customer's business contact and licence records
for the purpose of delivering and supporting an EclipsVault licence, for the duration of the licence
plus any statutory record-retention period.

**A.2 Nature and purpose.** Licence issuance and delivery, security advisories, support correspondence,
and statutory tax and business record-keeping.

**A.3 Categories of data subject and personal data.** The Customer's nominated business contacts.
Business email address, name where provided, licence and order record, support correspondence.
**No special categories of personal data are processed**, and the Customer shall not send any.

**A.4 Vendor obligations.** The vendor shall: process the data only for the purposes in A.2; keep it
confidential and limit access to personnel bound by confidentiality; apply the technical and
organisational measures in §4; not engage a sub-processor beyond those listed in §5 without prior
notice and an opportunity to object; and, at the end of the relationship, delete the data on request
except where retention is required by law.

**A.5 Assistance.** The vendor shall assist the Customer, so far as the data in A.3 allows, with data
subject requests and with any consultation with a supervisory authority. **The vendor cannot assist
with requests concerning vault contents, because it holds none** — those are for the Customer to serve
from its own instance, which is what the product's built-in personal-data export exists for.

**A.6 Personal data breach.** The vendor shall notify the Customer **as soon as it becomes aware** of a
breach affecting the data in A.3, and shall provide the information available at that time.

> **No fixed notification window is stated, and this is deliberate.** The vendor is a single individual
> with obligations that can require immediate absence at no notice and may be unreachable for up to
> seven consecutive days. A contractual 24- or 48-hour notification clause would be a term the vendor
> already knows it could breach. Note the practical scope: a breach here means a compromised mailbox or
> licence ledger, not a compromise of your secrets — those never leave your infrastructure, and the
> vendor's availability has no bearing on them.

**A.7 Audit.** The vendor shall make available the information necessary to demonstrate compliance with
this Annex, **by responding in writing to a reasonable audit questionnaire, no more than once per
year.** On-site inspection is not available: there is no vendor-operated facility processing this data
beyond a mailbox and a records file, and there is no premises for an auditor to attend.

**A.8 International transfers.** As stated in §3. Where the Customer requires Article 46 safeguards,
the parties shall enter into Standard Contractual Clauses (controller-to-controller), which are
incorporated by reference on execution.

**A.9 Precedence and liability.** In the event of conflict between this Annex and
[`COMMERCIAL_TERMS.md`](COMMERCIAL_TERMS.md) on data protection, this Annex prevails. The limitation of
liability in those terms applies to this Annex.

| | Customer | Vendor |
|---|---|---|
| Name | | Saba Sabashvili |
| Entity | | Individual Entrepreneur, Georgia |
| Signature | | |
| Date | | |
