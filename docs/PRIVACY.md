# Privacy statement

> Plain-language statement of what data the vendor of EclipsVault does and does not handle. Have a
> lawyer review the wording before you publish it as your official policy — this is a faithful, honest
> starting point, not legal advice. Fill the bracketed placeholders.

**Vendor:** Saba Sabashvili ("we"), sole proprietor / individual entrepreneur, Georgia.
**Contact:** sabashvili13@icloud.com

## The short version

EclipsVault is **self-hosted software**. You run it on infrastructure you control, and it seals your
secrets with a master key (KEK) that only you hold. As a result:

- **We never receive, see, or store your secrets, your KEK, your database, or anything in your vault.**
  There is no path by which that data reaches us.
- **The software does not phone home.** It contains no telemetry, no analytics, and no usage tracking.
  License verification runs entirely offline against a public key shipped in the product — nothing about
  your usage is transmitted to us. The only network calls the software makes are to systems **you**
  configure (your database, SMTP relay, KMS/HashiCorp Vault, identity provider, Redis) — all your own
  infrastructure.

The only personal data we hold is what you give us to **buy, license, and get support** for the
product. That is described below.

## What we collect, and why

| Data | Source | Why we have it |
|---|---|---|
| Your email address | You, at purchase / when you contact us | To deliver your license, send security advisories, and answer support requests. |
| Order / license record (tier, purchase date, license id) | The payment processor (see *Sub-processors*) | To issue and manage your license and honor support. |
| Support correspondence | You, when you email us | To help you and keep a record of the issue. |
| Business/tax records of the sale | The payment processor | To meet our legal and tax obligations. |

We do **not** collect payment card details — those are handled by our payment processor, which acts as
Merchant of Record for the sale. We never see your full card number.

## What we do *not* do

- We do not sell, rent, or share your data.
- We do not use it for advertising or profiling.
- We do not send marketing you didn't ask for. Security advisories about the product you run are the one
  exception — those are safety-critical, and we will keep them to that.

## Roles (data-protection terms)

- For **the contents of your vault**, *you* are the data controller. We are **not a processor** of that
  data, because we never receive it. What your instance does with your end-users' data is governed by
  your own privacy policy, not this one.
- For the **limited account data above** (your email, license, support), we are the controller, and the
  lawful basis is performing our contract with you and meeting our legal obligations.

## Sub-processors

- **[Payment processor / Merchant of Record — e.g. Paddle or Lemon Squeezy]** — processes payment,
  handles sales tax/VAT, and provides us your email and order record. See their own privacy policy.
- **[Email provider, if any]** — delivers license and advisory emails.

We keep this list current; material changes are noted in the product's release notes.

## Retention

- License and tax records: kept as long as the law requires us to keep business records.
- Support correspondence: kept as long as needed to support you, then deleted on request.

## Your rights

You can ask us to show you, correct, or delete the limited data we hold about you (your email, license,
and support history). Email sabashvili13@icloud.com and we will respond within [30] days. Deleting your
license record may end your entitlement to updates and support; it does not affect the copy of the
software already running on your own infrastructure.

## Changes

If this statement changes materially, we will note it in the product's release notes and update the date
below.

_Last updated: [date] · Governing jurisdiction: Georgia_
