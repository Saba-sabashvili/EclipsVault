# Licensing + go-to-market Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add offline-verifiable ECDSA licensing (soft, never-blocks-secrets), a vendor-side minting CLI, and the supporting trust/packaging artifacts (SECURITY.md, SBOM, Dockerfile, install guide, README pricing) so EclipsVault can be sold as a self-hosted digital product through a Merchant of Record.

**Architecture:** Reuse the existing ECDSA P-256 / SHA-256 primitive (`AuditBundleVerifier` pattern) with inverted key custody — the vendor holds the private key offline and mints licenses; the app ships the vendor's **public** key pinned in and can only *verify*. Core stays pure BCL (manual canonical byte form like `AuditCheckpointCanonical`, no `System.Text.Json`). Enforcement is soft: status display + startup log + fail-soft audit row + non-blocking banner. No license check ever touches the crypto/reveal path.

**Tech Stack:** .NET 10, ASP.NET Core MVC, `System.Security.Cryptography.ECDsa`, `System.Buffers.Text.Base64Url`, xUnit, GitHub Actions, Docker, CycloneDX.

## Global Constraints

- **Core (`EclipsVault.Core`) has ZERO package references** — BCL only. No `System.Text.Json`; use the manual canonical byte form (unit separator ``), mirroring `AuditCheckpointCanonical`.
- **Safety invariant:** no license check anywhere near `ICryptoEngine`, `SecretService.Reveal*`, decryption, or the API read path. A bad license changes banners/logs/audit only — never whether a secret is served.
- **Enforcement is soft ("tier-nudge")**: warnings, banners, one fail-soft audit row. Never disable a feature, never fail startup, never block decryption.
- **Clock:** inject `TimeProvider` (registered as `TimeProvider.System`); read time via `.GetUtcNow()`. Never `DateTime.Now`.
- **Enums:** one enum per file, explicit integer values, under `EclipsVault.Core/Domain/Enums/`.
- **Options pattern:** `public const string SectionName`; register with `services.Configure<T>(configuration.GetSection(T.SectionName))`.
- **Admin authorization:** `[Authorize(Policy = VaultPolicies.AdminOnly)]` (TopSecret clearance).
- **CSP is strict** — no inline scripts/styles. New markup reuses existing CSS classes (mirror `_Flash.cshtml`); no `style=`/`onclick=`.
- **Commit messages** end with: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- **Tests live in `EclipsVault.Tests`** (xUnit). Run all: `dotnet test --configuration Release -v q --nologo`.
- Work on branch `feat/licensing` (already created).

---

## Phase 1 — Core licensing primitives (pure, BCL-only, TDD)

### Task 1: License tiers, claims, and feature mapping

**Files:**
- Create: `EclipsVault.Core/Domain/Enums/LicenseTier.cs`
- Create: `EclipsVault.Core/Domain/Enums/LicenseStatus.cs`
- Create: `EclipsVault.Core/Application/Licensing/LicenseClaims.cs`
- Create: `EclipsVault.Core/Application/Licensing/LicenseFeatures.cs`
- Test: `EclipsVault.Tests/Licensing/LicenseFeaturesTests.cs`

**Interfaces:**
- Produces:
  - `enum LicenseTier { Community=0, Pro=1, Enterprise=2 }`
  - `enum LicenseStatus { Missing=0, Malformed=1, InvalidSignature=2, Expired=3, Valid=4 }`
  - `sealed record LicenseClaims(string LicenseId, LicenseTier Tier, string IssuedTo, string? Contact, DateTimeOffset IssuedAtUtc, DateTimeOffset? NotAfterUtc, int MaxNodes, IReadOnlyList<string> Features)`
  - `static class LicenseFeatures` with `const string Sso="sso", Kms="kms", RedisHa="redis-ha", DynamicSecrets="dynamic-secrets", ManagedRotation="managed-rotation", AuditAttestation="audit-attestation"`
  - `static class LicenseTierFeatures` with `IReadOnlyList<string> For(LicenseTier)` and `IReadOnlySet<string> Effective(LicenseClaims)`

- [ ] **Step 1: Write the failing test**

```csharp
// EclipsVault.Tests/Licensing/LicenseFeaturesTests.cs
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class LicenseFeaturesTests
{
    private static LicenseClaims Claims(LicenseTier tier, params string[] features)
        => new("lic-1", tier, "Acme Ltd", null,
               DateTimeOffset.UnixEpoch, null, 0, features);

    [Fact]
    public void Community_grants_no_premium_features()
    {
        var effective = LicenseTierFeatures.Effective(Claims(LicenseTier.Community));
        Assert.Empty(effective);
    }

    [Fact]
    public void Pro_grants_the_operational_features_not_the_enterprise_ones()
    {
        var effective = LicenseTierFeatures.Effective(Claims(LicenseTier.Pro));
        Assert.Contains(LicenseFeatures.Sso, effective);
        Assert.Contains(LicenseFeatures.Kms, effective);
        Assert.Contains(LicenseFeatures.RedisHa, effective);
        Assert.Contains(LicenseFeatures.DynamicSecrets, effective);
        Assert.DoesNotContain(LicenseFeatures.ManagedRotation, effective);
        Assert.DoesNotContain(LicenseFeatures.AuditAttestation, effective);
    }

    [Fact]
    public void Enterprise_grants_everything_pro_has_plus_the_enterprise_features()
    {
        var effective = LicenseTierFeatures.Effective(Claims(LicenseTier.Enterprise));
        Assert.Contains(LicenseFeatures.Sso, effective);
        Assert.Contains(LicenseFeatures.ManagedRotation, effective);
        Assert.Contains(LicenseFeatures.AuditAttestation, effective);
    }

    [Fact]
    public void Explicit_features_on_the_claim_override_the_tier_default()
    {
        // A bespoke Community license that was sold one extra feature.
        var effective = LicenseTierFeatures.Effective(Claims(LicenseTier.Community, LicenseFeatures.Kms));
        Assert.Equal(new[] { LicenseFeatures.Kms }, effective);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test --configuration Release -v q --nologo`
Expected: FAIL — `LicenseTier`/`LicenseFeatures`/`LicenseTierFeatures` do not exist (compile error).

- [ ] **Step 3: Write minimal implementation**

```csharp
// EclipsVault.Core/Domain/Enums/LicenseTier.cs
namespace EclipsVault.Core.Domain.Enums;

/// <summary>The commercial tier a license grants. Community is the free, non-production tier.</summary>
public enum LicenseTier
{
    Community = 0,
    Pro = 1,
    Enterprise = 2
}
```

```csharp
// EclipsVault.Core/Domain/Enums/LicenseStatus.cs
namespace EclipsVault.Core.Domain.Enums;

/// <summary>The outcome of verifying a license token. Only <see cref="Valid"/> is fully licensed.</summary>
public enum LicenseStatus
{
    Missing = 0,
    Malformed = 1,
    InvalidSignature = 2,
    Expired = 3,
    Valid = 4
}
```

```csharp
// EclipsVault.Core/Application/Licensing/LicenseClaims.cs
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Licensing;

/// <summary>
/// What a license asserts. The vendor mints this offline and signs it; the app verifies the
/// signature and reads these fields. <see cref="MaxNodes"/> is honor-based (shown, not enforced).
/// <see cref="Features"/> may be empty, in which case the tier's default feature set applies.
/// </summary>
public sealed record LicenseClaims(
    string LicenseId,
    LicenseTier Tier,
    string IssuedTo,
    string? Contact,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset? NotAfterUtc,
    int MaxNodes,
    IReadOnlyList<string> Features);
```

```csharp
// EclipsVault.Core/Application/Licensing/LicenseFeatures.cs
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Licensing;

/// <summary>Stable capability keys a license may grant. Kept as strings so a license can carry a
/// bespoke set without recompiling the verifier.</summary>
public static class LicenseFeatures
{
    public const string Sso = "sso";
    public const string Kms = "kms";
    public const string RedisHa = "redis-ha";
    public const string DynamicSecrets = "dynamic-secrets";
    public const string ManagedRotation = "managed-rotation";
    public const string AuditAttestation = "audit-attestation";
}

/// <summary>
/// Maps a tier to the features it grants, and resolves the *effective* feature set for a license:
/// the explicit <see cref="LicenseClaims.Features"/> if the vendor set any, otherwise the tier
/// default. Base secret management (local KEK, TOTP, passkeys, audit chain, ABAC) is never listed
/// here — it is the product and is never gated or nudged.
/// </summary>
public static class LicenseTierFeatures
{
    private static readonly string[] Pro =
        [LicenseFeatures.Sso, LicenseFeatures.Kms, LicenseFeatures.RedisHa, LicenseFeatures.DynamicSecrets];

    private static readonly string[] Enterprise =
        [.. Pro, LicenseFeatures.ManagedRotation, LicenseFeatures.AuditAttestation];

    public static IReadOnlyList<string> For(LicenseTier tier) => tier switch
    {
        LicenseTier.Pro => Pro,
        LicenseTier.Enterprise => Enterprise,
        _ => []
    };

    public static IReadOnlySet<string> Effective(LicenseClaims claims)
        => claims.Features.Count > 0
            ? new HashSet<string>(claims.Features, StringComparer.Ordinal)
            : new HashSet<string>(For(claims.Tier), StringComparer.Ordinal);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test --configuration Release -v q --nologo`
Expected: PASS (all four `LicenseFeaturesTests` green; existing 389 still green).

- [ ] **Step 5: Commit**

```bash
git add EclipsVault.Core/Domain/Enums/LicenseTier.cs EclipsVault.Core/Domain/Enums/LicenseStatus.cs EclipsVault.Core/Application/Licensing/LicenseClaims.cs EclipsVault.Core/Application/Licensing/LicenseFeatures.cs EclipsVault.Tests/Licensing/LicenseFeaturesTests.cs
git commit -m "Licensing: tiers, claims, and the tier->feature mapping

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Canonical payload, token codec, and signer

**Files:**
- Create: `EclipsVault.Core/Application/Licensing/LicenseCanonical.cs`
- Create: `EclipsVault.Core/Application/Licensing/LicenseToken.cs`
- Create: `EclipsVault.Core/Application/Licensing/LicenseSigner.cs`
- Test: `EclipsVault.Tests/Licensing/LicenseTokenTests.cs`

**Interfaces:**
- Consumes: `LicenseClaims`, `LicenseTier` (Task 1).
- Produces:
  - `static class LicenseCanonical` — `byte[] Serialize(LicenseClaims)`, `bool TryDeserialize(ReadOnlySpan<byte> payload, out LicenseClaims? claims)`
  - `static class LicenseToken` — `const string Prefix = "EVLIC1"`, `string Encode(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)`, `bool TryDecode(string? token, out byte[] payload, out byte[] signature)`
  - `static class LicenseSigner` — `string Sign(LicenseClaims claims, System.Security.Cryptography.ECDsa privateKey)`

- [ ] **Step 1: Write the failing test**

```csharp
// EclipsVault.Tests/Licensing/LicenseTokenTests.cs
using System.Security.Cryptography;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class LicenseTokenTests
{
    private static LicenseClaims Sample() => new(
        LicenseId: "9f1c2d3e",
        Tier: LicenseTier.Pro,
        IssuedTo: "Acme Ltd — Ünïcode & separators\tok",
        Contact: "ops@acme.example",
        IssuedAtUtc: new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
        NotAfterUtc: new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero),
        MaxNodes: 3,
        Features: []);

    [Fact]
    public void Canonical_round_trips_every_field()
    {
        var claims = Sample();
        var bytes = LicenseCanonical.Serialize(claims);

        Assert.True(LicenseCanonical.TryDeserialize(bytes, out var back));
        Assert.NotNull(back);
        Assert.Equal(claims.LicenseId, back!.LicenseId);
        Assert.Equal(claims.Tier, back.Tier);
        Assert.Equal(claims.IssuedTo, back.IssuedTo);
        Assert.Equal(claims.Contact, back.Contact);
        Assert.Equal(claims.IssuedAtUtc, back.IssuedAtUtc);
        Assert.Equal(claims.NotAfterUtc, back.NotAfterUtc);
        Assert.Equal(claims.MaxNodes, back.MaxNodes);
    }

    [Fact]
    public void Token_encodes_and_decodes_the_exact_bytes()
    {
        byte[] payload = [1, 2, 3, 250, 0, 99];
        byte[] sig = [9, 8, 7];

        var token = LicenseToken.Encode(payload, sig);
        Assert.StartsWith("EVLIC1.", token);

        Assert.True(LicenseToken.TryDecode(token, out var p, out var s));
        Assert.Equal(payload, p);
        Assert.Equal(sig, s);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-token")]
    [InlineData("WRONG.aaaa.bbbb")]
    [InlineData("EVLIC1.only-two-parts")]
    [InlineData("EVLIC1.!!!notbase64!!!.bbbb")]
    public void Token_decode_rejects_malformed_input(string? token)
    {
        Assert.False(LicenseToken.TryDecode(token, out _, out _));
    }

    [Fact]
    public void Signer_produces_a_token_whose_signature_matches_the_canonical_payload()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = LicenseSigner.Sign(Sample(), key);

        Assert.True(LicenseToken.TryDecode(token, out var payload, out var sig));
        Assert.True(key.VerifyData(payload, sig, HashAlgorithmName.SHA256));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test --configuration Release -v q --nologo`
Expected: FAIL — `LicenseCanonical`/`LicenseToken`/`LicenseSigner` do not exist.

- [ ] **Step 3: Write minimal implementation**

```csharp
// EclipsVault.Core/Application/Licensing/LicenseCanonical.cs
using System.Text;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Licensing;

/// <summary>
/// The exact bytes that are signed for (and verified against) a license — the payload of the
/// token. Shared by the vendor's signer and the app's pure verifier so both agree bit-for-bit,
/// mirroring <see cref="Auditing.AuditCheckpointCanonical"/>. Fields are joined by the ASCII unit
/// separator; free-text fields are base64'd so they can never contain the separator.
/// </summary>
public static class LicenseCanonical
{
    private const char Sep = ''; // ASCII unit separator

    public static byte[] Serialize(LicenseClaims c)
        => Encoding.UTF8.GetBytes(string.Join(Sep,
            c.LicenseId,
            ((int)c.Tier).ToString(),
            B64(c.IssuedTo),
            c.Contact is null ? "" : B64(c.Contact),
            c.IssuedAtUtc.UtcTicks.ToString(),
            c.NotAfterUtc is { } na ? na.UtcTicks.ToString() : "-",
            c.MaxNodes.ToString(),
            string.Join(',', c.Features)));

    public static bool TryDeserialize(ReadOnlySpan<byte> payload, out LicenseClaims? claims)
    {
        claims = null;
        string text;
        try { text = Encoding.UTF8.GetString(payload); }
        catch { return false; }

        var f = text.Split(Sep);
        if (f.Length != 8) return false;

        if (string.IsNullOrEmpty(f[0])) return false;
        if (!int.TryParse(f[1], out var tierValue) || !Enum.IsDefined((LicenseTier)tierValue)) return false;
        if (!TryB64(f[2], out var issuedTo)) return false;
        string? contact = null;
        if (f[3].Length > 0 && !TryB64(f[3], out contact)) return false;
        if (!long.TryParse(f[4], out var issuedTicks)) return false;
        DateTimeOffset? notAfter = null;
        if (f[5] != "-")
        {
            if (!long.TryParse(f[5], out var naTicks)) return false;
            notAfter = new DateTimeOffset(naTicks, TimeSpan.Zero);
        }
        if (!int.TryParse(f[6], out var maxNodes)) return false;
        var features = f[7].Length == 0 ? [] : f[7].Split(',');

        claims = new LicenseClaims(
            f[0], (LicenseTier)tierValue, issuedTo!, contact,
            new DateTimeOffset(issuedTicks, TimeSpan.Zero), notAfter, maxNodes, features);
        return true;
    }

    private static string B64(string s) => Convert.ToBase64String(Encoding.UTF8.GetBytes(s));

    private static bool TryB64(string s, out string? value)
    {
        value = null;
        try { value = Encoding.UTF8.GetString(Convert.FromBase64String(s)); return true; }
        catch { return false; }
    }
}
```

```csharp
// EclipsVault.Core/Application/Licensing/LicenseToken.cs
using System.Buffers.Text;

namespace EclipsVault.Core.Application.Licensing;

/// <summary>
/// The wire form of a license: <c>EVLIC1.&lt;base64url(payload)&gt;.&lt;base64url(signature)&gt;</c>.
/// The signature is over the exact payload bytes carried here (no re-serialization), so verification
/// can never disagree with signing over field ordering or encoding.
/// </summary>
public static class LicenseToken
{
    public const string Prefix = "EVLIC1";

    public static string Encode(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
        => $"{Prefix}.{Base64Url.EncodeToString(payload)}.{Base64Url.EncodeToString(signature)}";

    public static bool TryDecode(string? token, out byte[] payload, out byte[] signature)
    {
        payload = [];
        signature = [];
        if (string.IsNullOrWhiteSpace(token)) return false;

        var parts = token.Split('.');
        if (parts.Length != 3 || parts[0] != Prefix) return false;

        try
        {
            payload = Base64Url.DecodeFromChars(parts[1]);
            signature = Base64Url.DecodeFromChars(parts[2]);
            return true;
        }
        catch (FormatException)
        {
            payload = [];
            signature = [];
            return false;
        }
    }
}
```

```csharp
// EclipsVault.Core/Application/Licensing/LicenseSigner.cs
using System.Security.Cryptography;

namespace EclipsVault.Core.Application.Licensing;

/// <summary>
/// Mints a signed license token from claims and a private key. Pure and shared by the vendor CLI
/// and the tests. It holds no key itself — the security boundary is possession of the private key,
/// not this code (exactly as with the audit signer, whose canonical form is also public).
/// </summary>
public static class LicenseSigner
{
    public static string Sign(LicenseClaims claims, ECDsa privateKey)
    {
        var payload = LicenseCanonical.Serialize(claims);
        var signature = privateKey.SignData(payload, HashAlgorithmName.SHA256);
        return LicenseToken.Encode(payload, signature);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test --configuration Release -v q --nologo`
Expected: PASS (all `LicenseTokenTests` green).

- [ ] **Step 5: Commit**

```bash
git add EclipsVault.Core/Application/Licensing/LicenseCanonical.cs EclipsVault.Core/Application/Licensing/LicenseToken.cs EclipsVault.Core/Application/Licensing/LicenseSigner.cs EclipsVault.Tests/Licensing/LicenseTokenTests.cs
git commit -m "Licensing: canonical payload, EVLIC1 token codec, and signer

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Verifier and pinned vendor key

**Files:**
- Create: `EclipsVault.Core/Application/Licensing/LicenseVerification.cs`
- Create: `EclipsVault.Core/Application/Licensing/LicenseVerifier.cs`
- Create: `EclipsVault.Core/Application/Licensing/LicensePublicKey.cs`
- Test: `EclipsVault.Tests/Licensing/LicenseVerifierTests.cs`

**Interfaces:**
- Consumes: `LicenseClaims`, `LicenseStatus`, `LicenseCanonical`, `LicenseToken`, `LicenseSigner` (Tasks 1-2).
- Produces:
  - `sealed record LicenseVerification(LicenseStatus Status, LicenseClaims? Claims, string Message)`
  - `static class LicenseVerifier` — `LicenseVerification Verify(string? token, byte[] publicKeySpki, DateTimeOffset now)`
  - `static class LicensePublicKey` — `const string VendorSpkiBase64` (placeholder empty), `byte[] Spki { get; }`

- [ ] **Step 1: Write the failing test**

```csharp
// EclipsVault.Tests/Licensing/LicenseVerifierTests.cs
using System.Security.Cryptography;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class LicenseVerifierTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    private static LicenseClaims Claims(DateTimeOffset? notAfter) => new(
        "lic-1", LicenseTier.Pro, "Acme Ltd", "ops@acme.example",
        new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), notAfter, 3, []);

    [Fact]
    public void A_correctly_signed_unexpired_token_is_valid()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = LicenseSigner.Sign(Claims(Now.AddYears(1)), key);

        var result = LicenseVerifier.Verify(token, key.ExportSubjectPublicKeyInfo(), Now);

        Assert.Equal(LicenseStatus.Valid, result.Status);
        Assert.Equal("Acme Ltd", result.Claims!.IssuedTo);
    }

    [Fact]
    public void A_null_or_empty_token_is_missing()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var result = LicenseVerifier.Verify(null, key.ExportSubjectPublicKeyInfo(), Now);
        Assert.Equal(LicenseStatus.Missing, result.Status);
    }

    [Fact]
    public void Garbage_is_malformed()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var result = LicenseVerifier.Verify("EVLIC1.not.base64url!!", key.ExportSubjectPublicKeyInfo(), Now);
        Assert.Equal(LicenseStatus.Malformed, result.Status);
    }

    [Fact]
    public void A_token_signed_by_a_different_key_fails_signature()
    {
        using var vendor = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var attacker = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = LicenseSigner.Sign(Claims(Now.AddYears(1)), attacker);

        var result = LicenseVerifier.Verify(token, vendor.ExportSubjectPublicKeyInfo(), Now);

        Assert.Equal(LicenseStatus.InvalidSignature, result.Status);
        Assert.Null(result.Claims); // untrusted — do not surface claims
    }

    [Fact]
    public void An_expired_but_correctly_signed_token_is_expired_and_still_surfaces_claims()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = LicenseSigner.Sign(Claims(Now.AddDays(-1)), key);

        var result = LicenseVerifier.Verify(token, key.ExportSubjectPublicKeyInfo(), Now);

        Assert.Equal(LicenseStatus.Expired, result.Status);
        Assert.Equal("Acme Ltd", result.Claims!.IssuedTo);
    }

    [Fact]
    public void A_tampered_payload_fails_signature()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var token = LicenseSigner.Sign(Claims(Now.AddYears(1)), key);

        // Flip a character in the payload segment.
        var parts = token.Split('.');
        var body = parts[1].ToCharArray();
        body[0] = body[0] == 'A' ? 'B' : 'A';
        var tampered = $"{parts[0]}.{new string(body)}.{parts[2]}";

        var result = LicenseVerifier.Verify(tampered, key.ExportSubjectPublicKeyInfo(), Now);
        Assert.True(result.Status is LicenseStatus.InvalidSignature or LicenseStatus.Malformed);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test --configuration Release -v q --nologo`
Expected: FAIL — `LicenseVerifier`/`LicenseVerification`/`LicensePublicKey` do not exist.

- [ ] **Step 3: Write minimal implementation**

```csharp
// EclipsVault.Core/Application/Licensing/LicenseVerification.cs
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Licensing;

/// <summary>The result of verifying a license token. <see cref="Claims"/> is populated only when
/// the signature is trusted (Valid or Expired) — never for an unverifiable token.</summary>
public sealed record LicenseVerification(LicenseStatus Status, LicenseClaims? Claims, string Message);
```

```csharp
// EclipsVault.Core/Application/Licensing/LicenseVerifier.cs
using System.Security.Cryptography;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Licensing;

/// <summary>
/// Verifies a license token with no dependency on any private key — it (1) decodes the token,
/// (2) checks the ECDSA signature over the exact payload bytes against the pinned public key, and
/// (3) checks expiry. Pure BCL, structured exactly like <see cref="Auditing.AuditBundleVerifier"/>.
/// It never throws on bad input and never has any side effect: soft by construction.
/// </summary>
public static class LicenseVerifier
{
    public static LicenseVerification Verify(string? token, byte[] publicKeySpki, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(token))
            return new(LicenseStatus.Missing, null, "No license is configured — running unlicensed.");

        if (!LicenseToken.TryDecode(token, out var payload, out var signature))
            return new(LicenseStatus.Malformed, null, "The license is not a readable EclipsVault token.");

        if (!LicenseCanonical.TryDeserialize(payload, out var claims) || claims is null)
            return new(LicenseStatus.Malformed, null, "The license payload could not be read.");

        bool signatureOk;
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeySpki, out _);
            signatureOk = ecdsa.VerifyData(payload, signature, HashAlgorithmName.SHA256);
        }
        catch (CryptographicException)
        {
            signatureOk = false;
        }

        if (!signatureOk)
            return new(LicenseStatus.InvalidSignature, null, "The license signature is not valid for this build.");

        if (claims.NotAfterUtc is { } expiry && now > expiry)
            return new(LicenseStatus.Expired, claims, $"The license expired on {expiry:yyyy-MM-dd}.");

        return new(LicenseStatus.Valid, claims, $"Licensed to {claims.IssuedTo} ({claims.Tier}).");
    }
}
```

```csharp
// EclipsVault.Core/Application/Licensing/LicensePublicKey.cs
namespace EclipsVault.Core.Application.Licensing;

/// <summary>
/// The vendor's license-signing PUBLIC key, pinned into the build. The app can only ever *verify*
/// with this; minting requires the matching private key, which the vendor keeps offline.
///
/// PLACEHOLDER: run `EclipsVault.LicenseForge keygen` once, keep the printed private key offline,
/// and paste the printed SubjectPublicKeyInfo (SPKI) base64 here. While this is empty, every token
/// verifies as InvalidSignature and the vault runs unlicensed (soft) — it never blocks.
/// </summary>
public static class LicensePublicKey
{
    public const string VendorSpkiBase64 = "";

    public static byte[] Spki =>
        string.IsNullOrEmpty(VendorSpkiBase64) ? [] : Convert.FromBase64String(VendorSpkiBase64);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `dotnet test --configuration Release -v q --nologo`
Expected: PASS (all `LicenseVerifierTests` green).

- [ ] **Step 5: Commit**

```bash
git add EclipsVault.Core/Application/Licensing/LicenseVerification.cs EclipsVault.Core/Application/Licensing/LicenseVerifier.cs EclipsVault.Core/Application/Licensing/LicensePublicKey.cs EclipsVault.Tests/Licensing/LicenseVerifierTests.cs
git commit -m "Licensing: offline ECDSA verifier and pinned vendor public key

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Phase 2 — Vendor minting CLI

### Task 4: `EclipsVault.LicenseForge` console (keygen + mint)

**Files:**
- Create: `EclipsVault.LicenseForge/EclipsVault.LicenseForge.csproj`
- Create: `EclipsVault.LicenseForge/Program.cs`
- Modify: `EclipsVault.slnx` (add the project)

**Interfaces:**
- Consumes: `LicenseClaims`, `LicenseTier`, `LicenseSigner`, `LicenseVerifier`, `LicensePublicKey` (Phase 1).
- Produces: a CLI binary `eclipsvault-license` with `keygen` and `mint` verbs. No code is consumed by later tasks.

- [ ] **Step 1: Create the project file**

```xml
<!-- EclipsVault.LicenseForge/EclipsVault.LicenseForge.csproj -->
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <AssemblyName>eclipsvault-license</AssemblyName>
    <RootNamespace>EclipsVault.LicenseForge</RootNamespace>
  </PropertyGroup>

  <ItemGroup>
    <!-- References ONLY Core: shares the canonical form + signer, has no dependency on the app,
         the database, or any private key (the key is supplied at runtime, never compiled in). -->
    <ProjectReference Include="..\EclipsVault.Core\EclipsVault.Core.csproj" />
  </ItemGroup>

</Project>
```

- [ ] **Step 2: Write `Program.cs`**

```csharp
// EclipsVault.LicenseForge/Program.cs
using System.Security.Cryptography;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;

// Vendor-side license tool. `keygen` makes a keypair (keep the private key offline; paste the public
// key into LicensePublicKey.VendorSpkiBase64). `mint` signs a license token from a private key held
// in ECLIPSVAULT_LICENSE_SIGNING_KEY. Exit codes: 0 ok, 2 usage/error.
const string KeyEnv = "ECLIPSVAULT_LICENSE_SIGNING_KEY";

if (args.Length == 0 || args[0] is "-h" or "--help")
{
    Console.WriteLine("EclipsVault license tool");
    Console.WriteLine("  keygen                             generate a P-256 keypair");
    Console.WriteLine("  mint --tier <Community|Pro|Enterprise> --to <name> [--contact <email>]");
    Console.WriteLine("       [--nodes <n>] [--years <n>] [--features a,b,c] [--id <id>]");
    Console.WriteLine();
    Console.WriteLine($"  mint reads the private key (base64 PKCS#8) from ${KeyEnv}.");
    return args.Length == 0 ? 2 : 0;
}

switch (args[0])
{
    case "keygen":
        return KeyGen();
    case "mint":
        return Mint(args);
    default:
        Console.Error.WriteLine($"error: unknown command '{args[0]}'");
        return 2;
}

static int KeyGen()
{
    using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var priv = Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey());
    var pub = Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
    Console.WriteLine("# PRIVATE KEY (PKCS#8 base64) — keep OFFLINE, never commit:");
    Console.WriteLine(priv);
    Console.WriteLine();
    Console.WriteLine("# PUBLIC KEY (SPKI base64) — paste into LicensePublicKey.VendorSpkiBase64:");
    Console.WriteLine(pub);
    return 0;
}

static int Mint(string[] args)
{
    var opt = ParseOptions(args);

    var keyB64 = Environment.GetEnvironmentVariable(KeyEnv);
    if (string.IsNullOrWhiteSpace(keyB64))
    {
        Console.Error.WriteLine($"error: set {KeyEnv} to the base64 PKCS#8 private key (from keygen).");
        return 2;
    }
    if (!opt.TryGetValue("tier", out var tierText) || !Enum.TryParse<LicenseTier>(tierText, true, out var tier))
    {
        Console.Error.WriteLine("error: --tier must be Community, Pro, or Enterprise.");
        return 2;
    }
    if (!opt.TryGetValue("to", out var issuedTo) || string.IsNullOrWhiteSpace(issuedTo))
    {
        Console.Error.WriteLine("error: --to <customer name> is required.");
        return 2;
    }

    var now = DateTimeOffset.UtcNow;
    int.TryParse(opt.GetValueOrDefault("nodes"), out var nodes);
    var years = int.TryParse(opt.GetValueOrDefault("years"), out var y) ? y : 1;
    var features = opt.TryGetValue("features", out var f) && f.Length > 0
        ? f.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        : Array.Empty<string>();

    var claims = new LicenseClaims(
        LicenseId: opt.GetValueOrDefault("id") ?? Guid.NewGuid().ToString("N")[..12],
        Tier: tier,
        IssuedTo: issuedTo,
        Contact: opt.GetValueOrDefault("contact"),
        IssuedAtUtc: now,
        NotAfterUtc: tier == LicenseTier.Community ? null : now.AddYears(years),
        MaxNodes: nodes,
        Features: features);

    using var ecdsa = ECDsa.Create();
    ecdsa.ImportPkcs8PrivateKey(Convert.FromBase64String(keyB64), out _);

    var token = LicenseSigner.Sign(claims, ecdsa);

    // Self-check: the freshly minted token must verify against the matching public key.
    var check = LicenseVerifier.Verify(token, ecdsa.ExportSubjectPublicKeyInfo(), now);
    if (check.Status != LicenseStatus.Valid)
    {
        Console.Error.WriteLine($"error: minted token failed self-verification ({check.Status}).");
        return 2;
    }

    Console.WriteLine(token);
    return 0;
}

static Dictionary<string, string> ParseOptions(string[] args)
{
    var opt = new Dictionary<string, string>(StringComparer.Ordinal);
    for (var i = 1; i < args.Length - 1; i++)
    {
        if (args[i].StartsWith("--", StringComparison.Ordinal))
        {
            opt[args[i][2..]] = args[i + 1];
            i++;
        }
    }
    return opt;
}
```

- [ ] **Step 3: Add the project to the solution**

Edit `EclipsVault.slnx` — add this line inside `<Solution>` after the `EclipsVault.AuditVerifier` line:

```xml
  <Project Path="EclipsVault.LicenseForge/EclipsVault.LicenseForge.csproj" />
```

- [ ] **Step 4: Build and exercise the CLI end-to-end**

Run:
```bash
dotnet build EclipsVault.LicenseForge/EclipsVault.LicenseForge.csproj -v q --nologo
# keygen
dotnet run --project EclipsVault.LicenseForge -- keygen
# mint using a generated key (round-trips through the Core self-check)
KEY=$(dotnet run --project EclipsVault.LicenseForge -- keygen | sed -n '2p')
ECLIPSVAULT_LICENSE_SIGNING_KEY="$KEY" dotnet run --project EclipsVault.LicenseForge -- \
  mint --tier Pro --to "Acme Ltd" --nodes 3 --years 1
```
Expected: `keygen` prints a private and public key; `mint` prints a token starting with `EVLIC1.` and exits 0 (its internal self-verification passed).

- [ ] **Step 5: Commit**

```bash
git add EclipsVault.LicenseForge/EclipsVault.LicenseForge.csproj EclipsVault.LicenseForge/Program.cs EclipsVault.slnx
git commit -m "Licensing: EclipsVault.LicenseForge vendor CLI (keygen + mint)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Phase 3 — App integration (soft-nudge, never blocks)

### Task 5: `ILicenseState` port + `LicenseService` + DI

**Files:**
- Create: `EclipsVault.Core/Application/Abstractions/ILicenseState.cs`
- Create: `EclipsVault.Infrastructure/Security/Licensing/LicenseOptions.cs`
- Create: `EclipsVault.Infrastructure/Security/Licensing/LicenseService.cs`
- Modify: `EclipsVault.Infrastructure/DependencyInjection.cs` (register options + singleton)
- Test: `EclipsVault.Tests/Licensing/LicenseServiceTests.cs`

**Interfaces:**
- Consumes: `LicenseVerifier`, `LicenseVerification`, `LicenseStatus`, `LicenseClaims`, `LicenseTierFeatures`, `LicensePublicKey` (Phase 1).
- Produces:
  - `interface ILicenseState { LicenseStatus Status { get; } LicenseClaims? Claims { get; } string Message { get; } bool Allows(string feature); }`
  - `sealed class LicenseOptions { const string SectionName="License"; string EnvironmentVariable; string FilePath; string? DevelopmentPublicKeySpki; }`
  - `sealed class LicenseService : ILicenseState`

- [ ] **Step 1: Write the failing test**

```csharp
// EclipsVault.Tests/Licensing/LicenseServiceTests.cs
using System.Security.Cryptography;
using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Infrastructure.Security.Licensing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class LicenseServiceTests
{
    // Minimal IHostEnvironment stub set to Development so the dev public-key override is honored.
    private sealed class FakeEnv : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "test";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    private static LicenseService Build(string? token, string devPublicKeySpki)
    {
        var opts = Options.Create(new LicenseOptions
        {
            EnvironmentVariable = "ECLIPSVAULT_LICENSE_TEST_" + Guid.NewGuid().ToString("N"),
            DevelopmentPublicKeySpki = devPublicKeySpki
        });
        if (token is not null) Environment.SetEnvironmentVariable(opts.Value.EnvironmentVariable, token);
        return new LicenseService(opts, new FakeEnv(), TimeProvider.System, NullLogger<LicenseService>.Instance);
    }

    [Fact]
    public void A_valid_pro_token_reports_valid_and_grants_pro_features()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var claims = new LicenseClaims("lic-1", LicenseTier.Pro, "Acme", null,
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), 3, []);
        var token = LicenseSigner.Sign(claims, key);
        var pub = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

        var svc = Build(token, pub);

        Assert.Equal(LicenseStatus.Valid, svc.Status);
        Assert.True(svc.Allows(LicenseFeatures.Kms));
        Assert.False(svc.Allows(LicenseFeatures.ManagedRotation));
    }

    [Fact]
    public void No_token_reports_missing_and_allows_nothing()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var svc = Build(token: null, Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));

        Assert.Equal(LicenseStatus.Missing, svc.Status);
        Assert.False(svc.Allows(LicenseFeatures.Sso));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test --configuration Release -v q --nologo`
Expected: FAIL — `ILicenseState`/`LicenseOptions`/`LicenseService` do not exist.

- [ ] **Step 3: Write minimal implementation**

```csharp
// EclipsVault.Core/Application/Abstractions/ILicenseState.cs
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// The vault's current license, resolved once at startup. Read-only and side-effect-free; consulted
/// only by nudge surfaces (banner, License page, startup log/audit). Never consulted on the secret
/// read or decrypt path — a bad license must never block the vault.
/// </summary>
public interface ILicenseState
{
    LicenseStatus Status { get; }
    LicenseClaims? Claims { get; }
    string Message { get; }

    /// <summary>True only when the license is Valid and its effective feature set includes the key.</summary>
    bool Allows(string feature);
}
```

```csharp
// EclipsVault.Infrastructure/Security/Licensing/LicenseOptions.cs
namespace EclipsVault.Infrastructure.Security.Licensing;

public sealed class LicenseOptions
{
    public const string SectionName = "License";

    /// <summary>Environment variable holding the license token (takes precedence over the file).</summary>
    public string EnvironmentVariable { get; set; } = "ECLIPSVAULT_LICENSE";

    /// <summary>Fallback file (relative to the content root) holding the license token.</summary>
    public string FilePath { get; set; } = "license.key";

    /// <summary>Development-only override of the pinned vendor public key (base64 SPKI), for testing
    /// with a local keypair. Ignored outside Development.</summary>
    public string? DevelopmentPublicKeySpki { get; set; }
}
```

```csharp
// EclipsVault.Infrastructure/Security/Licensing/LicenseService.cs
using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Security.Licensing;

/// <summary>
/// Loads the license token (env var, then file) once at construction, verifies it against the
/// pinned vendor public key (or a Development override), and exposes the result. Singleton: the
/// license is fixed for the process lifetime, re-read only on restart — the same model as the KEK.
/// Verification is pure and cannot throw here, so a bad license never affects startup.
/// </summary>
public sealed class LicenseService : ILicenseState
{
    private readonly LicenseVerification _verification;
    private readonly IReadOnlySet<string> _features;

    public LicenseService(
        IOptions<LicenseOptions> options,
        IHostEnvironment environment,
        TimeProvider clock,
        ILogger<LicenseService> logger)
    {
        var opts = options.Value;

        var token = Environment.GetEnvironmentVariable(opts.EnvironmentVariable);
        if (string.IsNullOrWhiteSpace(token))
        {
            var path = Path.Combine(environment.ContentRootPath, opts.FilePath);
            if (File.Exists(path))
            {
                try { token = File.ReadAllText(path).Trim(); }
                catch (IOException) { /* treated as no token — soft */ }
            }
        }

        var publicKey = LicensePublicKey.Spki;
        if (environment.IsDevelopment() && !string.IsNullOrWhiteSpace(opts.DevelopmentPublicKeySpki))
        {
            try { publicKey = Convert.FromBase64String(opts.DevelopmentPublicKeySpki); }
            catch (FormatException) { /* keep pinned key */ }
        }

        _verification = LicenseVerifier.Verify(token, publicKey, clock.GetUtcNow());
        _features = _verification.Status == LicenseStatus.Valid && _verification.Claims is { } c
            ? LicenseTierFeatures.Effective(c)
            : new HashSet<string>(StringComparer.Ordinal);

        if (_verification.Status == LicenseStatus.Valid)
        {
            logger.LogInformation("License: {Message}", _verification.Message);
        }
        else
        {
            logger.LogWarning(
                "License check: {Status} — {Message} EclipsVault continues to run in full; this affects " +
                "only the licensing banner and audit, never secret access.",
                _verification.Status, _verification.Message);
        }
    }

    public LicenseStatus Status => _verification.Status;
    public LicenseClaims? Claims => _verification.Claims;
    public string Message => _verification.Message;
    public bool Allows(string feature) => _features.Contains(feature);
}
```

- [ ] **Step 4: Register in DI**

Edit `EclipsVault.Infrastructure/DependencyInjection.cs`. Add the options registration next to the other `services.Configure<...>` lines (near line 37, beside `AuditSigningOptions`):

```csharp
        services.Configure<LicenseOptions>(configuration.GetSection(LicenseOptions.SectionName));
```

Add the singleton registration next to the other security singletons (near line 113, beside `IKekProvider`):

```csharp
        services.AddSingleton<ILicenseState, LicenseService>();
```

Add the required usings at the top of the file if not already present:

```csharp
using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Infrastructure.Security.Licensing;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `dotnet test --configuration Release -v q --nologo`
Expected: PASS (`LicenseServiceTests` green; all others still green).

- [ ] **Step 6: Commit**

```bash
git add EclipsVault.Core/Application/Abstractions/ILicenseState.cs EclipsVault.Infrastructure/Security/Licensing/ EclipsVault.Infrastructure/DependencyInjection.cs EclipsVault.Tests/Licensing/LicenseServiceTests.cs
git commit -m "Licensing: ILicenseState port, LicenseService loader, DI wiring

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Startup log + fail-soft audit row + activity describer

**Files:**
- Modify: `EclipsVault.Core/Domain/Enums/AuditAction.cs` (add one value)
- Modify: `EclipsVault.Core/Application/Activity/ActivityDescriber.cs` (add one case)
- Modify: `EclipsVault.Web/Program.cs` (startup license check after `app.Build()`)
- Test: `EclipsVault.Tests/Licensing/LicenseActivityTests.cs`

**Interfaces:**
- Consumes: `ILicenseState`, `IAuditSink`, `AuditEntry`, `AuditAction`, `ActivityDescriber` (existing + Task 5).
- Produces: `AuditAction.LicenseInvalidProductionUse`; a describer mapping for it.

- [ ] **Step 1: Write the failing test**

```csharp
// EclipsVault.Tests/Licensing/LicenseActivityTests.cs
using EclipsVault.Core.Application.Activity;
using EclipsVault.Core.Domain.Enums;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class LicenseActivityTests
{
    [Fact]
    public void The_unlicensed_production_action_has_a_plain_language_description()
    {
        var described = ActivityDescriber.Describe(AuditAction.LicenseInvalidProductionUse);
        Assert.False(string.IsNullOrWhiteSpace(described.Title));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `dotnet test --configuration Release -v q --nologo`
Expected: FAIL — `AuditAction.LicenseInvalidProductionUse` does not exist (compile error).

- [ ] **Step 3: Add the audit action**

In `EclipsVault.Core/Domain/Enums/AuditAction.cs`, add a new value. Pick a value not already used by any member in the file (200 is expected to be free; if the compiler or a scan shows it taken, use the next free integer). Place it in a sensible group with a short comment:

```csharp
    // Licensing (soft — never blocks the vault).
    LicenseInvalidProductionUse = 200,
```

- [ ] **Step 4: Add the describer case**

In `EclipsVault.Core/Application/Activity/ActivityDescriber.cs`, add a case to the `switch`. Match the surrounding style and use members that already exist on `ActivityCategory` / `ActivitySeverity` (open the enum files to confirm the exact member names — use the security/high-signal category and the most severe severity available):

```csharp
        AuditAction.LicenseInvalidProductionUse =>
            new(ActivityCategory.Security, "Started unlicensed in production", ActivitySeverity.Notable),
```

If `ActivityCategory.Security` or `ActivitySeverity.Notable` are named differently, use the nearest existing members (the mapping only affects how a global-audit row is labelled; this event has no user actor and never appears in a personal feed).

- [ ] **Step 5: Wire the startup check in `Program.cs`**

In `EclipsVault.Web/Program.cs`, after `var app = builder.Build();` and after any startup migration/schema-verification block, add:

```csharp
// License check: log the status once, and record a single fail-soft audit row if the vault is
// running unlicensed/expired in a non-Development environment. This never blocks startup.
using (var licenseScope = app.Services.CreateScope())
{
    var licenseState = licenseScope.ServiceProvider.GetRequiredService<ILicenseState>(); // ctor logs status
    if (!app.Environment.IsDevelopment() && licenseState.Status != LicenseStatus.Valid)
    {
        try
        {
            var sink = licenseScope.ServiceProvider.GetRequiredService<IAuditSink>();
            await sink.WriteAsync(new AuditEntry
            {
                Action = AuditAction.LicenseInvalidProductionUse,
                ResourceType = "License",
                ResourceName = licenseState.Status.ToString(),
                Details = licenseState.Message,
                IsCritical = true,
                ActorUsername = "system"
            }, CancellationToken.None);
        }
        catch (Exception ex)
        {
            app.Logger.LogWarning(ex,
                "Could not record the unlicensed-startup audit row — continuing (licensing never blocks the vault).");
        }
    }
}
```

Add usings at the top of `Program.cs` if missing:

```csharp
using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
```

- [ ] **Step 6: Run tests + build the web app**

Run:
```bash
dotnet test --configuration Release -v q --nologo
dotnet build EclipsVault.Web/EclipsVault.Web.csproj -v q --nologo
```
Expected: tests PASS; web build succeeds with 0 warnings/0 errors. (If a different exhaustive `switch` over `AuditAction` exists elsewhere, the build will name it — add the new case there too, mirroring neighbours.)

- [ ] **Step 7: Live-verify the startup log**

Run (Development — should log Info, no audit row):
```bash
dotnet run --project EclipsVault.Web 2>&1 | grep -i "License" | head
```
Expected: a line like `License check: Missing — No license is configured…` (Development uses no pinned key, so Missing is expected) OR an Info line if a dev token is configured. Stop the app (Ctrl-C).

- [ ] **Step 8: Commit**

```bash
git add EclipsVault.Core/Domain/Enums/AuditAction.cs EclipsVault.Core/Application/Activity/ActivityDescriber.cs EclipsVault.Web/Program.cs EclipsVault.Tests/Licensing/LicenseActivityTests.cs
git commit -m "Licensing: startup status log + fail-soft unlicensed-in-production audit row

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: License admin page + global nudge banner

**Files:**
- Create: `EclipsVault.Web/Services/LicenseNudgeState.cs`
- Create: `EclipsVault.Web/Controllers/LicenseController.cs`
- Create: `EclipsVault.Web/Models/LicenseViewModel.cs`
- Create: `EclipsVault.Web/Views/License/Index.cshtml`
- Create: `EclipsVault.Web/Views/Shared/_LicenseBanner.cshtml`
- Modify: `EclipsVault.Web/Program.cs` (register `LicenseNudgeState`)
- Modify: `EclipsVault.Web/Views/Shared/_Layout.cshtml` (render banner + sidebar link)

**Interfaces:**
- Consumes: `ILicenseState`, `LicenseFeatures`, `LicenseStatus`, `VaultPolicies` (existing).
- Produces: `sealed record LicenseNudgeState(LicenseStatus Status, string Message, IReadOnlyList<string> PremiumFeaturesBeyondTier)` with `bool ShowBanner`.

- [ ] **Step 1: Create `LicenseNudgeState`**

```csharp
// EclipsVault.Web/Services/LicenseNudgeState.cs
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Web.Services;

/// <summary>
/// The precomputed inputs to the licensing banner: the license status and any premium features that
/// are switched on in configuration but not covered by the current tier. Computed once at startup.
/// </summary>
public sealed record LicenseNudgeState(
    LicenseStatus Status,
    string Message,
    IReadOnlyList<string> PremiumFeaturesBeyondTier)
{
    public bool ShowBanner => Status != LicenseStatus.Valid || PremiumFeaturesBeyondTier.Count > 0;
}
```

- [ ] **Step 2: Register `LicenseNudgeState` in `Program.cs`**

In `EclipsVault.Web/Program.cs`, in the service-registration section (before `builder.Build()`), add:

```csharp
builder.Services.AddSingleton(sp =>
{
    var license = sp.GetRequiredService<ILicenseState>();
    var cfg = sp.GetRequiredService<IConfiguration>();
    var beyond = new List<string>();

    // Config-active premium features (usage-based ones are shown on the page, not nudged in v1).
    if (string.Equals(cfg["Crypto:Engine"], "VaultTransit", StringComparison.OrdinalIgnoreCase)
        && !license.Allows(LicenseFeatures.Kms)) beyond.Add(LicenseFeatures.Kms);
    if (cfg.GetValue<bool>("Redis:Enabled") && !license.Allows(LicenseFeatures.RedisHa))
        beyond.Add(LicenseFeatures.RedisHa);
    if (!string.IsNullOrWhiteSpace(cfg["Sso:Authority"]) && !license.Allows(LicenseFeatures.Sso))
        beyond.Add(LicenseFeatures.Sso);

    return new EclipsVault.Web.Services.LicenseNudgeState(license.Status, license.Message, beyond);
});
```

(`ILicenseState` and `LicenseFeatures` usings already added to `Program.cs` in Task 6.)

- [ ] **Step 3: Create the view model + controller**

```csharp
// EclipsVault.Web/Models/LicenseViewModel.cs
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Web.Models;

public sealed record LicenseViewModel(
    LicenseStatus Status,
    string Message,
    LicenseClaims? Claims,
    IReadOnlyList<string> PremiumFeaturesBeyondTier);
```

```csharp
// EclipsVault.Web/Controllers/LicenseController.cs
using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Models;
using EclipsVault.Web.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers;

[Authorize(Policy = VaultPolicies.AdminOnly)]
public sealed class LicenseController : Controller
{
    private readonly ILicenseState _license;
    private readonly LicenseNudgeState _nudge;

    public LicenseController(ILicenseState license, LicenseNudgeState nudge)
    {
        _license = license;
        _nudge = nudge;
    }

    [HttpGet("/admin/license")]
    public IActionResult Index()
        => View(new LicenseViewModel(_license.Status, _license.Message, _license.Claims, _nudge.PremiumFeaturesBeyondTier));
}
```

Note: confirm the namespace of `VaultPolicies` by opening `EclipsVault.Web/Controllers/AuditController.cs` and matching its `using` for `VaultPolicies`; adjust the `using EclipsVault.Web.Authorization;` line if it differs.

- [ ] **Step 4: Create the License page view**

```html
@* EclipsVault.Web/Views/License/Index.cshtml *@
@model EclipsVault.Web.Models.LicenseViewModel
@{
    ViewData["Title"] = "License";
}

<div class="page-header">
    <h1>License</h1>
</div>

<div class="panel">
    <p><strong>Status:</strong> @Model.Status</p>
    <p>@Model.Message</p>

    @if (Model.Claims is { } c)
    {
        <dl class="data-table">
            <dt>Licensed to</dt><dd>@c.IssuedTo</dd>
            <dt>Tier</dt><dd>@c.Tier</dd>
            <dt>License id</dt><dd>@c.LicenseId</dd>
            <dt>Issued</dt><dd>@c.IssuedAtUtc.ToString("u")</dd>
            <dt>Expires</dt><dd>@(c.NotAfterUtc?.ToString("u") ?? "never")</dd>
            <dt>Node allowance</dt><dd>@(c.MaxNodes == 0 ? "unlimited" : c.MaxNodes.ToString())</dd>
        </dl>
    }

    @if (Model.PremiumFeaturesBeyondTier.Count > 0)
    {
        <p><strong>In use beyond your tier:</strong> @string.Join(", ", Model.PremiumFeaturesBeyondTier)</p>
    }
</div>

<div class="panel">
    <h2>Installing a license</h2>
    <p>
        Set the <code>ECLIPSVAULT_LICENSE</code> environment variable to your license token, or place
        the token in a <code>license.key</code> file in the app's content root, then restart. See the
        Pricing &amp; licensing section of the README to buy or renew.
    </p>
</div>
```

Note: `page-header`, `panel`, and `data-table` are existing site classes (used across the app — see any admin view, e.g. `Views/Audit/Index.cshtml`). If `data-table` doesn't suit a `<dl>`, use a plain `<dl>` and mirror the markup of an existing detail view. No inline styles (CSP).

- [ ] **Step 5: Create the banner partial**

Open `EclipsVault.Web/Views/Shared/_Flash.cshtml` and mirror its alert markup/classes so the banner is styled and CSP-clean. Then create:

```html
@* EclipsVault.Web/Views/Shared/_LicenseBanner.cshtml *@
@inject EclipsVault.Web.Services.LicenseNudgeState Nudge
@if (Nudge.ShowBanner)
{
    @* Mirror the container/classes used by _Flash.cshtml for a warning-level notice. *@
    <div class="flash flash-warning" role="status">
        @if (Nudge.Status != EclipsVault.Core.Domain.Enums.LicenseStatus.Valid)
        {
            <span>@Nudge.Message This changes nothing about how the vault runs — it only affects this notice. <a href="/admin/license">Details</a></span>
        }
        else
        {
            <span>Premium features in use beyond your license tier: @string.Join(", ", Nudge.PremiumFeaturesBeyondTier). <a href="/admin/license">Details</a></span>
        }
    </div>
}
```

Note: replace `flash flash-warning` with the actual warning classes from `_Flash.cshtml`.

- [ ] **Step 6: Render the banner + add a sidebar link in `_Layout.cshtml`**

In `EclipsVault.Web/Views/Shared/_Layout.cshtml`, next to the existing `<partial name="_Flash" />` (line ~247), add:

```html
        <partial name="_LicenseBanner" />
```

Add a sidebar nav entry to the admin group (mirror an existing admin link such as the Audit log entry), pointing at `/admin/license` with the label `License`. The command palette will pick it up automatically from the rendered `<a>` (no extra wiring).

- [ ] **Step 7: Build and live-verify the page + banner**

Run:
```bash
dotnet build EclipsVault.Web/EclipsVault.Web.csproj -v q --nologo
dotnet run --project EclipsVault.Web
```
Then in a browser at `https://localhost:7443`: sign in as `vault-admin` / `ChangeMe!Umbra#2026-Admin` (complete TOTP), and confirm (a) a warning banner appears (Development has no license → status Missing), and (b) `/admin/license` renders the status and the install instructions. Stop the app.

Expected: banner visible on authenticated pages; License page shows `Status: Missing` and the help text; no console errors; CSP not violated (no inline-style/script errors in the browser console).

- [ ] **Step 8: Commit**

```bash
git add EclipsVault.Web/Services/LicenseNudgeState.cs EclipsVault.Web/Controllers/LicenseController.cs EclipsVault.Web/Models/LicenseViewModel.cs EclipsVault.Web/Views/License/ EclipsVault.Web/Views/Shared/_LicenseBanner.cshtml EclipsVault.Web/Views/Shared/_Layout.cshtml EclipsVault.Web/Program.cs
git commit -m "Licensing: admin License page + non-blocking nudge banner

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Phase 4 — Trust & packaging

### Task 8: `SECURITY.md`

**Files:**
- Create: `SECURITY.md`

- [ ] **Step 1: Create the file**

```markdown
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
```

- [ ] **Step 2: Commit**

```bash
git add SECURITY.md
git commit -m "Add SECURITY.md: private disclosure channel, scope, safe harbor, continuity

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: Production `Dockerfile` + `.dockerignore`

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`

- [ ] **Step 1: Create `.dockerignore`**

```gitignore
# Build outputs
**/bin/
**/obj/
# Local dev secrets — must never enter an image
**/appsettings.Development.json
**/appsettings.*.Development.json
# VCS / docs / tooling
.git/
.github/
docs/
**/*.md
# Local key rings / license files
keyring/
license.key
```

- [ ] **Step 2: Create `Dockerfile`**

```dockerfile
# Multi-stage production image for EclipsVault.Web. TLS is expected to terminate at a reverse
# proxy/ingress (see docs/INSTALL.md); the app listens on plain HTTP inside the network.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore EclipsVault.Web/EclipsVault.Web.csproj --locked-mode
RUN dotnet publish EclipsVault.Web/EclipsVault.Web.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# Run as a non-root user.
RUN adduser --disabled-password --gecos "" --uid 10001 vault \
    && chown -R vault /app
USER vault

ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "EclipsVault.Web.dll"]
```

- [ ] **Step 3: Pin the base images to digests**

Digest-pinning matches the project's supply-chain posture (the compose file pins every image). Resolve the current digests and pin them:

```bash
docker pull mcr.microsoft.com/dotnet/sdk:10.0
docker inspect --format='{{index .RepoDigests 0}}' mcr.microsoft.com/dotnet/sdk:10.0
docker pull mcr.microsoft.com/dotnet/aspnet:10.0
docker inspect --format='{{index .RepoDigests 0}}' mcr.microsoft.com/dotnet/aspnet:10.0
```

Edit the two `FROM` lines to append the resolved digests, e.g.:
`FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:<resolved> AS build` and
`FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:<resolved> AS runtime`.

- [ ] **Step 4: Build the image to verify it compiles and runs as non-root**

```bash
docker build -t eclipsvault:local .
docker run --rm eclipsvault:local dotnet --info >/dev/null && echo "image OK"
```
Expected: image builds; the command runs (no root-permission errors).

- [ ] **Step 5: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "Add production Dockerfile (non-root, digest-pinned) and .dockerignore

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 10: `docs/INSTALL.md` production runbook

**Files:**
- Create: `docs/INSTALL.md`

- [ ] **Step 1: Create the file**

```markdown
# Production installation

EclipsVault is self-hosted: you run it in your own environment, hold your own keys, and manage your
own database and backups. This is the whole security model — the vendor never has access to your
secrets or your servers. This guide is the production runbook; for feature detail see the README.

## 1. Prerequisites

- A database: SQL Server or PostgreSQL 17+ (see `Database:Provider`).
- A TLS-terminating reverse proxy or ingress in front of the app (the container serves plain HTTP on
  port 8080 inside your network).
- A place to hold a persistent Data Protection key ring directory, shared by every replica.

## 2. Required configuration (environment variables)

| Variable | Purpose |
|---|---|
| `ConnectionStrings__DefaultConnection` | Database connection string. Use a least-privilege login and enforce TLS (`Encrypt=True;TrustServerCertificate=False` on SQL Server, `SSL Mode=Require` on PostgreSQL). |
| `Database__Provider` | `SqlServer` (default) or `Postgres`. |
| `ECLIPSVAULT_KEK` | Master key: `openssl rand -base64 32`. Or use a KMS engine (`Crypto__Engine=VaultTransit`, `VAULT_TOKEN`, `Vault__Address`). |
| `ECLIPSVAULT_AUDIT_SIGNING_KEY` | Base64 PKCS#8 P-256 private key for signing audit checkpoints. |
| `DataProtection__KeyRingPath` | Durable directory shared by all nodes (sealed at rest with the KEK). |
| `ECLIPSVAULT_LICENSE` | Your license token (or place it in a `license.key` file in the content root). |
| `ASPNETCORE_ENVIRONMENT` | Must be `Production` (anything other than `Development` disables dev seeding and fallbacks). |
| `ForwardedHeaders__KnownProxies` | The IP(s) of your reverse proxy, so the real client IP is trusted for rate limiting, the IP blacklist, ABAC network rules, and audit. |
| `AllowedHosts` | Your vault's hostname(s), so a spoofed `Host` header is rejected. |

## 3. Apply the schema from your deploy job (not the app)

The running app does not have rights to change the schema. Run migrations once, from your deploy
pipeline, with a login that has DDL rights (which the app's own login does not):

    ConnectionStrings__DefaultConnection="…" \
    dotnet ef database update --project EclipsVault.Infrastructure --startup-project EclipsVault.Web

For PostgreSQL, use `EclipsVault.Migrations.Postgres` and set `ECLIPSVAULT_DESIGN_PROVIDER=Postgres`.
The app verifies the schema at startup and refuses to start against a mismatched one.

## 4. First administrator

On an empty vault, create the first admin once (screened like any password), then remove the setting:

    Seed__AdminPassword='<a password unique to this deployment>' dotnet EclipsVault.Web.dll

## 5. Run (Docker)

    docker run -d --name eclipsvault \
      -e ConnectionStrings__DefaultConnection="…" \
      -e Database__Provider=Postgres \
      -e ECLIPSVAULT_KEK="…" \
      -e ECLIPSVAULT_AUDIT_SIGNING_KEY="…" \
      -e DataProtection__KeyRingPath=/keyring \
      -e ECLIPSVAULT_LICENSE="EVLIC1.…" \
      -e ASPNETCORE_ENVIRONMENT=Production \
      -e ForwardedHeaders__KnownProxies="10.0.0.2" \
      -e AllowedHosts="vault.example.com" \
      -v /srv/eclipsvault/keyring:/keyring \
      -p 8080:8080 \
      eclipsvault:local

Put your reverse proxy in front, terminating TLS and forwarding `X-Forwarded-For` /
`X-Forwarded-Proto` to the container.

## 6. Verify

- The app starts and logs `License: Licensed to …` (or a warning if unlicensed — it still runs).
- Sign in, complete TOTP, open a secret.
- On the admin **Audit log** page, run **Verify integrity** — the chain reports intact.

## 7. Backups

Back up the database **and** the Data Protection key ring directory. The key ring is sealed with your
KEK, so a backup is inert without `ECLIPSVAULT_KEK` — keep the KEK in your secret manager, not beside
the backup.
```

- [ ] **Step 2: Commit**

```bash
git add docs/INSTALL.md
git commit -m "Add docs/INSTALL.md: production deployment runbook

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 11: SBOM step in CI

**Files:**
- Modify: `.github/workflows/ci.yml` (add an `sbom` job)

- [ ] **Step 1: Add the job**

In `.github/workflows/ci.yml`, add a new job under `jobs:` (sibling to `build-test`, `migrations`, `security-scan`):

```yaml
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup .NET
        uses: actions/setup-dotnet@v4
        with:
          dotnet-version: '10.0.x'

      - name: Install CycloneDX
        run: dotnet tool install --global CycloneDX

      - name: Restore (locked)
        run: dotnet restore --locked-mode

      # A software bill of materials for the deployed app: every transitive dependency, so a
      # consumer can audit what ships. Fits the pin-and-prove supply-chain posture.
      - name: Generate SBOM
        run: dotnet CycloneDX EclipsVault.Web/EclipsVault.Web.csproj -o sbom -f sbom.json

      - name: Upload SBOM
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: sbom/sbom.json
```

- [ ] **Step 2: Verify the SBOM generation locally**

```bash
dotnet tool install --global CycloneDX || dotnet tool update --global CycloneDX
dotnet restore --locked-mode
dotnet CycloneDX EclipsVault.Web/EclipsVault.Web.csproj -o sbom -f sbom.json
test -s sbom/sbom.json && echo "SBOM generated"
rm -rf sbom
```
Expected: `sbom/sbom.json` is created and non-empty. (Clean it up — it's a CI artifact, not committed. Confirm `sbom/` is covered by `.gitignore` or add it.)

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "CI: generate a CycloneDX SBOM for the app as a build artifact

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Phase 5 — README pricing

### Task 12: README "Pricing & licensing" section

**Files:**
- Modify: `README.md` (add a section near the existing "Licence" section, around line 400)

- [ ] **Step 1: Add the section**

Insert immediately before the existing `## Licence` heading in `README.md`:

```markdown
## Pricing & licensing

EclipsVault is **self-hosted**: you run it in your own environment and hold your own keys — the
vendor never sees your secrets or your servers. A production license is an **annual subscription per
production deployment** (one install, however many replicas). It buys three things: the legal right
to run in production, ongoing security patches, and best-effort email support. It is enforced softly
— an unlicensed or lapsed vault shows a banner and records it, but **never** stops serving secrets.

| Tier | Price | For |
|---|---|---|
| **Community** | Free | Non-production, homelab, and 60-day evaluation. All features present. |
| **Pro** | $249/year per deployment | SSO, PostgreSQL, dynamic secrets, Redis HA, KMS engine + email support. |
| **Enterprise / Support** | Custom (annual) | Managed rotation, signed audit attestation, priority security patches, MSA/DPA, deployment help. |

**Continuity:** if maintenance ever stops, the intent is that customers keep the source and the right
to run and patch what they have deployed — a paused project never strands a running vault.

**Buy / renew:** _<Merchant-of-Record link — Polar or Lemon Squeezy — to be added at launch>_.
Contact `sabashvili13@icloud.com` for Enterprise or an invoice.

### Installing your license

Set the token you receive at purchase as `ECLIPSVAULT_LICENSE`, or place it in a `license.key` file
in the app's content root, then restart. The admin **License** page shows your status, tier, and
expiry.
```

- [ ] **Step 2: Verify the README renders (no broken table/markdown)**

```bash
grep -n "Pricing & licensing" README.md
```
Expected: the heading is found once; visually skim the table renders (pipes aligned, three tiers).

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "README: add Pricing & licensing section (tiers, continuity, install)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review (completed by plan author)

**Spec coverage:** token format (Tasks 2-3) ✓; Core primitives incl. tier→feature map & pinned key (Tasks 1-3) ✓; minting CLI (Task 4) ✓; LicenseService/options/DI + env→file transport + dev-key override (Task 5) ✓; startup log + fail-soft audit row + describer (Task 6) ✓; License page + nudge banner + config-active premium detection (Task 7) ✓; SECURITY.md (8), Dockerfile (9), INSTALL.md (10), SBOM CI (11), README pricing (12) ✓; safety invariant enforced (no license check on secret path — verifier is pure, service is read-only, all surfaces are log/banner/audit) ✓; per-deployment pricing + continuity ✓.

**Placeholder scan:** the only intentional placeholders are the empty pinned public key (`LicensePublicKey.VendorSpkiBase64 = ""`, replaced by the operator via `keygen`), the MoR buy link (does not exist until launch), and the base-image digests (resolved by a provided command in Task 9 Step 3). Each has an explicit resolution step. No vague "add error handling"/"write tests" placeholders.

**Type consistency:** `LicenseClaims`, `LicenseVerification`, `LicenseVerifier.Verify(string?, byte[], DateTimeOffset)`, `LicenseSigner.Sign(LicenseClaims, ECDsa)`, `LicenseToken.Encode/TryDecode`, `LicenseCanonical.Serialize/TryDeserialize`, `ILicenseState.Allows`, `LicenseNudgeState.ShowBanner` are used identically across tasks.
