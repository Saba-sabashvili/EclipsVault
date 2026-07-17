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
