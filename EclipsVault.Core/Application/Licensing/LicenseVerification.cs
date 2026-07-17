using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Licensing;

/// <summary>The result of verifying a license token. <see cref="Claims"/> is populated only when
/// the signature is trusted (Valid or Expired) — never for an unverifiable token.</summary>
public sealed record LicenseVerification(LicenseStatus Status, LicenseClaims? Claims, string Message);
