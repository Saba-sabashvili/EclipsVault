using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// The vault's current license, resolved once at startup. Read-only and side-effect-free; consulted
/// only by nudge surfaces (banner, License page, startup log/audit). Never consulted on the secret
/// read or decrypt path — a bad or missing license must never block the vault.
/// </summary>
public interface ILicenseState
{
    LicenseStatus Status { get; }
    LicenseClaims? Claims { get; }
    string Message { get; }

    /// <summary>True only when the license is Valid and its effective feature set includes the key.</summary>
    bool Allows(string feature);
}
