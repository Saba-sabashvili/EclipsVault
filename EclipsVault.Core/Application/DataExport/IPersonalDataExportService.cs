namespace EclipsVault.Core.Application.DataExport;

/// <summary>
/// Assembles a user's personal-data export from the existing account services. Strictly
/// self-scoped: every read is keyed by the caller's own user id, so the export can only ever
/// contain the caller's own data. Composition only — it holds no data of its own and performs
/// no decryption.
/// </summary>
public interface IPersonalDataExportService
{
    /// <summary>
    /// Builds the export for one user, or null when the account no longer exists (so a stale
    /// session can be sent to sign out, mirroring the other self-service services).
    /// </summary>
    Task<PersonalDataExport?> BuildForUserAsync(Guid userId, CancellationToken ct);
}
