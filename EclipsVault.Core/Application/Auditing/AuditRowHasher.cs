using System.Security.Cryptography;
using System.Text;
using EclipsVault.Core.Domain.Entities;

namespace EclipsVault.Core.Application.Auditing;

/// <summary>
/// Computes the tamper-evidence hash for an audit row. Pure and deterministic, so the same
/// function seals a new row (in the chain) and re-verifies it later. The hash binds the row's
/// immutable content <em>and</em> the previous row's hash, so altering, deleting, reordering,
/// or inserting any row breaks the chain from that point on.
/// </summary>
public static class AuditRowHasher
{
    /// <summary>The "previous hash" of the very first row — a fixed chain anchor.</summary>
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    private const char FieldSeparator = ''; // ASCII unit separator — will not appear in the fields.

    public static string Compute(AuditLog row, string previousHash)
    {
        var canonical = string.Join(FieldSeparator,
            row.Sequence.ToString(),
            row.Id.ToString("N"),
            row.TimestampUtc.UtcTicks.ToString(),
            row.UserId?.ToString("N") ?? string.Empty,
            row.Username,
            row.SourceIp,
            ((int)row.Action).ToString(),
            row.ResourceType,
            row.ResourceId?.ToString("N") ?? string.Empty,
            row.ResourceName ?? string.Empty,
            row.Details ?? string.Empty,
            row.IsCritical ? "1" : "0",
            previousHash);

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(digest).ToLowerInvariant();
    }
}
