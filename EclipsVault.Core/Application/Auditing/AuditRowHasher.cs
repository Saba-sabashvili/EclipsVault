using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using EclipsVault.Core.Domain.Entities;

namespace EclipsVault.Core.Application.Auditing;

/// <summary>
/// Computes the tamper-evidence hash for an audit row. Pure and deterministic, so the same
/// function seals a new row (in the chain) and re-verifies it later. The hash binds the row's
/// immutable content <em>and</em> the previous row's hash, so altering, deleting, reordering,
/// or inserting any row breaks the chain from that point on.
///
/// <para>
/// The canonical form is <b>versioned</b>, and the version travels on the row. Changing how a row
/// is hashed changes every hash, so a chain sealed under an older scheme must keep verifying under
/// that scheme forever — re-hashing stored rows to a new format would mean rewriting the very
/// evidence the chain exists to protect, and would invalidate any bundle an auditor already holds.
/// Old rows are therefore verified as they were written, and only new rows use the current version.
/// </para>
/// </summary>
public static class AuditRowHasher
{
    /// <summary>The "previous hash" of the very first row — a fixed chain anchor.</summary>
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";

    /// <summary>
    /// Length-prefixed canonicalisation. New rows are sealed with this; see <see cref="ComputeV2"/>.
    /// </summary>
    public const int CurrentVersion = 2;

    /// <summary>Rows written before the version column existed are version 1 by definition.</summary>
    public const int LegacyVersion = 1;

    private const char FieldSeparator = ''; // ASCII unit separator — v1 only.

    /// <summary>
    /// Hashes a row using the scheme its <see cref="AuditLog.HashVersion"/> names. A row that
    /// carries no version (0, e.g. read from a pre-upgrade bundle) is treated as version 1.
    /// </summary>
    public static string Compute(AuditLog row, string previousHash)
        => row.HashVersion >= CurrentVersion
            ? ComputeV2(row, previousHash)
            : ComputeV1(row, previousHash);

    /// <summary>
    /// Version 1 — fields joined by ASCII unit separator. <b>Retained only to verify rows sealed
    /// before version 2; never used for new rows.</b> It is ambiguous: the separator was assumed
    /// absent from every field, but nothing enforced that, so content shifted across a field
    /// boundary could produce an identical hash (see <see cref="ComputeV2"/>).
    /// </summary>
    public static string ComputeV1(AuditLog row, string previousHash)
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

    /// <summary>
    /// Version 2 — every field is written as its UTF-8 byte length (4 bytes, big-endian) followed
    /// by its bytes. There is no separator, so there is no character a field could contain that
    /// would shift a boundary: any two distinct field lists produce distinct bytes. This closes the
    /// v1 ambiguity, where free-text fields reachable from an identity provider (an email in
    /// <c>Username</c>, <c>ResourceName</c> or <c>Details</c>) could carry the separator and let a
    /// tampered row keep a valid hash.
    /// </summary>
    public static string ComputeV2(AuditLog row, string previousHash)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

        // The version is bound first, so a row cannot be replayed under a different scheme.
        WriteField(hash, CurrentVersion.ToString());
        WriteField(hash, row.Sequence.ToString());
        WriteField(hash, row.Id.ToString("N"));
        WriteField(hash, row.TimestampUtc.UtcTicks.ToString());
        WriteField(hash, row.UserId?.ToString("N") ?? string.Empty);
        WriteField(hash, row.Username);
        WriteField(hash, row.SourceIp);
        WriteField(hash, ((int)row.Action).ToString());
        WriteField(hash, row.ResourceType);
        WriteField(hash, row.ResourceId?.ToString("N") ?? string.Empty);
        WriteField(hash, row.ResourceName ?? string.Empty);
        WriteField(hash, row.Details ?? string.Empty);
        WriteField(hash, row.IsCritical ? "1" : "0");
        WriteField(hash, previousHash);

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static void WriteField(IncrementalHash hash, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
        hash.AppendData(length);
        hash.AppendData(bytes);
    }
}
