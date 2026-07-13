using System.Text;

namespace EclipsVault.Core.Application.Auditing;

/// <summary>
/// The exact byte sequence that is signed for (and verified against) a checkpoint. Shared by
/// the signer in Infrastructure and the pure verifier in Core so both agree bit-for-bit —
/// a mismatch here would make every signature fail to verify.
/// </summary>
public static class AuditCheckpointCanonical
{
    private const char FieldSeparator = ''; // ASCII unit separator — absent from the fields.

    public static byte[] Bytes(long sequence, string chainHeadHash, DateTimeOffset createdAtUtc)
        => Encoding.UTF8.GetBytes(string.Join(FieldSeparator,
            sequence.ToString(),
            chainHeadHash,
            createdAtUtc.UtcTicks.ToString()));
}
