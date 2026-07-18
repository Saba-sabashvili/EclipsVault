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
        if (!TryTicks(f[4], out var issuedAt)) return false;
        DateTimeOffset? notAfter = null;
        if (f[5] != "-")
        {
            if (!TryTicks(f[5], out var na)) return false;
            notAfter = na;
        }
        if (!int.TryParse(f[6], out var maxNodes)) return false;
        var features = f[7].Length == 0 ? [] : f[7].Split(',');

        claims = new LicenseClaims(
            f[0], (LicenseTier)tierValue, issuedTo!, contact,
            issuedAt, notAfter, maxNodes, features);
        return true;
    }

    // A tick count that parses as a long can still be outside the DateTime range, and the
    // DateTimeOffset(long, TimeSpan) constructor throws for those. This runs before the signature
    // check on operator/attacker-controlled bytes, so it must reject — never throw.
    private static bool TryTicks(string s, out DateTimeOffset value)
    {
        value = default;
        if (!long.TryParse(s, out var ticks)) return false;
        if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks) return false;
        value = new DateTimeOffset(ticks, TimeSpan.Zero);
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
