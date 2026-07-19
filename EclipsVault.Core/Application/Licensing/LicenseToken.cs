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
