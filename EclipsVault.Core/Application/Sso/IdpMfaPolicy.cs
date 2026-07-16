namespace EclipsVault.Core.Application.Sso;

/// <summary>
/// Decides whether an identity provider actually performed multi-factor authentication, from its
/// <c>amr</c> claim (RFC 8176).
///
/// <para>This exists because the alternative is to guess. The vault requires two factors; if SSO
/// simply skipped its own second factor, then every account here would be exactly as strong as a
/// single IdP password — and nobody would notice, because the sign-in still says "success". A factor
/// may only be waived if the IdP <em>says</em> it performed one.</para>
///
/// <para>Silence is not assurance. <c>amr</c> is optional and most providers omit it unless
/// configured (Keycloak among them), so an absent or unrecognised claim means "no factors asserted",
/// never "probably fine". The cost of being wrong here is a one-time TOTP prompt; the cost of the
/// opposite is a vault protected by one password.</para>
/// </summary>
public static class IdpMfaPolicy
{
    /// <summary>RFC 8176: the IdP performed multiple factors and is saying so directly.</summary>
    private const string MultiFactor = "mfa";

    /// <summary>Something you know.</summary>
    private static readonly HashSet<string> Knowledge =
        new(StringComparer.OrdinalIgnoreCase) { "pwd", "pin" };

    /// <summary>Something you have, or something you are. Deliberately excludes "sms" and "tel":
    /// they are widely accepted and widely defeated by SIM swapping, and this is a secrets vault.</summary>
    private static readonly HashSet<string> Possession =
        new(StringComparer.OrdinalIgnoreCase) { "otp", "hwk", "swk", "face", "fpt", "iris", "retina", "vbm", "user", "pop" };

    /// <summary>
    /// True when <paramref name="amr"/> asserts two genuinely different factors — either the IdP
    /// claims <c>mfa</c> outright, or it names both a knowledge factor and a possession/biometric
    /// one. Two of the same kind is one factor twice.
    /// </summary>
    public static bool AssertedMultiFactor(IReadOnlyCollection<string>? amr)
    {
        if (amr is null || amr.Count == 0)
        {
            return false;
        }

        if (amr.Any(m => MultiFactor.Equals(m, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return amr.Any(Knowledge.Contains) && amr.Any(Possession.Contains);
    }
}
