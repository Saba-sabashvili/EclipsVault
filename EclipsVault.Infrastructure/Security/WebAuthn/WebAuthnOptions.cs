namespace EclipsVault.Infrastructure.Security.WebAuthn;

/// <summary>
/// Relying-party identity for WebAuthn ceremonies. The <see cref="RelyingPartyId"/> is the
/// registrable domain the credential is bound to (never a full origin), and every accepted
/// browser <see cref="Origins"/> value must match the request's <c>clientDataJSON.origin</c>.
/// </summary>
public sealed class WebAuthnOptions
{
    public const string SectionName = "WebAuthn";

    /// <summary>Relying-party id — the effective domain (e.g. "localhost" or "vault.example.com"). No scheme, no port.</summary>
    public string RelyingPartyId { get; set; } = "localhost";

    /// <summary>Human-readable relying-party name shown by the authenticator UI.</summary>
    public string RelyingPartyName { get; set; } = "EclipsVault";

    /// <summary>Exact origins the ceremony will accept (scheme + host + port).</summary>
    public string[] Origins { get; set; } = ["https://localhost:7443"];
}
