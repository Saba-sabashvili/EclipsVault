namespace EclipsVault.Infrastructure.Security.Licensing;

/// <summary>
/// Where to find the license token and, in Development only, an override public key. Everything is
/// optional: with nothing configured the vault runs unlicensed (soft), never blocked.
/// </summary>
public sealed class LicenseOptions
{
    public const string SectionName = "License";

    /// <summary>Environment variable carrying the <c>EVLIC1</c> token. This is how a container injects it.</summary>
    public string EnvironmentVariable { get; init; } = "ECLIPSVAULT_LICENSE";

    /// <summary>Fallback file to read the token from when the environment variable is unset (e.g. a mounted secret).</summary>
    public string? FilePath { get; init; }

    /// <summary>
    /// A base64 SPKI public key that replaces the pinned vendor key — honored <em>only</em> in the
    /// Development environment, so a locally-minted key can be verified without editing the build.
    /// Ignored in every other environment, so it can never widen trust in production.
    /// </summary>
    public string? DevelopmentPublicKeySpki { get; init; }
}
