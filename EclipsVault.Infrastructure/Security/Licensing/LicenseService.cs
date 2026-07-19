using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Security.Licensing;

/// <summary>
/// Resolves the license once at startup: reads the token (environment variable, then file), verifies
/// it against the pinned vendor key with <see cref="LicenseVerifier"/>, and caches the outcome. A
/// singleton, so verification runs exactly once. Deliberately soft — it computes state and never
/// throws; nothing here touches the secret read or decrypt path.
/// </summary>
public sealed class LicenseService : ILicenseState
{
    private readonly LicenseVerification _result;
    private readonly IReadOnlySet<string> _features;

    public LicenseService(
        IOptions<LicenseOptions> options,
        IHostEnvironment environment,
        TimeProvider clock,
        ILogger<LicenseService> logger)
    {
        var opts = options.Value;
        var publicKey = ResolvePublicKey(opts, environment, logger);
        var token = ResolveToken(opts, logger);

        _result = LicenseVerifier.Verify(token, publicKey, clock.GetUtcNow());

        // Entitlement is populated only for a Valid license, so Allows() is false for anything else
        // (Missing/Malformed/InvalidSignature/Expired) without a second status check.
        _features = _result.Status == LicenseStatus.Valid && _result.Claims is { } claims
            ? LicenseTierFeatures.Effective(claims)
            : new HashSet<string>();
    }

    public LicenseStatus Status => _result.Status;
    public LicenseClaims? Claims => _result.Claims;
    public string Message => _result.Message;

    public bool Allows(string feature) => _features.Contains(feature);

    private static byte[] ResolvePublicKey(LicenseOptions opts, IHostEnvironment environment, ILogger logger)
    {
        // In Development an operator can point at a locally-minted key without touching the pinned
        // production key. Honored only in Development so a stray dev key can never widen trust in prod.
        if (environment.IsDevelopment() && !string.IsNullOrWhiteSpace(opts.DevelopmentPublicKeySpki))
        {
            try
            {
                return Convert.FromBase64String(opts.DevelopmentPublicKeySpki);
            }
            catch (FormatException)
            {
                logger.LogWarning(
                    "License:DevelopmentPublicKeySpki is not valid base64; falling back to the pinned vendor key.");
            }
        }

        return LicensePublicKey.Spki;
    }

    private static string? ResolveToken(LicenseOptions opts, ILogger logger)
    {
        // Precedence: the environment variable wins (how a container injects the license); a file path
        // is the fallback for deployments that mount the token as a secret file.
        var fromEnvironment = string.IsNullOrWhiteSpace(opts.EnvironmentVariable)
            ? null
            : Environment.GetEnvironmentVariable(opts.EnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(fromEnvironment))
            return fromEnvironment;

        if (string.IsNullOrWhiteSpace(opts.FilePath) || !File.Exists(opts.FilePath))
            return null;

        try
        {
            return File.ReadAllText(opts.FilePath).Trim();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            logger.LogWarning(ex, "Could not read the license file at {Path}; running unlicensed.", opts.FilePath);
            return null;
        }
    }
}
