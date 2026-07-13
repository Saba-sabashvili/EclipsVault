using EclipsVault.Core.Domain.Exceptions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Factory Pattern: resolves the crypto engine named in configuration. Moving from
/// local AES-GCM to a cloud KMS means registering the new engine here and flipping
/// the "Crypto:Engine" setting — the business layer is untouched.
/// </summary>
public sealed class CryptoEngineFactory : ICryptoEngineFactory
{
    private readonly IServiceProvider _services;
    private readonly CryptoOptions _options;

    public CryptoEngineFactory(IServiceProvider services, IOptions<CryptoOptions> options)
    {
        _services = services;
        _options = options.Value;
    }

    public ICryptoEngine Create() => _options.Engine switch
    {
        AesGcmCryptoEngine.EngineName => _services.GetRequiredService<AesGcmCryptoEngine>(),
        // e.g. "AwsKms" => _services.GetRequiredService<AwsKmsCryptoEngine>(),
        _ => throw new CryptoConfigurationException(
            $"Unknown crypto engine '{_options.Engine}'. Register the engine in {nameof(CryptoEngineFactory)} " +
            "and select it via the 'Crypto:Engine' configuration key.")
    };
}
