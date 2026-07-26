using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Adapts <see cref="SsoOptions"/> to <see cref="ISsoAvailability"/>, handing the presentation layer
/// the two fields it renders and nothing else — notably not <see cref="SsoOptions.ClientSecret"/>.
/// Reads through to the options monitor rather than snapshotting, so the port never becomes a stale
/// copy of configuration.
/// </summary>
public sealed class SsoAvailability : ISsoAvailability
{
    private readonly IOptions<SsoOptions> _options;

    public SsoAvailability(IOptions<SsoOptions> options) => _options = options;

    public bool Enabled => _options.Value.Enabled;

    public string DisplayName => _options.Value.DisplayName;
}
