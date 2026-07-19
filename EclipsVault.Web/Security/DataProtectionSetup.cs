using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.Options;

namespace EclipsVault.Web.Security;

/// <summary>
/// Wires the Data Protection key ring: where it is kept, and what keeps it safe there.
///
/// Left unconfigured, ASP.NET invents a key ring per machine under the user profile and, in a
/// container, per process. The consequences all read as something else: every restart signs
/// everyone out, a second replica cannot decrypt the first's cookies, and form posts fail
/// antiforgery for no visible reason. So outside Development this refuses to start rather than
/// leave an operator to discover it from a support ticket.
/// </summary>
public static class DataProtectionSetup
{
    public static IServiceCollection AddVaultDataProtection(
        this IServiceCollection services, IConfiguration configuration, IHostEnvironment environment)
    {
        var options = configuration.GetSection(DataProtectionOptions.SectionName).Get<DataProtectionOptions>()
                      ?? new DataProtectionOptions();

        // Pinned, not derived from the assembly name: the application name is part of how keys are
        // isolated, so if it ever moved, every existing cookie would stop decrypting at once.
        var builder = services.AddDataProtection().SetApplicationName("EclipsVault");

        if (!string.IsNullOrWhiteSpace(options.KeyRingPath))
        {
            builder.PersistKeysToFileSystem(new DirectoryInfo(options.KeyRingPath));

            // Sealed with the vault's own engine, so the ring is inert without the KEK.
            services.AddSingleton<IXmlEncryptor, KekXmlEncryptor>();
            services.AddSingleton<IConfigureOptions<KeyManagementOptions>>(sp =>
                new ConfigureNamedOptions<KeyManagementOptions>(Options.DefaultName, keyManagement =>
                    keyManagement.XmlEncryptor = sp.GetRequiredService<IXmlEncryptor>()));

            return services;
        }

        if (environment.IsDevelopment() || options.AllowEphemeralKeys)
        {
            return services; // the framework's own per-machine ring
        }

        throw new InvalidOperationException(
            "DataProtection:KeyRingPath is not set, so this vault would encrypt every authentication " +
            "cookie, antiforgery token and session with keys that disappear when the process does — " +
            "signing out every user on each restart, and leaving replicas unable to read one another's " +
            "cookies. Point it at a durable directory shared by every node (the keys are encrypted with " +
            "the vault's KEK, so it need not be secret storage). Set DataProtection:AllowEphemeralKeys=true " +
            "only if you genuinely intend a single throwaway node.");
    }
}
