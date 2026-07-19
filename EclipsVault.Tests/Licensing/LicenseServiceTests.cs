using System.Security.Cryptography;
using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Infrastructure.Security.Licensing;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class LicenseServiceTests
{
    // Minimal IHostEnvironment stub set to Development so the dev public-key override is honored.
    private sealed class FakeEnv : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = Environments.Development;
        public string ApplicationName { get; set; } = "test";
        public string ContentRootPath { get; set; } = AppContext.BaseDirectory;
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    private static LicenseService Build(string? token, string devPublicKeySpki)
    {
        var opts = Options.Create(new LicenseOptions
        {
            EnvironmentVariable = "ECLIPSVAULT_LICENSE_TEST_" + Guid.NewGuid().ToString("N"),
            DevelopmentPublicKeySpki = devPublicKeySpki
        });
        if (token is not null) Environment.SetEnvironmentVariable(opts.Value.EnvironmentVariable, token);
        return new LicenseService(opts, new FakeEnv(), TimeProvider.System, NullLogger<LicenseService>.Instance);
    }

    [Fact]
    public void A_valid_pro_token_reports_valid_and_grants_pro_features()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var claims = new LicenseClaims("lic-1", LicenseTier.Pro, "Acme", null,
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1), 3, []);
        var token = LicenseSigner.Sign(claims, key);
        var pub = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

        var svc = Build(token, pub);

        Assert.Equal(LicenseStatus.Valid, svc.Status);
        Assert.True(svc.Allows(LicenseFeatures.Kms));
        Assert.False(svc.Allows(LicenseFeatures.ManagedRotation));
    }

    [Fact]
    public void No_token_reports_missing_and_allows_nothing()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var svc = Build(token: null, Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));

        Assert.Equal(LicenseStatus.Missing, svc.Status);
        Assert.False(svc.Allows(LicenseFeatures.Sso));
    }

    [Fact]
    public void An_expired_token_reports_expired_and_grants_no_features()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var claims = new LicenseClaims("lic-2", LicenseTier.Enterprise, "Globex", null,
            DateTimeOffset.UtcNow.AddYears(-2), DateTimeOffset.UtcNow.AddDays(-1), 0, []);
        var token = LicenseSigner.Sign(claims, key);
        var pub = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());

        var svc = Build(token, pub);

        // The verifier surfaces the claims on an expired license (so a banner can name the customer),
        // but entitlement is strictly gated on Valid — an expired license grants nothing.
        Assert.Equal(LicenseStatus.Expired, svc.Status);
        Assert.NotNull(svc.Claims);
        Assert.False(svc.Allows(LicenseFeatures.AuditAttestation));
    }
}
