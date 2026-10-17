using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Web.Controllers;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Testcontainers.MsSql;
using Xunit;

namespace EclipsVault.IntegrationTests;

/// <summary>
/// The release's unchanged entry point and services, Production configuration, real HTTPS sockets
/// and disposable SQL Server. No authentication, audit, antiforgery or revocation service is replaced.
/// AccountController identifies the entry assembly without exposing Program for tests.
/// </summary>
public sealed partial class VaultFixture : IAsyncLifetime
{
    private readonly MsSqlContainer _sql = new MsSqlBuilder(
        "mcr.microsoft.com/mssql/server:2025-latest@sha256:ca62ad2d75975074cbc9ac39a1329cd88af9cd3ea2ffb59d6302579a97cf32f4")
        .WithName("eclipsvault-v141-backport-" + Guid.NewGuid().ToString("N"))
        .WithPassword("Sa1!" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)))
        .Build();
    private readonly DirectoryInfo _keyRing = Directory.CreateTempSubdirectory("eclipsvault-v141-keys-");
    private readonly Dictionary<string, string?> _environment = [];
    private readonly string _adminPassword = "It-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
    private readonly X509Certificate2 _certificate = CreateCertificate();
    private VaultHost? _host;
    private VaultSession? _admin;

    public IServiceProvider Services => _host!.Services;

    public async Task InitializeAsync()
    {
        await _sql.StartAsync();
        using var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        SetEnvironment("ConnectionStrings__DefaultConnection",
            new SqlConnectionStringBuilder(_sql.GetConnectionString()) { InitialCatalog = "EclipsVault" }.ConnectionString);
        SetEnvironment("ECLIPSVAULT_KEK", Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
        SetEnvironment("ECLIPSVAULT_AUDIT_SIGNING_KEY", Convert.ToBase64String(signingKey.ExportPkcs8PrivateKey()));
        SetEnvironment("DataProtection__KeyRingPath", _keyRing.FullName);
        SetEnvironment("Seed__AdminPassword", _adminPassword);
        SetEnvironment("Database__MigrateOnStartup", "true");
        SetEnvironment("Database__Provider", "SqlServer");
        SetEnvironment("Redis__Enabled", "false");
        // Model a loopback TLS proxy, with distinct test clients behind it. The real throttle and
        // trusted-network rules remain active, and forwarded headers are accepted only from loopback.
        SetEnvironment("ForwardedHeaders__KnownProxies__0", "127.0.0.1");
        SetEnvironment("AllowedHosts", "127.0.0.1");
        _host = StartFreshHost();
    }

    public VaultHost StartFreshHost()
    {
        var factory = new WebApplicationFactory<AccountController>()
            .WithWebHostBuilder(host => host.UseEnvironment(Environments.Production));
        factory.UseKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(_certificate)));
        factory.StartServer();
        var services = factory.Services;
        if (!services.GetRequiredService<IHostApplicationLifetime>().ApplicationStarted.IsCancellationRequested
            || services.GetRequiredService<IHostEnvironment>().EnvironmentName != Environments.Production)
        {
            factory.Dispose();
            throw new InvalidOperationException("The Production vault refused startup; inspect its startup log.");
        }

        var address = services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        return new VaultHost(factory, new Uri(address), _certificate.Thumbprint);
    }

    public VaultSession CreateSession(string source) => _host!.CreateSession(source);

    public async Task<HttpClient> AdminClientAsync()
    {
        if (_admin is null)
        {
            _admin = CreateSession("10.52.0.1");
            await SignInFirstTimeAsync(_admin.Client, "vault-admin", _adminPassword);
        }

        return _admin.Client;
    }

    public async Task<VaultSession> SignInNewAccountAsync(string username, string source)
    {
        var password = "It-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        using var created = await PostFormAsync(await AdminClientAsync(), "/Admin/CreateUser", new()
        {
            ["Username"] = username,
            ["FirstName"] = "Integration",
            ["LastName"] = "Test",
            ["Password"] = password,
            ["Clearance"] = ((int)ClearanceLevel.Standard).ToString(CultureInfo.InvariantCulture),
            ["ProjectKey"] = "GLOBAL",
        });
        Assert.Equal(HttpStatusCode.Redirect, created.StatusCode);
        var session = CreateSession(source);
        await SignInFirstTimeAsync(session.Client, username, password);
        Assert.NotNull(session.Cookies.GetCookies(session.Client.BaseAddress!)["EclipsVault.Session"]);
        return session;
    }

    public async Task DeleteAccountAsync(string username)
    {
        var admin = await AdminClientAsync();
        var users = await admin.GetStringAsync("/Admin/Users");
        var delete = DeleteUserForm().Matches(users)
            .Single(m => WebUtility.HtmlDecode(m.Value).Contains($"Delete user '{username}' permanently?", StringComparison.Ordinal))
            .Groups[1].Value;
        using var response = await PostFormAsync(admin, delete, new(), "/Admin/Users");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }

    private static async Task SignInFirstTimeAsync(HttpClient client, string username, string password)
    {
        using var afterPassword = await PostFormAsync(client, "/Account/Login", new()
        {
            ["Username"] = username,
            ["Password"] = password,
        });
        Assert.Equal("/Account/EnrollTotp", afterPassword.Headers.Location?.OriginalString);
        var enrollment = await client.GetStringAsync("/Account/EnrollTotp");
        var match = EnrollmentSecret().Match(enrollment);
        Assert.True(match.Success, "The real enrollment page must provide a TOTP seed.");
        if (Totp.SecondsLeftInStep() < 5)
        {
            await Task.Delay(TimeSpan.FromSeconds(Totp.SecondsLeftInStep() + 1));
        }

        using var confirmed = await PostFormAsync(client, "/Account/EnrollTotp", new()
        {
            ["Code"] = Totp.Code(match.Groups[1].Value, Totp.CurrentStep()),
        });
        Assert.Equal(HttpStatusCode.Redirect, confirmed.StatusCode);
        Assert.False(confirmed.Headers.Location?.OriginalString.StartsWith("/Account/", StringComparison.OrdinalIgnoreCase) ?? true,
            "Real password and TOTP enrollment must create an interactive session.");
    }

    public static async Task<HttpResponseMessage> PostFormAsync(
        HttpClient client, string path, Dictionary<string, string> fields, string? formPage = null)
    {
        fields["__RequestVerificationToken"] = FormTokenOf(await client.GetStringAsync(formPage ?? path));
        return await client.PostAsync(path, new FormUrlEncodedContent(fields));
    }

    public static string FormTokenOf(string page)
    {
        var token = AntiforgeryField().Match(page);
        Assert.True(token.Success, "The real form must provide an antiforgery token.");
        return WebUtility.HtmlDecode(token.Groups[1].Value);
    }

    private void SetEnvironment(string name, string value)
    {
        _environment.Add(name, Environment.GetEnvironmentVariable(name));
        Environment.SetEnvironmentVariable(name, value);
    }

    public async Task DisposeAsync()
    {
        try
        {
            _admin?.Dispose();
            if (_host is not null)
            {
                await _host.DisposeAsync();
            }
        }
        finally
        {
            try
            {
                await _sql.DisposeAsync();
            }
            finally
            {
                foreach (var (name, previous) in _environment)
                {
                    Environment.SetEnvironmentVariable(name, previous);
                }

                _certificate.Dispose();
                _keyRing.Delete(recursive: true);
            }
        }
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=EclipsVault disposable HTTP test", key, HashAlgorithmName.SHA256);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(2));
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"")]
    private static partial Regex AntiforgeryField();
    [GeneratedRegex("<code class=\"secret-code\">([A-Z2-7=]+)</code>")]
    private static partial Regex EnrollmentSecret();
    [GeneratedRegex("<form\\b[^>]*\\baction=\"(/Admin/DeleteUser/[0-9a-fA-F-]{36})\"[^>]*>")]
    private static partial Regex DeleteUserForm();
}

public sealed class VaultHost(WebApplicationFactory<AccountController> factory, Uri address, string certificateThumbprint) : IAsyncDisposable
{
    public IServiceProvider Services => factory.Services;

    public VaultSession CreateSession(string source, string? copiedCookies = null)
    {
        var cookies = new CookieContainer();
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = copiedCookies is null,
            CookieContainer = cookies,
            // Trust only the fixture's disposable certificate, including on the fresh host.
            ServerCertificateCustomValidationCallback = (_, certificate, _, _) => certificate?.Thumbprint == certificateThumbprint,
        };
        var client = new HttpClient(handler) { BaseAddress = address, Timeout = TimeSpan.FromSeconds(60) };
        client.DefaultRequestHeaders.Add("X-Forwarded-For", source);
        if (copiedCookies is not null)
        {
            client.DefaultRequestHeaders.Add("Cookie", copiedCookies);
        }

        return new VaultSession(client, cookies);
    }

    public ValueTask DisposeAsync() => factory.DisposeAsync();
}

public sealed record VaultSession(HttpClient Client, CookieContainer Cookies) : IDisposable
{
    public string CookieHeader => Cookies.GetCookieHeader(Client.BaseAddress!);
    public void Dispose() => Client.Dispose();
}

[CollectionDefinition(Name)]
public sealed class VaultCollection : ICollectionFixture<VaultFixture>
{
    public const string Name = "vault";
}
