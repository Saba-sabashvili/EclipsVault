using System.Net;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.Users;
using EclipsVault.Infrastructure.Security;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using Xunit.Abstractions;

namespace EclipsVault.IntegrationTests;

[Collection(VaultCollection.Name)]
public sealed partial class AccountDeletionTests(VaultFixture vault, ITestOutputHelper output)
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Deleted_account_cannot_reveal_with_retained_or_copied_cookie(bool freshHost)
    {
        var suffix = freshHost ? "fresh" : "immediate";
        var username = "it-deleted-" + suffix;
        var value = "it-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var details = await CreateSecretAsync("it-delete-secret-" + suffix, value);
        using var deleted = await vault.SignInNewAccountAsync(username, freshHost ? "10.52.0.70" : "10.52.0.71");
        var token = VaultFixture.FormTokenOf(await deleted.Client.GetStringAsync(details));

        using var noToken = await RevealAsync(deleted.Client, details, "");
        Assert.Equal(HttpStatusCode.BadRequest, noToken.StatusCode);
        await AssertRevealedAsync(deleted.Client, details, token, value);
        output.WriteLine("Before deletion: real password/MFA session revealed the disposable secret; missing antiforgery token returned 400.");

        // Capture every cookie (including antiforgery) and the open form token before any rejection
        // clears the original browser. Do not print them or plaintext, even on assertion failures.
        var copiedCookies = deleted.CookieHeader;
        using var surviving = await vault.SignInNewAccountAsync("it-surviving-" + suffix, freshHost ? "10.52.0.72" : "10.52.0.73");
        var survivingToken = VaultFixture.FormTokenOf(await surviving.Client.GetStringAsync(details));
        await vault.DeleteAccountAsync(username);
        using (var scope = vault.Services.CreateScope())
        {
            Assert.Null(await scope.ServiceProvider.GetRequiredService<IUserRepository>().FindByUsernameAsync(username, default));
        }

        if (freshHost)
        {
            await using var restarted = vault.StartFreshHost();
            Assert.IsType<InMemorySessionRevocationService>(restarted.Services.GetRequiredService<ISessionRevocationService>());
            Assert.NotSame(vault.Services.GetRequiredService<ISessionRevocationService>(), restarted.Services.GetRequiredService<ISessionRevocationService>());
            Assert.NotSame(vault.Services.GetRequiredService<ISessionRegistry>(), restarted.Services.GetRequiredService<ISessionRegistry>());
            using var control = restarted.CreateSession("10.52.0.72", surviving.CookieHeader);
            await AssertRevealedAsync(control.Client, details, survivingToken, value);
            output.WriteLine("Fresh Production HTTPS host: surviving account's retained cookie and antiforgery token revealed the same secret; revocation singletons are fresh.");
            using var replay = restarted.CreateSession("10.52.0.70", copiedCookies);
            using var response = await RevealAsync(replay.Client, details, token);
            await AssertRefusedAsync(response, value, "fresh-host copied cookie");
        }
        else
        {
            using var replay = vault.CreateSession("10.52.0.71");
            replay.Client.DefaultRequestHeaders.Add("Cookie", copiedCookies);
            using var original = await RevealAsync(deleted.Client, details, token);
            using var copied = await RevealAsync(replay.Client, details, token);
            // Record both statuses before asserting, so a red baseline proves both replay paths.
            output.WriteLine($"Immediate replay: original={(int)original.StatusCode}, copied={(int)copied.StatusCode}.");
            output.WriteLine($"Copied-cookie plaintextReturned={(await copied.Content.ReadAsStringAsync()).Contains(value, StringComparison.Ordinal)}.");
            await AssertRefusedAsync(original, value, "original browser");
            await AssertRefusedAsync(copied, value, "copied cookie");
            Assert.Null(deleted.Cookies.GetCookies(deleted.Client.BaseAddress!)["EclipsVault.Session"]);
        }
    }

    [Fact]
    public async Task Disabled_account_cookie_is_also_refused_by_a_fresh_host()
    {
        var value = "it-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
        var details = await CreateSecretAsync("it-disabled-secret", value);
        using var disabled = await vault.SignInNewAccountAsync("it-disabled-fresh", "10.52.0.75");
        var token = VaultFixture.FormTokenOf(await disabled.Client.GetStringAsync(details));
        await AssertRevealedAsync(disabled.Client, details, token, value);
        var copiedCookies = disabled.CookieHeader;
        Guid userId;
        using (var scope = vault.Services.CreateScope())
        {
            userId = (await scope.ServiceProvider.GetRequiredService<IUserRepository>()
                .FindByUsernameAsync("it-disabled-fresh", default))!.Id;
        }

        using var changed = await VaultFixture.PostFormAsync(await vault.AdminClientAsync(), $"/Admin/SetEnabled/{userId}",
            new() { ["enabled"] = "false" }, "/Admin/Users");
        Assert.Equal(HttpStatusCode.Redirect, changed.StatusCode);
        await using var restarted = vault.StartFreshHost();
        using var replay = restarted.CreateSession("10.52.0.75", copiedCookies);
        using var response = await RevealAsync(replay.Client, details, token);
        await AssertRefusedAsync(response, value, "fresh-host disabled account");
    }

    private async Task<string> CreateSecretAsync(string name, string value)
    {
        using var created = await VaultFixture.PostFormAsync(await vault.AdminClientAsync(), "/Secrets/Create", new()
        {
            ["Name"] = name,
            ["Value"] = value,
            ["ProjectKey"] = "GLOBAL",
            ["Environment"] = "Development",
            ["Sensitivity"] = "Internal",
        });
        Assert.Equal(HttpStatusCode.Redirect, created.StatusCode);
        var details = created.Headers.Location?.OriginalString;
        Assert.StartsWith("/Secrets/Details/", details);
        return details!;
    }

    private static Task<HttpResponseMessage> RevealAsync(HttpClient client, string details, string token)
        => client.PostAsync(details.Replace("/Details/", "/Reveal/", StringComparison.Ordinal),
            new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token }));

    private static async Task AssertRevealedAsync(HttpClient client, string details, string token, string value)
    {
        using var response = await RevealAsync(client, details, token);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(RevealedValue().Match(await response.Content.ReadAsStringAsync()).Groups[1].Value == value,
            "The legitimate account must receive the disposable secret's exact plaintext.");
    }

    private async Task AssertRefusedAsync(HttpResponseMessage response, string value, string scenario)
    {
        var body = await response.Content.ReadAsStringAsync();
        var disclosed = body.Contains(value, StringComparison.Ordinal);
        output.WriteLine($"{scenario}: status={(int)response.StatusCode}, plaintextReturned={disclosed}.");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/Account/Login", response.Headers.Location?.AbsolutePath);
        Assert.False(disclosed, "A deleted account must never receive plaintext.");
    }

    [GeneratedRegex("<code class=\"secret-code\" id=\"revealed-value\">([^<]+)</code>")]
    private static partial Regex RevealedValue();
}
