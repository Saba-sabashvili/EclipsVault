using System.Net;
using System.Net.Http.Json;
using Xunit;

namespace EclipsVault.IntegrationTests;

[Collection(VaultCollection.Name)]
public sealed class AreaVisibilityTests(VaultFixture vault)
{
    [Fact]
    public async Task An_administrator_is_offered_every_area()
    {
        var response = await (await vault.AdminClientAsync()).GetAsync("/api/ui/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var me = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.Equal([
            "overview", "secrets", "dynamic-secrets", "shared-with-me", "shared-by-me",
            "access", "access-requests", "security", "sign-ins", "sessions", "activity", "data", "profile",
            "users", "networks", "service-accounts", "audit", "notifications", "encryption", "license",
        ], me.GetProperty("areas").EnumerateArray().Select(area => area.GetString()!).ToArray());
    }

    [Fact]
    public async Task A_standard_account_is_offered_only_session_areas_and_cannot_open_administration()
    {
        var session = await vault.SignInNewAccountAsync("it-standard-areas");
        var response = await session.Client.GetAsync("/api/ui/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var me = await response.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
        Assert.Equal([
            "overview", "secrets", "dynamic-secrets", "shared-with-me", "shared-by-me",
            "access", "access-requests", "security", "sign-ins", "sessions", "activity", "data", "profile",
        ], me.GetProperty("areas").EnumerateArray().Select(area => area.GetString()!).ToArray());

        foreach (var path in new[] { "/Admin/Users", "/Admin/Networks", "/ServiceAccounts", "/Audit", "/Notifications", "/Encryption", "/License" })
        {
            var refused = await session.Client.GetAsync(path);
            Assert.Equal(HttpStatusCode.Redirect, refused.StatusCode);
            Assert.Equal("/Account/Denied", refused.Headers.Location?.AbsolutePath);
        }
    }
}
