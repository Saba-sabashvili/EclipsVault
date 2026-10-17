using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace EclipsVault.IntegrationTests;

/// <summary>
/// What the Angular account menu shows comes from <c>/api/ui/me</c> (ADR-0012): the avatar address,
/// and for whoever can act on it the licence notice the Legacy UI's banner shows.
/// </summary>
[Collection(VaultCollection.Name)]
public sealed class AccountMenuTests(VaultFixture vault)
{
    [Fact]
    public async Task An_administrator_of_an_unlicensed_vault_is_given_the_licence_notice()
    {
        var me = await (await vault.AdminClientAsync()).GetFromJsonAsync<JsonElement>("/api/ui/me");

        var notice = me.GetProperty("licenseNotice");
        Assert.Equal("Running unlicensed.", notice.GetProperty("title").GetString());
        Assert.EndsWith(
            "This changes nothing about how the vault runs — it only affects this notice.",
            notice.GetProperty("text").GetString());
    }

    [Fact]
    public async Task The_avatar_address_is_the_existing_avatar_endpoint()
    {
        var admin = await vault.AdminClientAsync();
        var me = await admin.GetFromJsonAsync<JsonElement>("/api/ui/me");

        var avatarUrl = me.GetProperty("avatarUrl").GetString()!;
        Assert.StartsWith("/Profile/Avatar?v=", avatarUrl, StringComparison.Ordinal);
        var avatar = await admin.GetAsync(avatarUrl);
        Assert.Equal(HttpStatusCode.OK, avatar.StatusCode);
        Assert.StartsWith("image/", avatar.Content.Headers.ContentType?.MediaType, StringComparison.Ordinal);
    }
}
