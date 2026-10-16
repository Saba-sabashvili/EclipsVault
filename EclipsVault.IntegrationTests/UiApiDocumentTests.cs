using System.Net;
using Xunit;

namespace EclipsVault.IntegrationTests;

/// <summary>
/// The UI API's OpenAPI document (ADR-0007): it describes the UI API and nothing else, and production
/// does not advertise it. The Angular UI's types are generated from this same document.
/// </summary>
[Collection(VaultCollection.Name)]
public sealed class UiApiDocumentTests(VaultFixture vault)
{
    /// <summary>
    /// Asked for with a session, so the answer cannot be a sign-in redirect standing in for "not here".
    /// The vault under test runs in Production.
    /// </summary>
    [Fact]
    public async Task The_openapi_document_is_not_served_outside_development()
    {
        var admin = await vault.AdminClientAsync();

        var response = await admin.GetAsync("/openapi/ui.json");

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.DoesNotContain("openapi", await response.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
    }
}
