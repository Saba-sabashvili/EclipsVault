using System.Text.Json;
using EclipsVault.Web.Controllers;
using EclipsVault.Web.Hosting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace EclipsVault.Tests.Web;

public sealed class UiApiDocumentGenerationTests
{
    [Theory]
    [InlineData("Development")]
    [InlineData("Production")]
    [InlineData("Staging")]
    public async Task The_document_is_returned_only_in_development(string environment)
    {
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions { EnvironmentName = environment });
        var controller = new UiApiDocumentController(builder.Environment);

        var response = await controller.Get(CancellationToken.None);

        if (environment != "Development")
        {
            Assert.IsType<NotFoundResult>(response);
            return;
        }

        var content = Assert.IsType<ContentResult>(response);
        Assert.Equal("application/json", content.ContentType);
        using var document = JsonDocument.Parse(content.Content!);
        Assert.True(document.RootElement.GetProperty("paths").TryGetProperty("/api/ui/me", out _));
    }

    [Fact]
    public async Task Document_generation_needs_only_controller_metadata_and_describes_only_the_ui_api()
    {
        using var document = JsonDocument.Parse(await UiApiOpenApi.GenerateAsync());

        Assert.StartsWith("3.", document.RootElement.GetProperty("openapi").GetString());
        var paths = document.RootElement.GetProperty("paths");
        Assert.True(paths.TryGetProperty("/api/ui/me", out var me));
        Assert.All(paths.EnumerateObject(), path => Assert.StartsWith("/api/ui/", path.Name));
        var response = me.GetProperty("get").GetProperty("responses").GetProperty("200")
            .GetProperty("content").GetProperty("application/json").GetProperty("schema");
        Assert.Equal("#/components/schemas/MeResponse", response.GetProperty("$ref").GetString());
        var properties = document.RootElement.GetProperty("components").GetProperty("schemas")
            .GetProperty("MeResponse").GetProperty("properties");
        Assert.Equal(["clearance", "displayName", "project", "username"],
            properties.EnumerateObject().Select(property => property.Name).Order().ToArray());
    }
}
