using Microsoft.AspNetCore.OpenApi;
using Microsoft.OpenApi;

namespace EclipsVault.Web.Hosting;

/// <summary>
/// Generates the UI API contract from MVC metadata, without invoking the vault's entry point.
/// Only framework discovery services are registered: no Infrastructure, vault workers, configuration
/// files, database or keys. Development and the build tool use this same document.
/// </summary>
public static class UiApiOpenApi
{
    public static async Task<string> GenerateAsync(CancellationToken cancellationToken = default)
    {
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions
        {
            ApplicationName = typeof(UiApiOpenApi).Assembly.GetName().Name,
            EnvironmentName = Environments.Production,
        });
        builder.WebHost.UseKestrel();
        builder.Services.AddControllers()
            .AddApplicationPart(typeof(UiApiOpenApi).Assembly);
        builder.Services.AddOpenApi("ui", options => options.ShouldInclude = description =>
            description.RelativePath?.StartsWith("api/ui/", StringComparison.OrdinalIgnoreCase) == true);

        // Building provides MVC's action descriptions. Never Start/Run this metadata-only host.
        await using var app = builder.Build();
        app.MapControllers();
        var provider = app.Services.GetRequiredKeyedService<IOpenApiDocumentProvider>("ui");
        var document = await provider.GetOpenApiDocumentAsync(cancellationToken);
        var json = await document.SerializeAsJsonAsync(OpenApiSpecVersion.OpenApi3_1, cancellationToken);
        return json.ReplaceLineEndings("\n") + "\n";
    }
}
