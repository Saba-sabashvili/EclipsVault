using EclipsVault.Web.Hosting;

if (args is not [var output])
{
    Console.Error.WriteLine("Usage: EclipsVault.UiApiDocument <output.json>");
    return 2;
}

var path = Path.GetFullPath(output);
Directory.CreateDirectory(Path.GetDirectoryName(path)!);
await File.WriteAllTextAsync(path, await UiApiOpenApi.GenerateAsync());
Console.WriteLine($"Wrote the UI API's OpenAPI document to {path}");
return 0;
