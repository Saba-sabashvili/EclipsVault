using EclipsVault.Core.Application.Auditing;
using Xunit;

namespace EclipsVault.Tests.Architecture;

/// <summary>
/// The dependency rule, asserted rather than asserted-about.
///
/// <para>
/// Layering is the kind of property that is true on the day it is written and quietly false a year
/// later, because nothing fails when someone adds one convenient <c>using</c>. Each violation is
/// individually harmless — it is always just one config object, just one entity — which is exactly
/// why the erosion is invisible without a test. These are cheap and they fail loudly, naming the
/// offending file.
/// </para>
/// </summary>
public class LayeringTests
{
    /// <summary>Walks up from the test binaries to the directory holding the solution file.</summary>
    private static DirectoryInfo RepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "EclipsVault.slnx")))
        {
            dir = dir.Parent;
        }

        Assert.True(dir is not null, "Could not locate EclipsVault.slnx above the test output directory.");
        return dir!;
    }

    private static List<string> SourceFiles(string projectRelativePath)
    {
        var root = Path.Combine(RepoRoot().FullName, projectRelativePath);
        var sep = Path.DirectorySeparatorChar;
        return [.. Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
            .Where(p => !p.Contains($"{sep}obj{sep}", StringComparison.Ordinal)
                     && !p.Contains($"{sep}bin{sep}", StringComparison.Ordinal))];
    }

    private static List<string> FilesContaining(string projectRelativePath, string needle, params string[] allowed)
        => [.. SourceFiles(projectRelativePath)
            .Where(f => File.ReadAllText(f).Contains(needle, StringComparison.Ordinal))
            .Select(f => Path.GetFileName(f))
            .Where(name => !allowed.Contains(name, StringComparer.Ordinal))
            .Order(StringComparer.Ordinal)];

    /// <summary>
    /// The innermost ring depends on nothing but the framework itself — no ORM, no logger, no DI
    /// container, no third-party package at all. This is what lets the offline audit verifier and the
    /// licence tool reuse Core's logic as plain console apps, and what keeps a persistence or hosting
    /// decision from reaching into the rules it is supposed to serve.
    ///
    /// <para>
    /// Known limit, stated so this is not over-trusted: the compiler emits a metadata reference only
    /// for assemblies whose types are actually used, so adding a <c>PackageReference</c> and not
    /// touching it passes here. That is the tolerable half of the gap — the test fires on first use,
    /// which is the moment the dependency becomes real. Verified by mutation, both ways round.
    /// </para>
    /// </summary>
    [Fact]
    public void Core_depends_on_nothing_but_the_base_class_library()
    {
        var nonBcl = typeof(AuditRowHasher).Assembly
            .GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .Where(n => !n.StartsWith("System", StringComparison.Ordinal)
                        && !string.Equals(n, "netstandard", StringComparison.Ordinal)
                        && !string.Equals(n, "mscorlib", StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToList();

        Assert.True(
            nonBcl.Count == 0,
            "EclipsVault.Core must reference no package or project. It now references: " + string.Join(", ", nonBcl));
    }

    /// <summary>Entities and value objects must not know about the services that orchestrate them.</summary>
    [Fact]
    public void The_domain_does_not_reach_out_into_the_application_layer()
    {
        var offenders = FilesContaining("EclipsVault.Core/Domain", "EclipsVault.Core.Application");

        Assert.True(
            offenders.Count == 0,
            "Domain must not depend on Application. Offending files: " + string.Join(", ", offenders));
    }

    /// <summary>
    /// Only the composition root may name a concrete adapter. Everywhere else the web layer talks to
    /// ports defined in Core, so swapping an implementation stays a one-file change — and so a
    /// controller cannot end up holding a configuration object that carries a client secret just to
    /// read a display name off it.
    /// </summary>
    [Fact]
    public void Only_the_composition_root_may_reference_infrastructure_from_the_web_layer()
    {
        var offenders = FilesContaining("EclipsVault.Web", "using EclipsVault.Infrastructure", allowed: "Program.cs");

        Assert.True(
            offenders.Count == 0,
            "Web may only touch Infrastructure in Program.cs. Offending files: " + string.Join(", ", offenders));
    }

    /// <summary>
    /// The web layer speaks in DTOs, never persisted entities — which is why controllers pass
    /// resource types as string literals rather than importing <c>Domain.Entities</c>. An entity that
    /// reaches a view is an entity a view can be tempted to mutate.
    /// </summary>
    [Fact]
    public void The_web_layer_does_not_bind_to_domain_entities()
    {
        var offenders = FilesContaining("EclipsVault.Web", "EclipsVault.Core.Domain.Entities");

        Assert.True(
            offenders.Count == 0,
            "Web must use DTOs, not entities. Offending files: " + string.Join(", ", offenders));
    }
}
