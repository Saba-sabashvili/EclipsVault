using EclipsVault.LicenseForge.Cli;
using EclipsVault.LicenseForge.Rendering;

namespace EclipsVault.LicenseForge.Commands;

/// <summary>
/// Base for the forge's verbs. Carries the resolved <see cref="Pretty"/> mode and the shared
/// <see cref="Fail"/> path so every command reports errors the same way: a themed chip on a terminal,
/// a plain <c>error:</c> line on stderr when output is piped, always with the usage exit code.
/// </summary>
public abstract class Command
{
    protected Command(bool pretty) => Pretty = pretty;

    /// <summary>True when output should be themed; false for scriptable, plain, redirected output.</summary>
    protected bool Pretty { get; }

    /// <summary>Run the verb against the full argument vector; returns a process exit code.</summary>
    public abstract int Execute(string[] args);

    /// <summary>Report a user-fixable error and return <see cref="ExitCodes.Usage"/>.</summary>
    protected int Fail(string message)
    {
        if (Pretty)
            Render.Error(message);
        else
            Console.Error.WriteLine($"error: {message}");
        return ExitCodes.Usage;
    }
}
