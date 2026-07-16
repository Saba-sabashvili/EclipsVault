namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// How this process is allowed to treat the schema.
/// </summary>
public sealed class DatabaseOptions
{
    public const string SectionName = "Database";

    /// <summary>
    /// Lets the running service apply migrations itself. Development does this regardless; anywhere
    /// else it is off, because a service that migrates on boot is a service holding rights to drop
    /// and rewrite every table for the whole time it is serving requests — permissions it uses for
    /// a few seconds and an attacker who reaches the connection string has for months.
    ///
    /// Turn it on for a single-node self-hosted install where there is no deploy pipeline to put the
    /// migration in, and accept that the trade is real: the app's login then needs DDL rights.
    /// </summary>
    public bool MigrateOnStartup { get; set; }
}
