namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Identity of the actor behind the current unit of work. In a web request this is
/// populated from the authenticated principal; background workers surface as the
/// "system" actor.
/// </summary>
public interface IAuditContext
{
    Guid? UserId { get; }

    string? Username { get; }

    string? SourceIp { get; }
}
