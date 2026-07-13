namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Executes the active-defence playbook when a honey-token is requested:
/// revoke the caller's authentication state, blacklist the source IP range,
/// raise a critical structured alert, and persist a high-priority audit row.
/// </summary>
public interface IIntrusionResponseService
{
    Task TriggerHoneyTokenAsync(Guid secretId, string secretName, CancellationToken ct);
}
