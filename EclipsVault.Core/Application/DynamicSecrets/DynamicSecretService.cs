using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;

namespace EclipsVault.Core.Application.DynamicSecrets;

/// <summary>
/// Lease lifecycle for dynamic credentials. Mint, hand over once, destroy on time.
/// </summary>
public sealed class DynamicSecretService : IDynamicSecretService
{
    private const int LeaseListLimit = 50;

    private readonly IDynamicSecretRepository _repository;
    private readonly IReadOnlyDictionary<DynamicSecretBackend, IDynamicSecretBackend> _backends;
    private readonly IAuditContext _actor;
    private readonly TimeProvider _clock;

    public DynamicSecretService(
        IDynamicSecretRepository repository,
        IEnumerable<IDynamicSecretBackend> backends,
        IAuditContext actor,
        TimeProvider clock)
    {
        _repository = repository;
        _backends = backends.ToDictionary(b => b.Backend);
        _actor = actor;
        _clock = clock;
    }

    public async Task<IReadOnlyList<DynamicSecretRoleDto>> ListRolesAsync(CancellationToken ct)
        => (await _repository.ListRolesAsync(ct)).Select(Map).ToList();

    public async Task<DynamicSecretRoleDto?> FindRoleAsync(Guid roleId, CancellationToken ct)
        => await _repository.FindRoleAsync(roleId, ct) is { } role ? Map(role) : null;

    public Task<DynamicSecretLease?> FindLeaseAsync(Guid leaseId, CancellationToken ct)
        => _repository.FindLeaseAsync(leaseId, ct);

    public async Task<IssuedCredentialDto> IssueAsync(Guid roleId, int? ttlMinutes, CancellationToken ct)
    {
        var role = await _repository.FindRoleAsync(roleId, ct)
                   ?? throw new VaultAdminException("That dynamic-secret role no longer exists.");

        if (!role.IsEnabled)
        {
            throw new VaultAdminException($"The role '{role.Name}' is disabled and cannot issue credentials.");
        }

        var backend = ResolveBackend(role);
        var now = _clock.GetUtcNow();
        var expiresAt = now.AddMinutes(ClampTtl(role, ttlMinutes));

        var identity = CredentialMint.NewIdentity(role.Name);
        var password = CredentialMint.NewPassword();

        // Create it for real first: if the backend refuses, nothing was leased and nothing to undo.
        await backend.MintAsync(role, identity, password, expiresAt, ct);

        var lease = new DynamicSecretLease
        {
            Id = Guid.NewGuid(),
            RoleId = role.Id,
            RoleName = role.Name,
            UserId = _actor.UserId ?? Guid.Empty,
            Username = _actor.Username ?? "system",
            CredentialIdentity = identity,
            IssuedAtUtc = now,
            ExpiresAtUtc = expiresAt,
            Status = LeaseStatus.Active
        };

        try
        {
            // The insert carries its own audit row in the same transaction (the interceptor).
            await _repository.AddLeaseAsync(lease, ct);
        }
        catch
        {
            // The credential is live but we failed to record it — and an unrecorded live credential
            // is precisely what a leasing engine must never leave behind, because nothing would ever
            // come back to reap it. Undo the mint before surfacing the failure.
            await TryRevokeQuietlyAsync(backend, role, identity, ct);
            throw;
        }

        return new IssuedCredentialDto(lease.Id, role.Name, identity, password, expiresAt);
    }

    public async Task<IReadOnlyList<LeaseDto>> ListLeasesAsync(Guid userId, bool includeEveryone, CancellationToken ct)
    {
        var leases = includeEveryone
            ? await _repository.ListAllLeasesAsync(LeaseListLimit, ct)
            : await _repository.ListLeasesForUserAsync(userId, LeaseListLimit, ct);

        return leases.Select(Map).ToList();
    }

    public async Task<bool> RevokeAsync(Guid leaseId, Guid userId, bool isAdmin, CancellationToken ct)
    {
        var lease = await _repository.FindLeaseAsync(leaseId, ct);

        // One indistinguishable "no" for unknown / already-closed / someone else's, so a caller
        // cannot use revoke to discover which leases exist.
        if (lease is null || lease.Status != LeaseStatus.Active || (!isAdmin && lease.UserId != userId))
        {
            return false;
        }

        var role = await _repository.FindRoleAsync(lease.RoleId, ct);
        if (role is null)
        {
            // The recipe is gone, so we no longer know how to destroy the credential. Say so loudly
            // rather than closing the lease and pretending it is handled.
            await CloseAsync(lease, LeaseStatus.RevocationFailed,
                "The role that minted this credential no longer exists, so it could not be destroyed automatically.", ct);
            return true;
        }

        await RevokeAtBackendAsync(role, lease, LeaseStatus.Revoked, ct);
        return true;
    }

    public async Task<int> ReapDueLeasesAsync(CancellationToken ct)
    {
        var now = _clock.GetUtcNow();
        var due = await _repository.ListDueLeasesAsync(now, ct);
        var closed = 0;

        foreach (var lease in due)
        {
            var role = await _repository.FindRoleAsync(lease.RoleId, ct);
            if (role is null)
            {
                await CloseAsync(lease, LeaseStatus.RevocationFailed,
                    "The role that minted this credential no longer exists, so it could not be destroyed automatically.", ct);
                closed++;
                continue;
            }

            await RevokeAtBackendAsync(role, lease, LeaseStatus.Expired, ct);
            closed++;
        }

        return closed;
    }

    /// <summary>
    /// Destroys the credential and closes the lease. A backend failure is recorded on the lease as
    /// <see cref="LeaseStatus.RevocationFailed"/> rather than thrown away or retried forever: the
    /// credential may still be live, and that is a fact an operator has to see.
    /// </summary>
    private async Task RevokeAtBackendAsync(
        DynamicSecretRole role, DynamicSecretLease lease, LeaseStatus success, CancellationToken ct)
    {
        try
        {
            await ResolveBackend(role).RevokeAsync(role, lease.CredentialIdentity, ct);
            await CloseAsync(lease, success, null, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            await CloseAsync(lease, LeaseStatus.RevocationFailed, Truncate(ex.Message), ct);
        }
    }

    private async Task CloseAsync(DynamicSecretLease lease, LeaseStatus status, string? error, CancellationToken ct)
    {
        lease.Close(status, _clock.GetUtcNow(), error);
        await _repository.UpdateLeaseAsync(lease, ct);
    }

    private static async Task TryRevokeQuietlyAsync(
        IDynamicSecretBackend backend, DynamicSecretRole role, string identity, CancellationToken ct)
    {
        try
        {
            await backend.RevokeAsync(role, identity, ct);
        }
        catch
        {
            // Best effort: the original failure is the one worth surfacing.
        }
    }

    private IDynamicSecretBackend ResolveBackend(DynamicSecretRole role)
        => _backends.TryGetValue(role.Backend, out var backend)
            ? backend
            : throw new VaultAdminException($"No backend is configured for '{role.Backend}'.");

    /// <summary>A caller may ask for less than the role's ceiling, never more.</summary>
    private static int ClampTtl(DynamicSecretRole role, int? requested)
        => Math.Clamp(requested ?? role.DefaultTtlMinutes, 1, Math.Max(1, role.MaxTtlMinutes));

    private static string Truncate(string value) => value.Length > 500 ? value[..500] : value;

    private static DynamicSecretRoleDto Map(DynamicSecretRole r) => new(
        r.Id, r.Name, r.Description, r.ProjectKey, r.Environment, r.Sensitivity,
        r.Backend, r.DefaultTtlMinutes, r.MaxTtlMinutes, r.IsEnabled);

    private static LeaseDto Map(DynamicSecretLease l) => new(
        l.Id, l.RoleId, l.RoleName, l.CredentialIdentity, l.Username,
        l.IssuedAtUtc, l.ExpiresAtUtc, l.ClosedAtUtc, l.Status, l.RevocationError);
}
