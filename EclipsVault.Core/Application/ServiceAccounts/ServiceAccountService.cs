using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;

namespace EclipsVault.Core.Application.ServiceAccounts;

/// <summary>
/// Administrative service-account lifecycle and API-key issuance. Also implements
/// <see cref="IApiKeyAuthenticator"/> so the API layer can resolve a presented key
/// without a second service. Every mutation is audited.
/// </summary>
public sealed class ServiceAccountService : IServiceAccountService, IApiKeyAuthenticator
{
    private const string ApiKeyPrefix = "evk_";

    /// <summary>Minimum gap between persisted "last used" updates for a key (write-amplification damper).</summary>
    private static readonly TimeSpan LastUsedWriteInterval = TimeSpan.FromMinutes(1);

    private readonly IServiceAccountRepository _repository;
    private readonly IApiKeyFactory _keys;
    private readonly IAuditSink _audit;
    private readonly TimeProvider _clock;

    public ServiceAccountService(IServiceAccountRepository repository, IApiKeyFactory keys, IAuditSink audit, TimeProvider clock)
    {
        _repository = repository;
        _keys = keys;
        _audit = audit;
        _clock = clock;
    }

    private Task AuditAsync(AuditAction action, Guid id, string name, string? details, CancellationToken ct)
        => _audit.WriteAsync(new AuditEntry { Action = action, ResourceType = nameof(ServiceAccount), ResourceId = id, ResourceName = name, Details = details }, ct);

    public async Task<IReadOnlyList<ServiceAccountSummaryDto>> ListAsync(CancellationToken ct)
    {
        var now = _clock.GetUtcNow();
        var accounts = await _repository.ListAsync(ct);
        var summaries = new List<ServiceAccountSummaryDto>(accounts.Count);
        foreach (var a in accounts)
        {
            var active = await _repository.CountActiveKeysAsync(a.Id, now, ct);
            summaries.Add(new ServiceAccountSummaryDto(a.Id, a.Name, a.Clearance, a.ProjectKey, a.IsDisabled, active, a.CreatedAtUtc));
        }

        return summaries;
    }

    public async Task<ServiceAccountDetailsDto?> GetAsync(Guid id, CancellationToken ct)
    {
        var account = await _repository.FindAsync(id, ct);
        if (account is null)
        {
            return null;
        }

        var keys = await _repository.ListKeysAsync(id, ct);
        var keyDtos = keys
            .Select(k => new ApiKeyDto(k.Id, k.Prefix, k.CreatedAtUtc, k.ExpiresAtUtc, k.RevokedAtUtc, k.LastUsedAtUtc,
                k.ClearanceCeiling, k.ProjectScope, k.MetadataOnly))
            .ToList();

        return new ServiceAccountDetailsDto(account.Id, account.Name, account.Clearance, account.ProjectKey,
            account.IsDisabled, account.CreatedAtUtc, keyDtos);
    }

    public async Task<Guid> CreateAsync(CreateServiceAccountRequest request, CancellationToken ct)
    {
        var name = request.Name.Trim();
        if (name.Length < 3)
        {
            throw new VaultAdminException("Service account names must be at least 3 characters long.");
        }

        if (await _repository.ExistsByNameAsync(name, ct))
        {
            throw new VaultAdminException($"A service account named '{name}' already exists.");
        }

        var account = new ServiceAccount
        {
            Id = Guid.NewGuid(),
            Name = name,
            Clearance = request.Clearance,
            ProjectKey = request.ProjectKey.Trim().ToUpperInvariant(),
            CreatedAtUtc = _clock.GetUtcNow()
        };

        await _repository.AddAsync(account, ct);
        await AuditAsync(AuditAction.ServiceAccountCreated, account.Id, account.Name,
            $"Created (clearance {account.Clearance}, project {account.ProjectKey})", ct);
        return account.Id;
    }

    public async Task<bool> SetEnabledAsync(Guid id, bool enabled, CancellationToken ct)
    {
        var account = await _repository.FindAsync(id, ct);
        if (account is null)
        {
            return false;
        }

        if (account.IsDisabled == !enabled)
        {
            return true;
        }

        account.IsDisabled = !enabled;
        await _repository.UpdateAsync(account, ct);
        await AuditAsync(
            enabled ? AuditAction.ServiceAccountEnabled : AuditAction.ServiceAccountDisabled,
            account.Id, account.Name, null, ct);
        return true;
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct)
    {
        var account = await _repository.FindAsync(id, ct);
        if (account is null)
        {
            return false;
        }

        await _repository.DeleteAsync(account, ct); // keys cascade-delete
        await AuditAsync(AuditAction.ServiceAccountDeleted, account.Id, account.Name, null, ct);
        return true;
    }

    public async Task<IssuedApiKeyDto?> IssueKeyAsync(Guid serviceAccountId, IssueApiKeyRequest request, CancellationToken ct)
    {
        var account = await _repository.FindAsync(serviceAccountId, ct);
        if (account is null)
        {
            return null;
        }

        // A ceiling only counts when it is actually below the account (never a widening).
        var ceiling = request.ClearanceCeiling is { } c && (int)c < (int)account.Clearance ? c : (ClearanceLevel?)null;
        var projectScope = string.IsNullOrWhiteSpace(request.ProjectScope)
            ? null
            : request.ProjectScope.Trim().ToUpperInvariant();

        var generated = _keys.Generate();
        var now = _clock.GetUtcNow();
        var key = new ApiKey
        {
            Id = Guid.NewGuid(),
            ServiceAccountId = serviceAccountId,
            KeyHash = generated.Hash,
            Prefix = generated.Prefix,
            CreatedAtUtc = now,
            ExpiresAtUtc = request.TtlDays is > 0 ? now.AddDays(request.TtlDays.Value) : null,
            ClearanceCeiling = ceiling,
            ProjectScope = projectScope,
            MetadataOnly = request.MetadataOnly
        };

        await _repository.AddKeyAsync(key, ct);
        await AuditAsync(AuditAction.ApiKeyIssued, account.Id, account.Name,
            $"Key {key.Prefix}… issued" + DescribeScope(key) + (key.ExpiresAtUtc is { } e ? $", expires {e:u}" : ""), ct);

        return new IssuedApiKeyDto(key.Id, generated.RawToken, generated.Prefix);
    }

    private static string DescribeScope(ApiKey key)
    {
        var parts = new List<string>();
        if (key.ClearanceCeiling is { } ceiling)
        {
            parts.Add($"clearance ≤ {ceiling}");
        }
        if (!string.IsNullOrEmpty(key.ProjectScope))
        {
            parts.Add($"project {key.ProjectScope}");
        }
        if (key.MetadataOnly)
        {
            parts.Add("metadata-only");
        }

        return parts.Count == 0 ? " (unscoped)" : $" scoped to {string.Join(", ", parts)}";
    }

    public async Task<bool> RevokeKeyAsync(Guid keyId, CancellationToken ct)
    {
        var key = await _repository.FindKeyAsync(keyId, ct);
        if (key is null)
        {
            return false;
        }

        if (key.RevokedAtUtc is not null)
        {
            return true;
        }

        key.RevokedAtUtc = _clock.GetUtcNow();
        await _repository.UpdateKeyAsync(key, ct);

        var account = await _repository.FindAsync(key.ServiceAccountId, ct);
        await AuditAsync(AuditAction.ApiKeyRevoked, key.ServiceAccountId, account?.Name ?? "service account",
            $"Key {key.Prefix}… revoked", ct);
        return true;
    }

    public async Task<AuthenticatedServiceAccount?> AuthenticateAsync(string presentedToken, CancellationToken ct)
    {
        presentedToken = presentedToken.Trim();
        if (!presentedToken.StartsWith(ApiKeyPrefix, StringComparison.Ordinal))
        {
            return null;
        }

        var key = await _repository.FindKeyByHashAsync(_keys.Hash(presentedToken), ct);
        var now = _clock.GetUtcNow();
        if (key?.ServiceAccount is null || !key.IsActive(now) || key.ServiceAccount.IsDisabled)
        {
            return null;
        }

        // Throttle the last-used stamp so a read-heavy API caller doesn't incur a DB write on
        // every request — coarse "last used" telemetry doesn't need per-call precision.
        if (key.LastUsedAtUtc is null || now - key.LastUsedAtUtc >= LastUsedWriteInterval)
        {
            key.LastUsedAtUtc = now;
            await _repository.UpdateKeyAsync(key, ct);
        }

        var account = key.ServiceAccount;
        return new AuthenticatedServiceAccount(
            account.Id,
            account.Name,
            key.EffectiveClearance(account.Clearance),
            account.ProjectKey,
            key.ProjectScope,
            key.MetadataOnly);
    }
}
