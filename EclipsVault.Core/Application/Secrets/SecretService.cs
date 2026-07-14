using System.Security.Cryptography;
using System.Text;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;

namespace EclipsVault.Core.Application.Secrets;

/// <summary>
/// Secret lifecycle orchestration: cache-aside reads of encrypted envelopes,
/// honey-token trap wire, fail-closed audit ordering, envelope encryption via the
/// engine factory, and eager cache eviction on every mutation.
/// </summary>
public sealed class SecretService : ISecretService
{
    private readonly ISecretRepository _repository;
    private readonly ICryptoEngineFactory _cryptoFactory;
    private readonly ISecretCache _cache;
    private readonly IIntrusionResponseService _intrusion;
    private readonly IAuditSink _audit;
    private readonly IAuditContext _actor;
    private readonly TimeProvider _clock;

    public SecretService(
        ISecretRepository repository,
        ICryptoEngineFactory cryptoFactory,
        ISecretCache cache,
        IIntrusionResponseService intrusion,
        IAuditSink audit,
        IAuditContext actor,
        TimeProvider clock)
    {
        _repository = repository;
        _cryptoFactory = cryptoFactory;
        _cache = cache;
        _intrusion = intrusion;
        _audit = audit;
        _actor = actor;
        _clock = clock;
    }

    private Task AuditSecretAsync(Guid id, string name, AuditAction action, CancellationToken ct)
        => _audit.WriteAsync(new AuditEntry { Action = action, ResourceType = nameof(Secret), ResourceId = id, ResourceName = name }, ct);

    public async Task<IReadOnlyList<SecretSummaryDto>> ListAsync(CancellationToken ct)
    {
        var secrets = await _repository.ListActiveAsync(_clock.GetUtcNow(), ct);
        return secrets
            .Select(s => new SecretSummaryDto(s.Id, s.Name, s.ProjectKey, s.Environment, s.Sensitivity, s.CreatedAtUtc, s.ExpiresAtUtc, s.IsHoneyToken))
            .ToList();
    }

    public async Task<SecretDetailsDto> GetDetailsAsync(Guid id, CancellationToken ct)
    {
        var envelope = await GetEnvelopeAsync(id, ct);
        await TripHoneyTokenIfNeededAsync(envelope, ct);
        await AuditSecretAsync(envelope.Id, envelope.Name, AuditAction.SecretMetadataViewed, ct);

        return new SecretDetailsDto(
            envelope.Id, envelope.Name, envelope.ProjectKey, envelope.Environment, envelope.Sensitivity,
            envelope.Algorithm, envelope.CreatedAtUtc, envelope.UpdatedAtUtc, envelope.ExpiresAtUtc);
    }

    public async Task<RevealedSecretDto> RevealAsync(Guid id, CancellationToken ct)
    {
        var envelope = await GetEnvelopeAsync(id, ct);
        await TripHoneyTokenIfNeededAsync(envelope, ct);

        // Fail-closed ordering: the audit row is committed BEFORE any decryption.
        // If it cannot be written, no plaintext ever exists for this request.
        await AuditSecretAsync(envelope.Id, envelope.Name, AuditAction.SecretRevealed, ct);

        var engine = _cryptoFactory.Create();
        var plaintext = engine.Unseal(new SealedSecret(envelope.Ciphertext, envelope.WrappedDek, envelope.KekId, envelope.Algorithm));
        try
        {
            return new RevealedSecretDto(envelope.Id, envelope.Name, Encoding.UTF8.GetString(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async Task<Guid> CreateAsync(CreateSecretRequest request, CancellationToken ct)
    {
        var sealedSecret = SealValue(request.Value);
        var now = _clock.GetUtcNow();

        var secret = new Secret
        {
            Id = Guid.NewGuid(),
            Name = request.Name.Trim(),
            ProjectKey = request.ProjectKey.Trim().ToUpperInvariant(),
            Environment = request.Environment,
            Sensitivity = request.Sensitivity,
            Ciphertext = sealedSecret.Ciphertext,
            WrappedDek = sealedSecret.WrappedDek,
            KekId = sealedSecret.KekId,
            Algorithm = sealedSecret.Algorithm,
            CreatedAtUtc = now,
            ExpiresAtUtc = request.TtlDays > 0 ? now.AddDays(request.TtlDays) : null,
            CreatedByUserId = _actor.UserId ?? Guid.Empty
        };

        await _repository.AddAsync(secret, ct);
        await _cache.EvictAsync(secret.Id, ct);
        return secret.Id;
    }

    public async Task RotateAsync(Guid id, string newValue, string? changeNote, CancellationToken ct)
    {
        var envelope = await GetEnvelopeAsync(id, ct);
        await TripHoneyTokenIfNeededAsync(envelope, ct);

        var entity = await _repository.FindAsync(id, ct) ?? throw new SecretNotFoundException(id);
        var archived = await ArchiveCurrentAsync(entity, changeNote, ct);

        var sealedSecret = SealValue(newValue);
        entity.Ciphertext = sealedSecret.Ciphertext;
        entity.WrappedDek = sealedSecret.WrappedDek;
        entity.KekId = sealedSecret.KekId;
        entity.Algorithm = sealedSecret.Algorithm;
        entity.UpdatedAtUtc = _clock.GetUtcNow();

        // One transaction: the interceptor writes a SecretUpdated audit row atomically.
        await _repository.RotateAsync(entity, archived, ct);
        await _cache.EvictAsync(id, ct);
    }

    public async Task<IReadOnlyList<SecretVersionDto>> ListVersionsAsync(Guid id, CancellationToken ct)
    {
        var versions = await _repository.ListVersionsAsync(id, ct);
        return versions
            .Select(v => new SecretVersionDto(v.Id, v.VersionNumber, v.ArchivedAtUtc, v.ArchivedBy, v.ChangeNote))
            .ToList();
    }

    public async Task<RevealedSecretDto> RevealVersionAsync(Guid id, Guid versionId, CancellationToken ct)
    {
        var envelope = await GetEnvelopeAsync(id, ct);
        await TripHoneyTokenIfNeededAsync(envelope, ct);

        var version = await _repository.FindVersionAsync(id, versionId, ct)
                      ?? throw new SecretNotFoundException(versionId);

        // Fail-closed: audit committed before any decryption.
        await AuditSecretAsync(id, envelope.Name, AuditAction.SecretVersionRevealed, ct);

        var engine = _cryptoFactory.Create();
        var plaintext = engine.Unseal(new SealedSecret(version.Ciphertext, version.WrappedDek, version.KekId, version.Algorithm));
        try
        {
            return new RevealedSecretDto(id, envelope.Name, Encoding.UTF8.GetString(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    public async Task RestoreVersionAsync(Guid id, Guid versionId, CancellationToken ct)
    {
        var envelope = await GetEnvelopeAsync(id, ct);
        await TripHoneyTokenIfNeededAsync(envelope, ct);

        var entity = await _repository.FindAsync(id, ct) ?? throw new SecretNotFoundException(id);
        var version = await _repository.FindVersionAsync(id, versionId, ct)
                      ?? throw new SecretNotFoundException(versionId);

        var archived = await ArchiveCurrentAsync(entity, $"Superseded by restore of version {version.VersionNumber}", ct);

        // Copy the chosen version's envelope back onto the live secret (no re-encryption needed).
        entity.Ciphertext = version.Ciphertext;
        entity.WrappedDek = version.WrappedDek;
        entity.KekId = version.KekId;
        entity.Algorithm = version.Algorithm;
        entity.UpdatedAtUtc = _clock.GetUtcNow();

        await _repository.RotateAsync(entity, archived, ct);
        await AuditSecretAsync(id, envelope.Name, AuditAction.SecretVersionRestored, ct);
        await _cache.EvictAsync(id, ct);
    }

    /// <summary>Builds a version snapshot of the secret's CURRENT (about-to-be-replaced) value.</summary>
    private async Task<SecretVersion> ArchiveCurrentAsync(Secret entity, string? changeNote, CancellationToken ct)
        => new()
        {
            Id = Guid.NewGuid(),
            SecretId = entity.Id,
            VersionNumber = await _repository.CountVersionsAsync(entity.Id, ct) + 1,
            Ciphertext = entity.Ciphertext,
            WrappedDek = entity.WrappedDek,
            KekId = entity.KekId,
            Algorithm = entity.Algorithm,
            ArchivedAtUtc = _clock.GetUtcNow(),
            ArchivedBy = _actor.Username ?? "system",
            ChangeNote = changeNote
        };

    public async Task DeleteAsync(Guid id, CancellationToken ct)
    {
        var envelope = await GetEnvelopeAsync(id, ct);
        await TripHoneyTokenIfNeededAsync(envelope, ct);

        var entity = await _repository.FindAsync(id, ct) ?? throw new SecretNotFoundException(id);
        await _repository.DeleteAsync(entity, ct);
        await _cache.EvictAsync(id, ct);
    }

    private SealedSecret SealValue(string value)
    {
        var plaintext = Encoding.UTF8.GetBytes(value);
        try
        {
            return _cryptoFactory.Create().Seal(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    private async Task<EncryptedSecretEnvelope> GetEnvelopeAsync(Guid id, CancellationToken ct)
    {
        var cached = await _cache.GetAsync(id, ct);
        if (cached is not null)
        {
            return cached;
        }

        var entity = await _repository.FindAsync(id, ct);
        if (entity is null || entity.IsShredded ||
            (entity.ExpiresAtUtc is { } expiry && expiry <= _clock.GetUtcNow()))
        {
            throw new SecretNotFoundException(id);
        }

        var envelope = new EncryptedSecretEnvelope(
            entity.Id, entity.Name, entity.ProjectKey, entity.Environment, entity.Sensitivity,
            entity.Ciphertext, entity.WrappedDek, entity.KekId, entity.Algorithm,
            entity.IsHoneyToken, entity.CreatedAtUtc, entity.UpdatedAtUtc, entity.ExpiresAtUtc);

        await _cache.SetAsync(envelope, ct);
        return envelope;
    }

    private async Task TripHoneyTokenIfNeededAsync(EncryptedSecretEnvelope envelope, CancellationToken ct)
    {
        if (!envelope.IsHoneyToken)
        {
            return;
        }

        // Deliberately bypasses ABAC: the trap fires no matter who asks or from where.
        await _intrusion.TriggerHoneyTokenAsync(envelope.Id, envelope.Name, ct);
        throw new HoneyTokenTrippedException(envelope.Id, envelope.Name);
    }
}
