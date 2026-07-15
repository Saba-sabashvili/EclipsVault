using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.Secrets;
using EclipsVault.Core.Application.Users;
using EclipsVault.Core.Domain.Entities;
using Xunit;

namespace EclipsVault.Tests.Secrets;

/// <summary>
/// The self-scoped revoke on the "Shared by me" page must never let a caller revoke a grant they
/// didn't issue. These tests pin that authorization boundary (the IDOR guard) and its indistinguishable
/// failure, plus the case-insensitive issuer match.
/// </summary>
public class SecretGrantServiceTests
{
    private sealed class FakeGrants : ISecretGrantRepository
    {
        private readonly SecretGrant? _grant;
        public int RemoveCalls { get; private set; }
        public FakeGrants(SecretGrant? grant) => _grant = grant;

        public Task<SecretGrant?> FindAsync(Guid grantId, CancellationToken ct) => Task.FromResult(_grant);
        public Task<bool> RemoveAsync(Guid grantId, CancellationToken ct)
        {
            RemoveCalls++;
            return Task.FromResult(true);
        }

        public Task AddAsync(SecretGrant grant, CancellationToken ct) => throw new NotSupportedException();
        public Task<bool> HasActiveGrantAsync(Guid userId, Guid secretId, DateTimeOffset asOfUtc, CancellationToken ct) => throw new NotSupportedException();
        public Task<bool> ExistsAsync(Guid userId, Guid secretId, CancellationToken ct) => throw new NotSupportedException();
        public Task<IReadOnlyList<SecretGrant>> ListForSecretAsync(Guid secretId, CancellationToken ct) => throw new NotSupportedException();
        public Task<IReadOnlyList<SharedSecretDto>> ListSharedWithUserAsync(Guid userId, DateTimeOffset asOfUtc, CancellationToken ct) => throw new NotSupportedException();
        public Task<IReadOnlyList<OutgoingShareDto>> ListIssuedByAsync(string grantorUsername, DateTimeOffset asOfUtc, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class FakeSecrets : ISecretRepository
    {
        public Task<Secret?> FindAsync(Guid id, CancellationToken ct)
            => Task.FromResult<Secret?>(new Secret { Id = id, Name = "prod/api-key" });

        public Task<IReadOnlyList<Secret>> ListActiveAsync(DateTimeOffset asOfUtc, CancellationToken ct) => throw new NotSupportedException();
        public Task<IReadOnlyList<Secret>> ListExpiredAsync(DateTimeOffset asOfUtc, CancellationToken ct) => throw new NotSupportedException();
        public Task AddAsync(Secret secret, CancellationToken ct) => throw new NotSupportedException();
        public Task UpdateAsync(Secret secret, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(Secret secret, CancellationToken ct) => throw new NotSupportedException();
        public Task RotateAsync(Secret secret, SecretVersion archivedVersion, CancellationToken ct) => throw new NotSupportedException();
        public Task ShredAsync(Secret secret, CancellationToken ct) => throw new NotSupportedException();
        public Task<IReadOnlyList<SecretVersion>> ListVersionsAsync(Guid secretId, CancellationToken ct) => throw new NotSupportedException();
        public Task<SecretVersion?> FindVersionAsync(Guid secretId, Guid versionId, CancellationToken ct) => throw new NotSupportedException();
        public Task<int> CountVersionsAsync(Guid secretId, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class FakeUsers : IUserRepository
    {
        public Task<User?> FindByUsernameAsync(string username, CancellationToken ct) => throw new NotSupportedException();
        public Task<User?> FindByUsernameOrEmailAsync(string identifier, CancellationToken ct) => throw new NotSupportedException();
        public Task<IReadOnlyList<string>> FindEmailsWithPrefixAsync(string localPrefix, string domain, CancellationToken ct) => throw new NotSupportedException();
        public Task<User?> FindByIdAsync(Guid id, CancellationToken ct) => throw new NotSupportedException();
        public Task<IReadOnlyList<User>> ListAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task AddAsync(User user, CancellationToken ct) => throw new NotSupportedException();
        public Task UpdateAsync(User user, CancellationToken ct) => throw new NotSupportedException();
        public Task DeleteAsync(User user, CancellationToken ct) => throw new NotSupportedException();
        public Task<byte[]?> GetAvatarPngAsync(Guid userId, CancellationToken ct) => throw new NotSupportedException();
        public Task SetAvatarAsync(User user, byte[] png, CancellationToken ct) => throw new NotSupportedException();
        public Task RemoveAvatarAsync(User user, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class RecordingSink : IAuditSink
    {
        public int Writes { get; private set; }
        public Task WriteAsync(AuditEntry entry, CancellationToken ct)
        {
            Writes++;
            return Task.CompletedTask;
        }
    }

    private sealed class StubActor : IAuditContext
    {
        public Guid? UserId => Guid.NewGuid();
        public string? Username => "alice";
        public string? SourceIp => "::1";
    }

    private static SecretGrant Grant(string grantedBy) => new()
    {
        Id = Guid.NewGuid(),
        SecretId = Guid.NewGuid(),
        GranteeUserId = Guid.NewGuid(),
        GranteeUsername = "carol",
        GrantedBy = grantedBy,
        CreatedAtUtc = DateTimeOffset.UtcNow.AddDays(-1)
    };

    private static (SecretGrantService Service, FakeGrants Grants, RecordingSink Sink) NewService(SecretGrant? grant)
    {
        var grants = new FakeGrants(grant);
        var sink = new RecordingSink();
        var service = new SecretGrantService(grants, new FakeSecrets(), new FakeUsers(), sink, new StubActor(), TimeProvider.System);
        return (service, grants, sink);
    }

    [Fact]
    public async Task Revokes_when_the_caller_issued_the_grant()
    {
        var (service, grants, sink) = NewService(Grant(grantedBy: "alice"));

        Assert.True(await service.RevokeIssuedAsync(Guid.NewGuid(), "alice", CancellationToken.None));
        Assert.Equal(1, grants.RemoveCalls);
        Assert.Equal(1, sink.Writes); // the revoke is audited
    }

    [Fact]
    public async Task Refuses_to_revoke_a_grant_issued_by_someone_else()
    {
        var (service, grants, sink) = NewService(Grant(grantedBy: "bob"));

        // alice must not be able to revoke a grant bob issued, even with its real id.
        Assert.False(await service.RevokeIssuedAsync(Guid.NewGuid(), "alice", CancellationToken.None));
        Assert.Equal(0, grants.RemoveCalls); // nothing removed
        Assert.Equal(0, sink.Writes);        // nothing audited
    }

    [Fact]
    public async Task The_issuer_match_is_case_insensitive()
    {
        var (service, grants, _) = NewService(Grant(grantedBy: "Alice"));

        Assert.True(await service.RevokeIssuedAsync(Guid.NewGuid(), "alice", CancellationToken.None));
        Assert.Equal(1, grants.RemoveCalls);
    }

    [Fact]
    public async Task Returns_false_for_a_missing_grant_without_removing_anything()
    {
        var (service, grants, sink) = NewService(grant: null);

        Assert.False(await service.RevokeIssuedAsync(Guid.NewGuid(), "alice", CancellationToken.None));
        Assert.Equal(0, grants.RemoveCalls);
        Assert.Equal(0, sink.Writes);
    }
}
