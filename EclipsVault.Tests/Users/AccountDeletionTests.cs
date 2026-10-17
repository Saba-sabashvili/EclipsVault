using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.Users;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;
using Xunit;

namespace EclipsVault.Tests.Users;

public sealed class AccountDeletionTests
{
    [Fact]
    public async Task Deletion_revokes_before_removing_the_account_and_audits_success()
    {
        var state = new DeletionState();
        Assert.True(await state.Service.DeleteAsync(state.User.Id, default));
        Assert.Equal(new[] { "revoke", "delete", "audit" }, state.Events);
        Assert.Equal(state.User.Id, state.RevokedUserId);
        Assert.Equal(state.Now, state.RevokedAt);
        Assert.Equal(AuditAction.UserDeleted, Assert.Single(state.Audits).Action);
    }

    [Fact]
    public async Task Unavailable_revocation_prevents_deletion_and_success_audit()
    {
        var state = new DeletionState { RefuseRevocation = true };
        await Assert.ThrowsAsync<InvalidOperationException>(() => state.Service.DeleteAsync(state.User.Id, default));
        Assert.Equal(new[] { "revoke" }, state.Events);
        Assert.Empty(state.Audits);
    }

    [Fact]
    public async Task Failed_deletion_leaves_sessions_revoked_without_a_success_audit()
    {
        var state = new DeletionState { RefuseDelete = true };
        await Assert.ThrowsAsync<InvalidOperationException>(() => state.Service.DeleteAsync(state.User.Id, default));
        Assert.Equal(new[] { "revoke", "delete" }, state.Events);
        Assert.Equal(state.User.Id, state.RevokedUserId);
        Assert.Empty(state.Audits);
    }

    [Theory]
    [InlineData("self")]
    [InlineData("last-admin")]
    [InlineData("missing")]
    public async Task Refused_or_missing_account_is_not_revoked_or_deleted(string scenario)
    {
        var state = new DeletionState();
        var target = state.User.Id;
        if (scenario == "self")
        {
            target = state.ActorId;
        }
        else if (scenario == "last-admin")
        {
            state.User.Clearance = ClearanceLevel.TopSecret;
        }

        if (scenario == "missing")
        {
            Assert.False(await state.Service.DeleteAsync(Guid.NewGuid(), default));
        }
        else
        {
            await Assert.ThrowsAsync<VaultAdminException>(() => state.Service.DeleteAsync(target, default));
        }

        Assert.Empty(state.Events);
    }

    private sealed class DeletionState : IUserRepository, ISessionRevocationService, IAuditSink, IAuditContext
    {
        public User User { get; } = new() { Id = Guid.NewGuid(), Username = "disposable", Clearance = ClearanceLevel.Standard };
        public Guid ActorId { get; } = Guid.NewGuid();
        public DateTimeOffset Now { get; } = new(2026, 10, 17, 12, 0, 0, TimeSpan.Zero);
        public List<string> Events { get; } = [];
        public List<AuditEntry> Audits { get; } = [];
        public Guid? RevokedUserId { get; private set; }
        public DateTimeOffset? RevokedAt { get; private set; }
        public bool RefuseRevocation { get; init; }
        public bool RefuseDelete { get; init; }
        Guid? IAuditContext.UserId => ActorId;
        string? IAuditContext.Username => "administrator";
        string? IAuditContext.SourceIp => "127.0.0.1";

        // Deletion must not touch password, MFA, provisioning or notification dependencies.
        public UserAdminService Service => new(this, null!, this, null!, null!, new UserDirectoryOptions("test.invalid"), null!, this, this, new FixedClock(Now));

        public Task RevokeAsync(Guid userId, DateTimeOffset revokedAtUtc, CancellationToken ct = default)
        {
            Events.Add("revoke");
            if (RefuseRevocation)
            {
                throw new InvalidOperationException("Disposable revocation failure.");
            }

            RevokedUserId = userId;
            RevokedAt = revokedAtUtc;
            return Task.CompletedTask;
        }

        public Task DeleteAsync(User user, CancellationToken ct)
        {
            Events.Add("delete");
            if (RefuseDelete)
            {
                throw new InvalidOperationException("Disposable deletion failure.");
            }

            return Task.CompletedTask;
        }

        public Task WriteAsync(AuditEntry entry, CancellationToken ct)
        {
            Events.Add("audit");
            Audits.Add(entry);
            return Task.CompletedTask;
        }

        public Task<User?> FindByIdAsync(Guid id, CancellationToken ct) => Task.FromResult(id == User.Id ? User : null);
        public Task<IReadOnlyList<User>> ListAsync(CancellationToken ct) => Task.FromResult<IReadOnlyList<User>>([User]);
        public Task<bool> IsRevokedAsync(Guid userId, DateTimeOffset sessionIssuedAtUtc, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<User?> FindByUsernameAsync(string username, CancellationToken ct) => throw new NotSupportedException();
        public Task<User?> FindByUsernameOrEmailAsync(string identifier, CancellationToken ct) => throw new NotSupportedException();
        public Task<IReadOnlyList<string>> FindEmailsWithPrefixAsync(string localPrefix, string domain, CancellationToken ct) => throw new NotSupportedException();
        public Task AddAsync(User user, CancellationToken ct) => throw new NotSupportedException();
        public Task UpdateAsync(User user, CancellationToken ct) => throw new NotSupportedException();
        public Task<byte[]?> GetAvatarPngAsync(Guid userId, CancellationToken ct) => throw new NotSupportedException();
        public Task SetAvatarAsync(User user, byte[] png, CancellationToken ct) => throw new NotSupportedException();
        public Task RemoveAvatarAsync(User user, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
