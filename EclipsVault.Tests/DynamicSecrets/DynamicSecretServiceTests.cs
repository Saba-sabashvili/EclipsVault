using EclipsVault.Core.Application.Abstractions;
using EclipsVault.Core.Application.DynamicSecrets;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Core.Domain.Exceptions;
using Xunit;

namespace EclipsVault.Tests.DynamicSecrets;

/// <summary>
/// A dynamic credential is live on a real backend, so the lease lifecycle carries the safety
/// properties: a caller cannot lease one for longer than the role allows, a credential the vault
/// failed to record is rolled back rather than left orphaned, a revocation failure is surfaced
/// instead of swallowed, and revoke cannot be used to probe for other people's leases.
/// </summary>
public class DynamicSecretServiceTests
{
    private static readonly Guid Owner = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid Stranger = Guid.Parse("22222222-2222-2222-2222-222222222222");

    private sealed class FakeBackend : IDynamicSecretBackend
    {
        public bool MintThrows { get; init; }
        public bool RevokeThrows { get; init; }
        public List<string> Minted { get; } = [];
        public List<string> Revoked { get; } = [];

        public DynamicSecretBackend Backend => DynamicSecretBackend.SqlServer;

        public Task MintAsync(DynamicSecretRole role, string identity, string password, DateTimeOffset expiresAtUtc, CancellationToken ct)
        {
            if (MintThrows)
            {
                throw new InvalidOperationException("backend refused");
            }

            Minted.Add(identity);
            return Task.CompletedTask;
        }

        public Task RevokeAsync(DynamicSecretRole role, string identity, CancellationToken ct)
        {
            if (RevokeThrows)
            {
                throw new InvalidOperationException("login is still connected");
            }

            Revoked.Add(identity);
            return Task.CompletedTask;
        }
    }

    private sealed class FakeRepository : IDynamicSecretRepository
    {
        private readonly DynamicSecretRole? _role;
        public FakeRepository(DynamicSecretRole? role) => _role = role;

        public bool AddThrows { get; init; }
        public List<DynamicSecretLease> Leases { get; } = [];

        public Task<IReadOnlyList<DynamicSecretRole>> ListRolesAsync(CancellationToken ct)
            => Task.FromResult<IReadOnlyList<DynamicSecretRole>>(_role is null ? [] : [_role]);

        public Task<DynamicSecretRole?> FindRoleAsync(Guid roleId, CancellationToken ct) => Task.FromResult(_role);

        public Task AddLeaseAsync(DynamicSecretLease lease, CancellationToken ct)
        {
            if (AddThrows)
            {
                throw new InvalidOperationException("audit write failed");
            }

            Leases.Add(lease);
            return Task.CompletedTask;
        }

        public Task<DynamicSecretLease?> FindLeaseAsync(Guid leaseId, CancellationToken ct)
            => Task.FromResult(Leases.FirstOrDefault(l => l.Id == leaseId));

        public Task<IReadOnlyList<DynamicSecretLease>> ListLeasesForUserAsync(Guid userId, int max, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<DynamicSecretLease>>(Leases.Where(l => l.UserId == userId).ToList());

        public Task<IReadOnlyList<DynamicSecretLease>> ListAllLeasesAsync(int max, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<DynamicSecretLease>>(Leases);

        public Task<IReadOnlyList<DynamicSecretLease>> ListDueLeasesAsync(DateTimeOffset asOfUtc, CancellationToken ct)
            => Task.FromResult<IReadOnlyList<DynamicSecretLease>>(Leases.Where(l => l.IsDue(asOfUtc)).ToList());

        public Task UpdateLeaseAsync(DynamicSecretLease lease, CancellationToken ct) => Task.CompletedTask;
    }

    private sealed class StubActor : IAuditContext
    {
        public Guid? UserId => Owner;
        public string? Username => "dev-user";
        public string? SourceIp => "::1";
    }

    private static DynamicSecretRole Role(bool enabled = true, int defaultTtl = 15, int maxTtl = 60) => new()
    {
        Id = Guid.NewGuid(),
        Name = "phoenix_db_reader",
        ProjectKey = "PHOENIX",
        Backend = DynamicSecretBackend.SqlServer,
        CreationStatements = "CREATE LOGIN [{{name}}] WITH PASSWORD = '{{password}}';",
        RevocationStatements = "DROP LOGIN [{{name}}];",
        DefaultTtlMinutes = defaultTtl,
        MaxTtlMinutes = maxTtl,
        IsEnabled = enabled
    };

    private static DynamicSecretService Build(FakeRepository repository, FakeBackend backend)
        => new(repository, [backend], new StubActor(), TimeProvider.System);

    [Fact]
    public async Task Issuing_mints_a_credential_and_opens_a_lease()
    {
        var role = Role();
        var repository = new FakeRepository(role);
        var backend = new FakeBackend();

        var issued = await Build(repository, backend).IssueAsync(role.Id, null, CancellationToken.None);

        Assert.Equal(Assert.Single(backend.Minted), issued.Identity);
        Assert.NotEmpty(issued.Secret);

        var lease = Assert.Single(repository.Leases);
        Assert.Equal(LeaseStatus.Active, lease.Status);
        Assert.Equal(issued.Identity, lease.CredentialIdentity);
        Assert.Equal(Owner, lease.UserId);
    }

    [Fact]
    public async Task The_issued_password_is_never_written_to_the_lease()
    {
        // The whole premise of a dynamic secret: the vault keeps no copy. A lease table leak must
        // not yield live credentials, so the secret exists only in the issuing response.
        var role = Role();
        var repository = new FakeRepository(role);

        var issued = await Build(repository, new FakeBackend()).IssueAsync(role.Id, null, CancellationToken.None);

        var lease = Assert.Single(repository.Leases);
        Assert.DoesNotContain(issued.Secret, lease.CredentialIdentity);
        Assert.DoesNotContain(issued.Secret, lease.RoleName);
        Assert.DoesNotContain(issued.Secret, lease.Username);
    }

    [Theory]
    [InlineData(null, 15)]   // no ask -> the role's default
    [InlineData(5, 5)]       // under the ceiling -> honoured
    [InlineData(600, 60)]    // over the ceiling -> clamped, not rejected
    [InlineData(0, 1)]       // nonsense -> floor
    [InlineData(-99, 1)]
    public async Task A_requested_lease_is_clamped_to_the_roles_ceiling(int? requested, int expectedMinutes)
    {
        var role = Role(defaultTtl: 15, maxTtl: 60);
        var repository = new FakeRepository(role);

        var before = DateTimeOffset.UtcNow;
        var issued = await Build(repository, new FakeBackend()).IssueAsync(role.Id, requested, CancellationToken.None);

        var actual = (issued.ExpiresAtUtc - before).TotalMinutes;
        Assert.InRange(actual, expectedMinutes - 1, expectedMinutes + 1);
    }

    [Fact]
    public async Task A_disabled_role_issues_nothing()
    {
        var role = Role(enabled: false);
        var backend = new FakeBackend();

        await Assert.ThrowsAsync<VaultAdminException>(
            () => Build(new FakeRepository(role), backend).IssueAsync(role.Id, null, CancellationToken.None));

        Assert.Empty(backend.Minted);
    }

    [Fact]
    public async Task An_unknown_role_issues_nothing()
    {
        var backend = new FakeBackend();

        await Assert.ThrowsAsync<VaultAdminException>(
            () => Build(new FakeRepository(null), backend).IssueAsync(Guid.NewGuid(), null, CancellationToken.None));

        Assert.Empty(backend.Minted);
    }

    [Fact]
    public async Task A_backend_that_refuses_to_mint_leaves_no_lease()
    {
        var role = Role();
        var repository = new FakeRepository(role);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build(repository, new FakeBackend { MintThrows = true }).IssueAsync(role.Id, null, CancellationToken.None));

        Assert.Empty(repository.Leases);
    }

    [Fact]
    public async Task A_credential_that_cannot_be_recorded_is_rolled_back_off_the_backend()
    {
        // The dangerous case: minted for real, but the lease (and its audit row) failed to persist.
        // Left alone that is a live credential nothing will ever reap. It must be undone.
        var role = Role();
        var backend = new FakeBackend();
        var repository = new FakeRepository(role) { AddThrows = true };

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Build(repository, backend).IssueAsync(role.Id, null, CancellationToken.None));

        Assert.Equal(Assert.Single(backend.Minted), Assert.Single(backend.Revoked));
    }

    [Fact]
    public async Task Revoking_destroys_the_credential_and_closes_the_lease()
    {
        var role = Role();
        var repository = new FakeRepository(role);
        var backend = new FakeBackend();
        var service = Build(repository, backend);

        var issued = await service.IssueAsync(role.Id, null, CancellationToken.None);

        Assert.True(await service.RevokeAsync(issued.LeaseId, Owner, isAdmin: false, CancellationToken.None));
        Assert.Equal(issued.Identity, Assert.Single(backend.Revoked));
        Assert.Equal(LeaseStatus.Revoked, Assert.Single(repository.Leases).Status);
    }

    [Fact]
    public async Task A_stranger_cannot_revoke_someone_elses_lease()
    {
        var role = Role();
        var repository = new FakeRepository(role);
        var backend = new FakeBackend();
        var service = Build(repository, backend);

        var issued = await service.IssueAsync(role.Id, null, CancellationToken.None);

        Assert.False(await service.RevokeAsync(issued.LeaseId, Stranger, isAdmin: false, CancellationToken.None));
        Assert.Empty(backend.Revoked);
        Assert.Equal(LeaseStatus.Active, Assert.Single(repository.Leases).Status);
    }

    [Fact]
    public async Task An_admin_can_revoke_anyones_lease()
    {
        var role = Role();
        var repository = new FakeRepository(role);
        var service = Build(repository, new FakeBackend());

        var issued = await service.IssueAsync(role.Id, null, CancellationToken.None);

        Assert.True(await service.RevokeAsync(issued.LeaseId, Stranger, isAdmin: true, CancellationToken.None));
    }

    [Fact]
    public async Task An_unknown_lease_is_indistinguishable_from_a_forbidden_one()
    {
        var service = Build(new FakeRepository(Role()), new FakeBackend());

        Assert.False(await service.RevokeAsync(Guid.NewGuid(), Owner, isAdmin: false, CancellationToken.None));
    }

    [Fact]
    public async Task A_lease_cannot_be_revoked_twice()
    {
        var role = Role();
        var repository = new FakeRepository(role);
        var backend = new FakeBackend();
        var service = Build(repository, backend);

        var issued = await service.IssueAsync(role.Id, null, CancellationToken.None);
        Assert.True(await service.RevokeAsync(issued.LeaseId, Owner, isAdmin: false, CancellationToken.None));
        Assert.False(await service.RevokeAsync(issued.LeaseId, Owner, isAdmin: false, CancellationToken.None));

        Assert.Single(backend.Revoked);
    }

    [Fact]
    public async Task A_backend_that_refuses_to_revoke_records_the_failure_rather_than_claiming_success()
    {
        // The credential may still be live. Closing the lease as "Revoked" would be a lie the audit
        // trail then repeats, so this lands in RevocationFailed with the reason attached.
        var role = Role();
        var repository = new FakeRepository(role);
        var service = Build(repository, new FakeBackend { RevokeThrows = true });

        var issued = await service.IssueAsync(role.Id, null, CancellationToken.None);
        Assert.True(await service.RevokeAsync(issued.LeaseId, Owner, isAdmin: false, CancellationToken.None));

        var lease = Assert.Single(repository.Leases);
        Assert.Equal(LeaseStatus.RevocationFailed, lease.Status);
        Assert.Contains("still connected", lease.RevocationError);
    }

    [Fact]
    public async Task Reaping_closes_only_leases_whose_time_is_up()
    {
        var role = Role(defaultTtl: 15, maxTtl: 60);
        var repository = new FakeRepository(role);
        var backend = new FakeBackend();
        var service = Build(repository, backend);

        var live = await service.IssueAsync(role.Id, 60, CancellationToken.None);
        var doomed = await service.IssueAsync(role.Id, 1, CancellationToken.None);

        // Force the second lease past its deadline without waiting a minute for it.
        repository.Leases.Single(l => l.Id == doomed.LeaseId).ExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(-1);

        Assert.Equal(1, await service.ReapDueLeasesAsync(CancellationToken.None));
        Assert.Equal(doomed.Identity, Assert.Single(backend.Revoked));
        Assert.Equal(LeaseStatus.Active, repository.Leases.Single(l => l.Id == live.LeaseId).Status);
        Assert.Equal(LeaseStatus.Expired, repository.Leases.Single(l => l.Id == doomed.LeaseId).Status);
    }

    [Fact]
    public async Task Leases_are_listed_per_user_unless_you_are_an_admin()
    {
        var role = Role();
        var repository = new FakeRepository(role);
        var service = Build(repository, new FakeBackend());

        await service.IssueAsync(role.Id, null, CancellationToken.None);

        Assert.Single(await service.ListLeasesAsync(Owner, includeEveryone: false, CancellationToken.None));
        Assert.Empty(await service.ListLeasesAsync(Stranger, includeEveryone: false, CancellationToken.None));
        Assert.Single(await service.ListLeasesAsync(Stranger, includeEveryone: true, CancellationToken.None));
    }
}
