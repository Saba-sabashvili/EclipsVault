using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace EclipsVault.Infrastructure.Persistence;

/// <summary>
/// The vault's persistence root. All mapping lives in IEntityTypeConfiguration
/// classes — domain entities stay free of database attributes.
/// </summary>
public sealed class EclipsVaultDbContext : DbContext
{
    public EclipsVaultDbContext(DbContextOptions<EclipsVaultDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users => Set<User>();

    public DbSet<Secret> Secrets => Set<Secret>();

    public DbSet<SecretVersion> SecretVersions => Set<SecretVersion>();

    public DbSet<SecretGrant> SecretGrants => Set<SecretGrant>();

    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    public DbSet<AuditCheckpoint> AuditCheckpoints => Set<AuditCheckpoint>();

    public DbSet<PasskeyCredential> PasskeyCredentials => Set<PasskeyCredential>();

    public DbSet<MfaRecoveryCode> MfaRecoveryCodes => Set<MfaRecoveryCode>();

    public DbSet<TrustedNetwork> TrustedNetworks => Set<TrustedNetwork>();

    public DbSet<UserAvatar> UserAvatars => Set<UserAvatar>();

    public DbSet<ServiceAccount> ServiceAccounts => Set<ServiceAccount>();

    public DbSet<ApiKey> ApiKeys => Set<ApiKey>();

    public DbSet<AccessRequest> AccessRequests => Set<AccessRequest>();

    public DbSet<EmailLog> EmailLogs => Set<EmailLog>();

    /// <summary>Recipes for minting short-lived backend credentials on demand.</summary>
    public DbSet<DynamicSecretRole> DynamicSecretRoles => Set<DynamicSecretRole>();

    /// <summary>Issued dynamic credentials, tracked so they can be destroyed when their lease ends.</summary>
    public DbSet<DynamicSecretLease> DynamicSecretLeases => Set<DynamicSecretLease>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
        => modelBuilder.ApplyConfigurationsFromAssembly(typeof(EclipsVaultDbContext).Assembly);
}
