using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EclipsVault.Infrastructure.Persistence.Configurations;

public sealed class DynamicSecretLeaseConfiguration : IEntityTypeConfiguration<DynamicSecretLease>
{
    public void Configure(EntityTypeBuilder<DynamicSecretLease> builder)
    {
        builder.ToTable("DynamicSecretLeases");
        builder.HasKey(l => l.Id);

        builder.Property(l => l.RoleName).HasMaxLength(64).IsRequired();
        builder.Property(l => l.Username).HasMaxLength(64).IsRequired();

        // The minted principal's name: the only handle revocation has, so it is required and unique.
        builder.Property(l => l.CredentialIdentity).HasMaxLength(128).IsRequired();
        builder.HasIndex(l => l.CredentialIdentity).IsUnique();

        builder.Property(l => l.RevocationError).HasMaxLength(500);

        // The reaper's hot path: find the active leases that are due.
        builder.HasIndex(l => new { l.Status, l.ExpiresAtUtc });
        builder.HasIndex(l => l.UserId);
    }
}
