using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EclipsVault.Infrastructure.Persistence.Configurations;

public sealed class ServiceAccountConfiguration : IEntityTypeConfiguration<ServiceAccount>
{
    public void Configure(EntityTypeBuilder<ServiceAccount> builder)
    {
        builder.ToTable("ServiceAccounts");
        builder.HasKey(a => a.Id);

        builder.Property(a => a.Name).HasMaxLength(64).IsRequired();
        builder.HasIndex(a => a.Name).IsUnique();

        builder.Property(a => a.ProjectKey).HasMaxLength(64).IsRequired();
        builder.Property(a => a.Clearance).HasConversion<int>();

        builder.HasMany(a => a.Keys)
            .WithOne(k => k.ServiceAccount)
            .HasForeignKey(k => k.ServiceAccountId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}

public sealed class ApiKeyConfiguration : IEntityTypeConfiguration<ApiKey>
{
    public void Configure(EntityTypeBuilder<ApiKey> builder)
    {
        builder.ToTable("ApiKeys");
        builder.HasKey(k => k.Id);

        builder.Property(k => k.KeyHash).HasMaxLength(64).IsRequired();
        builder.HasIndex(k => k.KeyHash).IsUnique();

        builder.Property(k => k.Prefix).HasMaxLength(32).IsRequired();

        // Per-key scope (all narrowing, all optional).
        builder.Property(k => k.ClearanceCeiling).HasConversion<int?>();
        builder.Property(k => k.ProjectScope).HasMaxLength(64);
        builder.Property(k => k.MetadataOnly).HasDefaultValue(false);
        builder.Property(k => k.AllowedCidrs).HasMaxLength(512);
    }
}
