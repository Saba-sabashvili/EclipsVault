using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EclipsVault.Infrastructure.Persistence.Configurations;

public sealed class DynamicSecretRoleConfiguration : IEntityTypeConfiguration<DynamicSecretRole>
{
    public void Configure(EntityTypeBuilder<DynamicSecretRole> builder)
    {
        builder.ToTable("DynamicSecretRoles");
        builder.HasKey(r => r.Id);

        builder.Property(r => r.Name).HasMaxLength(64).IsRequired();
        builder.HasIndex(r => r.Name).IsUnique();

        builder.Property(r => r.Description).HasMaxLength(256).IsRequired();
        builder.Property(r => r.ProjectKey).HasMaxLength(64).IsRequired();
        builder.Property(r => r.CreationStatements).HasMaxLength(4000).IsRequired();
        builder.Property(r => r.RevocationStatements).HasMaxLength(4000).IsRequired();
    }
}
