using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EclipsVault.Infrastructure.Persistence.Configurations;

public sealed class SecretConfiguration : IEntityTypeConfiguration<Secret>
{
    public void Configure(EntityTypeBuilder<Secret> builder)
    {
        builder.ToTable("Secrets");
        builder.HasKey(s => s.Id);

        builder.Property(s => s.Name).HasMaxLength(128).IsRequired();
        builder.HasIndex(s => s.Name).IsUnique();

        builder.Property(s => s.ProjectKey).HasMaxLength(64).IsRequired();
        builder.Property(s => s.Environment).HasConversion<int>();
        builder.Property(s => s.Sensitivity).HasConversion<int>();

        builder.Property(s => s.Ciphertext).IsRequired();
        builder.Property(s => s.WrappedDek).IsRequired();
        builder.Property(s => s.KekId).HasMaxLength(64).IsRequired();
        builder.Property(s => s.Algorithm).HasMaxLength(32).IsRequired();

        builder.HasIndex(s => s.ExpiresAtUtc);
        builder.HasIndex(s => new { s.ProjectKey, s.Environment });
    }
}
