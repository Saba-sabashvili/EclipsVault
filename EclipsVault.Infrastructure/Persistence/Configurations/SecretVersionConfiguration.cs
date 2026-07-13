using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EclipsVault.Infrastructure.Persistence.Configurations;

public sealed class SecretVersionConfiguration : IEntityTypeConfiguration<SecretVersion>
{
    public void Configure(EntityTypeBuilder<SecretVersion> builder)
    {
        builder.ToTable("SecretVersions");
        builder.HasKey(v => v.Id);

        builder.Property(v => v.Ciphertext).IsRequired();
        builder.Property(v => v.WrappedDek).IsRequired();
        builder.Property(v => v.KekId).HasMaxLength(64).IsRequired();
        builder.Property(v => v.Algorithm).HasMaxLength(32).IsRequired();
        builder.Property(v => v.ArchivedBy).HasMaxLength(64).IsRequired();
        builder.Property(v => v.ChangeNote).HasMaxLength(256);

        builder.HasIndex(v => new { v.SecretId, v.VersionNumber }).IsUnique();

        // Deleting a secret removes its archived versions.
        builder.HasOne<Secret>()
            .WithMany()
            .HasForeignKey(v => v.SecretId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
