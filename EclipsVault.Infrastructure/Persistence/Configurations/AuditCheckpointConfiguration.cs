using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EclipsVault.Infrastructure.Persistence.Configurations;

public sealed class AuditCheckpointConfiguration : IEntityTypeConfiguration<AuditCheckpoint>
{
    public void Configure(EntityTypeBuilder<AuditCheckpoint> builder)
    {
        builder.ToTable("AuditCheckpoints");
        builder.HasKey(c => c.Id);

        builder.Property(c => c.ChainHeadHash).HasMaxLength(64).IsRequired();
        builder.Property(c => c.Signature).HasMaxLength(256).IsRequired(); // P-256 DER sig ~72 bytes
        builder.Property(c => c.SigningKeyId).HasMaxLength(32).IsRequired();

        builder.HasIndex(c => c.Sequence);
    }
}
