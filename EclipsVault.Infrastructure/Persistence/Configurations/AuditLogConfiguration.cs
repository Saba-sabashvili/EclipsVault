using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EclipsVault.Infrastructure.Persistence.Configurations;

public sealed class AuditLogConfiguration : IEntityTypeConfiguration<AuditLog>
{
    public void Configure(EntityTypeBuilder<AuditLog> builder)
    {
        builder.ToTable("AuditLogs");
        builder.HasKey(a => a.Id);

        builder.Property(a => a.Username).HasMaxLength(64).IsRequired();
        builder.Property(a => a.SourceIp).HasMaxLength(64).IsRequired();
        builder.Property(a => a.Action).HasConversion<int>();
        builder.Property(a => a.ResourceType).HasMaxLength(64).IsRequired();
        builder.Property(a => a.ResourceName).HasMaxLength(128);
        builder.Property(a => a.Details).HasMaxLength(1024);
        builder.Property(a => a.PreviousHash).HasMaxLength(64);
        builder.Property(a => a.EntryHash).HasMaxLength(64);

        builder.HasIndex(a => a.TimestampUtc);
        builder.HasIndex(a => a.ResourceId);
        builder.HasIndex(a => a.UserId);

        // Chained rows have a unique, gap-free sequence; the filter excludes not-yet-chained
        // rows (Sequence 0) so the constraint can be added before the one-time back-fill runs.
        builder.HasIndex(a => a.Sequence).IsUnique().HasFilter("[Sequence] <> 0");
    }
}
