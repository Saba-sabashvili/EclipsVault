using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EclipsVault.Infrastructure.Persistence.Configurations;

public sealed class EmailLogConfiguration : IEntityTypeConfiguration<EmailLog>
{
    public void Configure(EntityTypeBuilder<EmailLog> builder)
    {
        builder.ToTable("EmailLogs");
        builder.HasKey(e => e.Id);

        builder.Property(e => e.ToAddress).HasMaxLength(256).IsRequired();
        builder.Property(e => e.Subject).HasMaxLength(256).IsRequired();
        builder.Property(e => e.Body).HasMaxLength(4000).IsRequired();
        builder.Property(e => e.EventType).HasMaxLength(64).IsRequired();
        builder.Property(e => e.Transport).HasMaxLength(32).IsRequired();
        builder.Property(e => e.Error).HasMaxLength(1024);
        builder.Property(e => e.Status).HasConversion<int>();

        builder.HasIndex(e => e.CreatedAtUtc);
    }
}
