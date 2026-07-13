using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EclipsVault.Infrastructure.Persistence.Configurations;

public sealed class TrustedNetworkConfiguration : IEntityTypeConfiguration<TrustedNetwork>
{
    public void Configure(EntityTypeBuilder<TrustedNetwork> builder)
    {
        builder.ToTable("TrustedNetworks");
        builder.HasKey(t => t.Id);

        builder.Property(t => t.Cidr).HasMaxLength(64).IsRequired();
        builder.HasIndex(t => t.Cidr).IsUnique();

        builder.Property(t => t.Label).HasMaxLength(128).IsRequired();
        builder.Property(t => t.AddedBy).HasMaxLength(64).IsRequired();
    }
}
