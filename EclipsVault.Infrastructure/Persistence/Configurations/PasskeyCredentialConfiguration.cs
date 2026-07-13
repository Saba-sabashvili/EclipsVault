using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EclipsVault.Infrastructure.Persistence.Configurations;

public sealed class PasskeyCredentialConfiguration : IEntityTypeConfiguration<PasskeyCredential>
{
    public void Configure(EntityTypeBuilder<PasskeyCredential> builder)
    {
        builder.ToTable("PasskeyCredentials");
        builder.HasKey(p => p.Id);

        builder.Property(p => p.CredentialId).HasMaxLength(1024).IsRequired();
        builder.HasIndex(p => p.CredentialId).IsUnique();

        builder.Property(p => p.PublicKey).IsRequired();
        builder.Property(p => p.Nickname).HasMaxLength(64);
    }
}
