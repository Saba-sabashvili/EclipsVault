using EclipsVault.Core.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace EclipsVault.Infrastructure.Persistence.Configurations;

public sealed class FeatureEvaluationConfiguration : IEntityTypeConfiguration<FeatureEvaluation>
{
    public void Configure(EntityTypeBuilder<FeatureEvaluation> builder)
    {
        builder.ToTable("FeatureEvaluations");

        // The capability key is the identity: one window per capability, and the primary key is what
        // makes two nodes opening it at once resolve to a single winner rather than two windows.
        builder.HasKey(e => e.FeatureKey);
        builder.Property(e => e.FeatureKey).HasMaxLength(64).IsRequired();
        builder.Property(e => e.StartedAtUtc).IsRequired();
    }
}
