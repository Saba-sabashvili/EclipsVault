using EclipsVault.Core.Application.Activity;
using EclipsVault.Core.Domain.Enums;
using Xunit;

namespace EclipsVault.Tests.Licensing;

public class LicenseActivityTests
{
    [Fact]
    public void The_unlicensed_production_action_has_an_explicit_plain_language_description()
    {
        var described = ActivityDescriber.Describe(AuditAction.LicenseInvalidProductionUse);

        // An explicit mapping, not the humanised fallback (which would land in Other / Routine).
        Assert.NotEqual(ActivityCategory.Other, described.Category);
        Assert.Equal(ActivitySeverity.Notable, described.Severity);
        Assert.False(string.IsNullOrWhiteSpace(described.Title));
    }
}
