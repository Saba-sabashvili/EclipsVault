using System.Net;
using EclipsVault.Core.Application.Networks;
using EclipsVault.Core.Domain.Entities;
using Xunit;

namespace EclipsVault.Tests.ServiceAccounts;

/// <summary>
/// The per-key network-binding decision — the same predicate the authenticator applies:
/// an empty binding allows any source; otherwise the source must fall inside an allowed range.
/// </summary>
public class ApiKeyNetworkBindingTests
{
    private static bool WouldAccept(string? binding, string sourceIp)
    {
        var allowed = new ApiKey { AllowedCidrs = binding }.AllowedCidrList();
        return allowed.Count == 0 || NetworkRules.IsInAnyCidr(IPAddress.Parse(sourceIp), allowed);
    }

    [Fact]
    public void A_key_with_no_binding_is_accepted_from_anywhere()
        => Assert.True(WouldAccept(null, "8.8.8.8"));

    [Fact]
    public void A_source_inside_the_binding_is_accepted()
        => Assert.True(WouldAccept("10.0.0.0/24;192.168.1.0/24", "192.168.1.50"));

    [Fact]
    public void A_source_outside_the_binding_is_rejected()
        => Assert.False(WouldAccept("10.0.0.0/24", "203.0.113.9"));

    [Fact]
    public void AllowedCidrList_splits_trims_and_ignores_blanks()
    {
        var key = new ApiKey { AllowedCidrs = "10.0.0.0/24; 192.168.0.0/16 ;" };
        Assert.Equal(["10.0.0.0/24", "192.168.0.0/16"], key.AllowedCidrList());
    }
}
