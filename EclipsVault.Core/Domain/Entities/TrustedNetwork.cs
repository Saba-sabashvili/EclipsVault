namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// A runtime-managed trusted source range for the ABAC network rule. Complements the
/// static Abac:TrustedIpCidrs configuration so administrators can trust a new
/// location (e.g. a VPN egress address) without redeploying.
/// </summary>
public class TrustedNetwork
{
    public Guid Id { get; set; }

    /// <summary>Normalized CIDR notation (a bare IP is stored as /32 or /128).</summary>
    public string Cidr { get; set; } = string.Empty;

    public string Label { get; set; } = string.Empty;

    public string AddedBy { get; set; } = string.Empty;

    public DateTimeOffset CreatedAtUtc { get; set; }
}
