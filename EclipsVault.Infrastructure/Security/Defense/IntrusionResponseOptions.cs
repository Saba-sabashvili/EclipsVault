namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Tuning for the active-defence containment that runs when a honey-token is tripped.
/// </summary>
public sealed class IntrusionResponseOptions
{
    public const string SectionName = "IntrusionResponse";

    /// <summary>
    /// When <c>false</c> (the default), a trip blocks only the exact offending host. When <c>true</c>,
    /// it blocks the surrounding /24 (IPv4) or /64 (IPv6).
    ///
    /// The default is the exact host because the blacklist is consulted before authentication on every
    /// request: widening the block to a subnet lets one trip from behind a shared egress (office NAT,
    /// VPN concentrator, cloud NAT gateway) deny the vault to everyone on that range — a low-privilege
    /// session, or a compromised one, could take the whole office offline. Enable range blocking only
    /// for single-tenant deployments where the entire subnet is under one operator's control.
    ///
    /// Changing this at runtime does not retroactively re-key existing blocks; already-blocked entries
    /// keep the width they were created with until they are lifted.
    /// </summary>
    public bool BlockSurroundingRange { get; set; }
}
