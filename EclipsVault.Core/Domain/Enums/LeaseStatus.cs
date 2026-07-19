namespace EclipsVault.Core.Domain.Enums;

/// <summary>Lifecycle of a dynamic credential's lease.</summary>
public enum LeaseStatus
{
    /// <summary>The credential exists on the backend and the lease has not yet elapsed.</summary>
    Active = 1,

    /// <summary>The TTL elapsed and the reaper destroyed the credential.</summary>
    Expired = 2,

    /// <summary>Someone handed the credential back (or an admin pulled it) before the TTL.</summary>
    Revoked = 3,

    /// <summary>
    /// The vault could not destroy the credential on the backend. The credential may still be live,
    /// so this is the one lease state that demands a human — it is audited as critical.
    /// </summary>
    RevocationFailed = 4
}
