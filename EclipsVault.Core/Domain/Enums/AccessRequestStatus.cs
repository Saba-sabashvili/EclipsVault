namespace EclipsVault.Core.Domain.Enums;

/// <summary>Lifecycle of a user's request for access to a secret they were denied.</summary>
public enum AccessRequestStatus
{
    Pending = 0,
    Approved = 1,
    Rejected = 2,
    Cancelled = 3
}
