namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// An explicit access grant: a named user is allowed to reach a specific secret even
/// though they are outside its project. A grant crosses the project boundary only —
/// the grantee still needs adequate clearance and must satisfy the network/time rules,
/// so sharing never widens the clearance ceiling. Grants may carry an expiry.
/// </summary>
public class SecretGrant
{
    public Guid Id { get; set; }

    public Guid SecretId { get; set; }

    public Guid GranteeUserId { get; set; }

    /// <summary>Denormalized for display in the sharing panel without an extra join.</summary>
    public string GranteeUsername { get; set; } = string.Empty;

    /// <summary>Username of whoever created the grant.</summary>
    public string GrantedBy { get; set; } = string.Empty;

    public DateTimeOffset CreatedAtUtc { get; set; }

    /// <summary>When set and in the past, the grant no longer confers access.</summary>
    public DateTimeOffset? ExpiresAtUtc { get; set; }

    public bool IsActive(DateTimeOffset nowUtc) => ExpiresAtUtc is null || ExpiresAtUtc > nowUtc;
}
