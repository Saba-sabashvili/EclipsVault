namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// A user's custom profile picture, always stored as a sanitised, re-encoded PNG.
/// Kept in its own table so the (potentially large) blob is never dragged in by
/// ordinary <see cref="User"/> queries.
/// </summary>
public class UserAvatar
{
    /// <summary>Primary key and one-to-one foreign key to the owning user.</summary>
    public Guid UserId { get; set; }

    /// <summary>Sanitised PNG bytes (already resized and stripped of metadata).</summary>
    public byte[] Png { get; set; } = [];

    public DateTimeOffset UpdatedAtUtc { get; set; }
}
