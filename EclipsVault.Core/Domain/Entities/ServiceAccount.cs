using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Domain.Entities;

/// <summary>
/// A non-interactive identity (an application or service) that retrieves secrets over
/// the API using an <see cref="ApiKey"/> instead of password + TOTP. It carries the
/// same ABAC attributes as a user — clearance and project — so the existing access
/// policy governs exactly what it can read.
/// </summary>
public class ServiceAccount
{
    public Guid Id { get; set; }

    /// <summary>Human-friendly, unique identifier for the service.</summary>
    public string Name { get; set; } = string.Empty;

    public ClearanceLevel Clearance { get; set; } = ClearanceLevel.Standard;

    public string ProjectKey { get; set; } = string.Empty;

    /// <summary>When true, all of its keys are rejected regardless of their own state.</summary>
    public bool IsDisabled { get; set; }

    public DateTimeOffset CreatedAtUtc { get; set; }

    public ICollection<ApiKey> Keys { get; set; } = new List<ApiKey>();
}
