using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Web.Models;

/// <summary>One environment's outcome for a given sensitivity: allowed, or a short reason why not.</summary>
public sealed record AccessCell(SecretEnvironment Environment, bool Allowed, string? Reason);

/// <summary>A sensitivity row across every environment.</summary>
public sealed record AccessRow(SensitivityLevel Sensitivity, IReadOnlyList<AccessCell> Cells);

/// <summary>
/// The "My access" page: the caller's own subject attributes, the live request context, and a grid
/// of what they could open right now (evaluated by the real ABAC engine).
/// </summary>
public sealed class MyAccessViewModel
{
    public required ClearanceLevel Clearance { get; init; }
    public required string ProjectKey { get; init; }
    public required string SourceIp { get; init; }
    public required bool IsTrustedNetwork { get; init; }
    public required bool IsProductionWindowOpen { get; init; }
    public required int WindowStartHour { get; init; }
    public required int WindowEndHour { get; init; }
    public required string WindowZone { get; init; }
    public required IReadOnlyList<SecretEnvironment> Environments { get; init; }
    public required IReadOnlyList<AccessRow> Rows { get; init; }

    /// <summary>Whether this user's clearance lets them cross project boundaries (TopSecret only).</summary>
    public bool CrossesProjects => Clearance == ClearanceLevel.TopSecret;

    public string WindowRange => $"{WindowStartHour:00}:00–{WindowEndHour:00}:00 {WindowZone}";
}
