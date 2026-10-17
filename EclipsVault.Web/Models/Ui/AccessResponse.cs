namespace EclipsVault.Web.Models.Ui;

/// <summary>
/// The caller's own access explanation. Only these selected fields reach the wire; in particular,
/// network configuration, other accounts and actual secrets are never part of this response.
/// Ranks select the existing classification badge styles; decisions come solely from the server.
/// </summary>
public sealed record AccessResponse(
    string Clearance,
    int ClearanceRank,
    string Project,
    bool CrossesProjects,
    string SourceIp,
    bool IsTrustedNetwork,
    bool IsProductionWindowOpen,
    int WindowStartHour,
    int WindowEndHour,
    string WindowZone,
    IReadOnlyList<string> Environments,
    IReadOnlyList<AccessRowResponse> Rows);
