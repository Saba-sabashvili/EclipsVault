namespace EclipsVault.Web.Models.Ui;

/// <summary>One classification's decisions across the deployment environments.</summary>
public sealed record AccessRowResponse(string Sensitivity, int SensitivityRank, IReadOnlyList<AccessCellResponse> Cells);
