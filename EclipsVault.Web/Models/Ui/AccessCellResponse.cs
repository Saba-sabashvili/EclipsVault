namespace EclipsVault.Web.Models.Ui;

/// <summary>Allowed, or the same short first-denial explanation the Legacy UI showed.</summary>
public sealed record AccessCellResponse(string Environment, bool Allowed, string? Reason);
