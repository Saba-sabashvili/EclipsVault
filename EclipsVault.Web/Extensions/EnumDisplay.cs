using EclipsVault.Core.Domain.Enums;
using Microsoft.AspNetCore.Mvc.Rendering;

namespace EclipsVault.Web.Extensions;

/// <summary>
/// Turns the vault's classification enums into the words a person should read. Their names are C#
/// identifiers — <c>TopSecret</c> — so rendering one raw leaks "TopSecret" onto a page that should
/// say "Top Secret". Each value maps to its label here.
///
/// This lives in the Web layer deliberately. Presentation is not the domain's concern, and
/// <c>EclipsVault.Core</c> carries no DataAnnotations by design, so the usual <c>[Display(Name=…)]</c>
/// on the enum is off the table — a Web-layer map keeps the label out of Core. One place for the
/// vocabulary means a badge and a dropdown can never disagree about what a level is called.
/// </summary>
public static class EnumDisplay
{
    public static string ToDisplayName(this ClearanceLevel level) => level switch
    {
        ClearanceLevel.Standard => "Standard",
        ClearanceLevel.Elevated => "Elevated",
        ClearanceLevel.Secret => "Secret",
        ClearanceLevel.TopSecret => "Top Secret",
        _ => level.ToString()
    };

    public static string ToDisplayName(this SensitivityLevel level) => level switch
    {
        SensitivityLevel.Internal => "Internal",
        SensitivityLevel.Confidential => "Confidential",
        SensitivityLevel.Secret => "Secret",
        SensitivityLevel.TopSecret => "Top Secret",
        _ => level.ToString()
    };

    /// <summary>
    /// Clearance options for a <c>&lt;select&gt;</c>, labelled with the display name and valued by
    /// the underlying number — the same value shape <c>Html.GetEnumSelectList&lt;T&gt;</c> produces,
    /// so an <c>asp-for</c> binding still pre-selects the model's current value and round-trips it.
    /// </summary>
    public static IEnumerable<SelectListItem> ClearanceSelectList()
        => Enum.GetValues<ClearanceLevel>()
            .Select(c => new SelectListItem(c.ToDisplayName(), ((int)c).ToString()));

    public static IEnumerable<SelectListItem> SensitivitySelectList()
        => Enum.GetValues<SensitivityLevel>()
            .Select(s => new SelectListItem(s.ToDisplayName(), ((int)s).ToString()));
}
