using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Abac;

/// <summary>
/// Whether a caller may create a secret carrying the attributes they asked for.
///
/// <para><b>Why the write side needs its own rules.</b> <see cref="SecretAccessPolicy"/> answers
/// "may this subject reach that resource?", which needs a resource to exist. Creation has no
/// resource yet — the caller proposes its attributes — so the question is the inverse: are these
/// attributes ones this subject is entitled to *assign*? Leaving that unasked made the project key a
/// free-text form field, and the read path treats project as a boundary, so a user could write a
/// credential into a team's namespace that they could not themselves open.</para>
///
/// <para>Only the two attribute rules apply. Rule 3 (production window) and rule 4 (trusted network)
/// govern *reaching* a value and give the creator nothing — a Production label makes a secret harder
/// to read, not easier — so requiring them here would block legitimate work without closing anything.
/// The explicit-grant exception cannot apply either: there is no secret yet to have been granted.</para>
/// </summary>
public static class SecretCreationPolicy
{
    public static AccessDecision Evaluate(
        SubjectAttributes subject, string requestedProjectKey, SensitivityLevel requestedSensitivity)
    {
        var reasons = new List<string>();

        // Mirrors rule 1: you cannot classify a secret above the clearance you hold.
        if ((int)subject.Clearance < (int)requestedSensitivity)
        {
            reasons.Add($"Clearance '{subject.Clearance}' is below the requested sensitivity '{requestedSensitivity}'.");
        }

        // Every secret must carry a project. TopSecret clearance is exempt from having to *match* one
        // (rule 2's documented exception), never from having one at all: a secret with no project
        // sits outside the boundary the read rules are expressed in, so it belongs to no one.
        if (string.IsNullOrWhiteSpace(requestedProjectKey))
        {
            reasons.Add("A secret must be created in a project.");
        }
        else if (subject.Clearance != ClearanceLevel.TopSecret &&
                 !string.Equals(subject.ProjectKey?.Trim(), requestedProjectKey.Trim(), StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add(
                $"Subject project '{subject.ProjectKey}' does not permit creating a secret in project '{requestedProjectKey.Trim()}'.");
        }

        return reasons.Count == 0 ? AccessDecision.Allow() : AccessDecision.Deny(reasons);
    }
}
