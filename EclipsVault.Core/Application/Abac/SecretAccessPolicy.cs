using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.Abac;

/// <summary>
/// The pure ABAC rule engine. Maps subject claims against resource attributes and
/// runtime context. No framework types, no I/O — trivially unit-testable.
/// </summary>
public static class SecretAccessPolicy
{
    /// <param name="kind">
    /// Whether the caller wants the value or only to know the resource exists. Enumeration runs the
    /// same rules — a name discloses what exists and what it is worth — with the single exception
    /// noted at rule 6.
    /// </param>
    public static AccessDecision Evaluate(
        SubjectAttributes subject,
        ResourceAttributes resource,
        RequestContext context,
        ApiKeyScope? scope = null,
        AccessKind kind = AccessKind.Read)
    {
        var reasons = new List<string>();

        // Rule 1: clearance must dominate the secret's sensitivity classification.
        if ((int)subject.Clearance < (int)resource.Sensitivity)
        {
            reasons.Add($"Clearance '{subject.Clearance}' is below required sensitivity '{resource.Sensitivity}'.");
        }

        // Rule 2: project assignment must match — unless the subject holds TopSecret
        // clearance, or has been explicitly granted access to this specific secret.
        // A grant crosses the project boundary only; the clearance rule above still holds.
        if (subject.Clearance != ClearanceLevel.TopSecret &&
            !context.IsExplicitlyGranted &&
            !string.Equals(subject.ProjectKey, resource.ProjectKey, StringComparison.OrdinalIgnoreCase))
        {
            reasons.Add($"Subject project '{subject.ProjectKey}' does not match resource project '{resource.ProjectKey}'.");
        }

        // Rule 3: production secrets are only reachable inside the configured access window.
        if (resource.Environment == SecretEnvironment.Production && !context.IsWithinProductionWindow)
        {
            reasons.Add("Production secrets are outside the permitted access time window.");
        }

        // Rule 4: anything above Internal must originate from a trusted network range.
        if (resource.Sensitivity >= SensitivityLevel.Confidential && !context.IsFromTrustedNetwork)
        {
            reasons.Add($"Source address '{context.SourceIp ?? "unknown"}' is outside the trusted network ranges.");
        }

        // Rules 5–6: per-key scope. These only ever add denials, so a scoped API key can
        // reach a strict subset of what its service account could — never more.
        if (scope is not null)
        {
            // Rule 5: a project-scoped key is pinned to one project, even a TopSecret account's.
            if (!string.IsNullOrEmpty(scope.ProjectScope) &&
                !string.Equals(scope.ProjectScope, resource.ProjectKey, StringComparison.OrdinalIgnoreCase))
            {
                reasons.Add($"This API key is scoped to project '{scope.ProjectScope}'.");
            }

            // Rule 6: a metadata-only key may enumerate secrets but never read a value. This is the
            // one rule enumeration drops — dropping it is what "metadata-only" means.
            if (scope.MetadataOnly && kind == AccessKind.Read)
            {
                reasons.Add("This API key is limited to metadata only; it cannot read secret values.");
            }
        }

        return reasons.Count == 0 ? AccessDecision.Allow() : AccessDecision.Deny(reasons);
    }
}
