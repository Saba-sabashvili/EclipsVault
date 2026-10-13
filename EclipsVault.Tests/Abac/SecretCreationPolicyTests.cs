using EclipsVault.Core.Application.Abac;
using EclipsVault.Core.Domain.Enums;
using Xunit;

namespace EclipsVault.Tests.Abac;

/// <summary>
/// Creating a secret is an access decision, and it used to be an unguarded one: the create form
/// checked only that the caller was not classifying above their own clearance, then took
/// <c>ProjectKey</c> straight from the posted form. The read path treats project as a hard boundary,
/// so a user could write a credential of their choosing into another team's namespace, where it
/// showed up in that team's list indistinguishably from a real one and got deployed.
///
/// This pins the write side to the same two rules the read side enforces — clearance dominance, and
/// project match with the documented TopSecret exception.
/// </summary>
public class SecretCreationPolicyTests
{
    private static SubjectAttributes Subject(
        ClearanceLevel clearance = ClearanceLevel.Secret, string project = "PHOENIX") => new(clearance, project);

    [Fact]
    public void Allows_creating_in_your_own_project_at_or_below_your_clearance()
    {
        var decision = SecretCreationPolicy.Evaluate(
            Subject(), requestedProjectKey: "PHOENIX", requestedSensitivity: SensitivityLevel.Confidential);

        Assert.True(decision.IsAllowed);
        Assert.Empty(decision.DenialReasons);
    }

    [Fact]
    public void Denies_planting_a_secret_in_a_project_you_are_not_assigned_to()
    {
        var decision = SecretCreationPolicy.Evaluate(
            Subject(project: "WEB"), requestedProjectKey: "FINANCE", requestedSensitivity: SensitivityLevel.Internal);

        Assert.False(decision.IsAllowed);
        Assert.Contains(decision.DenialReasons, r => r.Contains("FINANCE"));
    }

    [Fact]
    public void Denies_classifying_a_new_secret_above_your_own_clearance()
    {
        var decision = SecretCreationPolicy.Evaluate(
            Subject(clearance: ClearanceLevel.Standard),
            requestedProjectKey: "PHOENIX",
            requestedSensitivity: SensitivityLevel.TopSecret);

        Assert.False(decision.IsAllowed);
        Assert.Contains(decision.DenialReasons, r => r.Contains("Clearance"));
    }

    [Fact]
    public void Allows_top_secret_clearance_to_create_across_projects_as_the_read_rules_do()
    {
        var decision = SecretCreationPolicy.Evaluate(
            Subject(clearance: ClearanceLevel.TopSecret, project: "WEB"),
            requestedProjectKey: "FINANCE",
            requestedSensitivity: SensitivityLevel.Confidential);

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public void Matches_the_project_case_insensitively_because_the_key_is_upper_cased_on_write()
    {
        var decision = SecretCreationPolicy.Evaluate(
            Subject(project: "phoenix"), requestedProjectKey: "PHOENIX", requestedSensitivity: SensitivityLevel.Internal);

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public void Denies_a_blank_project_rather_than_treating_it_as_a_match()
    {
        var decision = SecretCreationPolicy.Evaluate(
            Subject(project: "WEB"), requestedProjectKey: "   ", requestedSensitivity: SensitivityLevel.Internal);

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public void Denies_a_blank_project_even_at_top_secret_clearance()
    {
        // TopSecret is exempt from having to *match* a project, never from having one: a secret with
        // no project sits outside the boundary the read rules are expressed in.
        var decision = SecretCreationPolicy.Evaluate(
            Subject(clearance: ClearanceLevel.TopSecret, project: "WEB"),
            requestedProjectKey: "",
            requestedSensitivity: SensitivityLevel.Internal);

        Assert.False(decision.IsAllowed);
    }
}
