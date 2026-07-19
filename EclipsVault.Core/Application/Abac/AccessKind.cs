namespace EclipsVault.Core.Application.Abac;

/// <summary>
/// What the caller is trying to do with a resource, which decides how much of the rule set applies.
///
/// The two are separate because a name is not nothing: "Production_AWS_Root_Key" tells an attacker
/// what exists, where, and what it is worth, before a single value is read. Knowing a secret exists
/// is therefore an access decision in its own right and runs the same rules — a list is not a
/// second, laxer copy of the policy.
/// </summary>
public enum AccessKind
{
    /// <summary>
    /// Learning that the resource exists, and its attributes. Everything applies except the
    /// metadata-only key scope, whose entire definition is that it may enumerate but not read.
    /// </summary>
    Enumerate = 1,

    /// <summary>Reading the resource's value. The full rule set applies.</summary>
    Read = 2
}
