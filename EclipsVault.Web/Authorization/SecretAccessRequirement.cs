using Microsoft.AspNetCore.Authorization;

namespace EclipsVault.Web.Authorization;

/// <summary>
/// Requirement evaluated by <see cref="SecretAccessHandler"/> against an <see cref="IAbacResource"/>.
/// <see cref="Kind"/> says whether the caller wants the value or only to know the resource exists;
/// both run the same rules in Core.
/// </summary>
public sealed class SecretAccessRequirement : IAuthorizationRequirement
{
    public SecretAccessRequirement(AccessKind kind = AccessKind.Read) => Kind = kind;

    public AccessKind Kind { get; }
}
