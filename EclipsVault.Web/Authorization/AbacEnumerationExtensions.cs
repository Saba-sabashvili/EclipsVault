using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace EclipsVault.Web.Authorization;

/// <summary>
/// Narrows a list to the rows the caller is allowed to know exist.
///
/// This runs each row through <see cref="SecretAccessHandler"/> — the same handler, requirement and
/// rule engine that gate opening one — rather than re-deriving "who may see this?" from claims at
/// the two call sites. A list filter written a second time is a copy of the access policy that
/// nothing keeps in step, and its failure mode is silent: it goes on showing names long after the
/// enforcement path stopped allowing the reads.
/// </summary>
public static class AbacEnumerationExtensions
{
    public static async Task<List<T>> VisibleToAsync<T>(
        this IAuthorizationService authorization,
        ClaimsPrincipal user,
        IEnumerable<T> resources)
        where T : IAbacResource
    {
        var requirement = new SecretAccessRequirement(AccessKind.Enumerate);

        var visible = new List<T>();
        foreach (var resource in resources)
        {
            if ((await authorization.AuthorizeAsync(user, resource, requirement)).Succeeded)
            {
                visible.Add(resource);
            }
        }

        return visible;
    }
}
