using Microsoft.AspNetCore.Authorization;

namespace EclipsVault.Web.Authorization;

/// <summary>Marker requirement evaluated by <see cref="SecretAccessHandler"/> against a SecretDetailsDto resource.</summary>
public sealed class SecretAccessRequirement : IAuthorizationRequirement
{
}
