using System.Security.Claims;
using EclipsVault.Core.Domain.Enums;
using Microsoft.AspNetCore.Authorization;

namespace EclipsVault.Web.Authorization;

/// <summary>
/// Resource-based ABAC handler. Extracts subject attributes from claims, reads the environmental
/// context (production window, network trust) from the shared <see cref="IAccessContextProvider"/>
/// — the same snapshot the self-service "My access" page shows — resolves any explicit grant, and
/// delegates the actual decision to the pure rule engine in Core.
/// </summary>
public sealed class SecretAccessHandler : AuthorizationHandler<SecretAccessRequirement, SecretDetailsDto>
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IAccessContextProvider _accessContext;
    private readonly ISecretGrantService _grants;
    private readonly TimeProvider _clock;
    private readonly ILogger<SecretAccessHandler> _logger;

    public SecretAccessHandler(
        IHttpContextAccessor httpContextAccessor,
        IAccessContextProvider accessContext,
        ISecretGrantService grants,
        TimeProvider clock,
        ILogger<SecretAccessHandler> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _accessContext = accessContext;
        _grants = grants;
        _clock = clock;
        _logger = logger;
    }

    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        SecretAccessRequirement requirement,
        SecretDetailsDto resource)
    {
        var clearanceClaim = context.User.FindFirstValue(VaultClaimTypes.Clearance);
        var projectClaim = context.User.FindFirstValue(VaultClaimTypes.Project);

        if (!int.TryParse(clearanceClaim, out var clearanceValue) || projectClaim is null)
        {
            _logger.LogWarning("ABAC denied secret {SecretId}: principal is missing vault attribute claims", resource.Id);
            context.Fail(new AuthorizationFailureReason(this,
                "Your session is missing the vault attribute claims needed to evaluate access. Sign out and back in."));
            return;
        }

        var subject = new SubjectAttributes((ClearanceLevel)clearanceValue, projectClaim);
        var resourceAttributes = new ResourceAttributes(resource.Environment, resource.Sensitivity, resource.ProjectKey);

        var ct = _httpContextAccessor.HttpContext?.RequestAborted ?? CancellationToken.None;

        // Shared with the "My access" page: network trust + production-window state.
        var accessContext = await _accessContext.CurrentAsync(ct);

        // An explicit grant lets a user outside the secret's project reach it.
        var isGranted = false;
        if (Guid.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
        {
            isGranted = await _grants.HasActiveGrantAsync(userId, resource.Id, ct);
        }

        var requestContext = new RequestContext(
            _clock.GetUtcNow(),
            accessContext.SourceIp?.ToString(),
            accessContext.IsWithinProductionWindow,
            accessContext.IsTrustedNetwork,
            isGranted);

        // Per-key scope (present only for scoped API keys; interactive users carry none).
        var scopeProject = context.User.FindFirstValue(VaultClaimTypes.ScopeProject);
        var metadataOnly = context.User.FindFirstValue(VaultClaimTypes.ScopeMetadataOnly) == "true";
        ApiKeyScope? scope = scopeProject is not null || metadataOnly
            ? new ApiKeyScope(scopeProject, metadataOnly)
            : null;

        var decision = SecretAccessPolicy.Evaluate(subject, resourceAttributes, requestContext, scope);
        if (decision.IsAllowed)
        {
            context.Succeed(requirement);
        }
        else
        {
            _logger.LogWarning(
                "ABAC denied access to secret {SecretId} ({SecretName}) for user {UserName} from {SourceIp}: {DenialReasons}",
                resource.Id, resource.Name, context.User.Identity?.Name, requestContext.SourceIp, decision.DenialReasons);
            foreach (var reason in decision.DenialReasons)
            {
                context.Fail(new AuthorizationFailureReason(this, reason));
            }
        }
    }
}
