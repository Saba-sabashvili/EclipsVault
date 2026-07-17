using System.Security.Claims;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Web.Extensions;
using Microsoft.AspNetCore.Authorization;

namespace EclipsVault.Web.Authorization;

/// <summary>
/// Resource-based ABAC handler. Extracts subject attributes from claims, reads the environmental
/// context (production window, network trust) from the shared <see cref="IAccessContextProvider"/>
/// — the same snapshot the self-service "My access" page shows — resolves any explicit grant, and
/// delegates the actual decision to the pure rule engine in Core.
///
/// It gates any <see cref="IAbacResource"/>, not just a stored secret: a dynamic-secret role carries
/// the same three attributes, so issuing a credential is decided by this one handler and one rule
/// engine rather than a parallel copy that could drift from it.
/// </summary>
public sealed class SecretAccessHandler : AuthorizationHandler<SecretAccessRequirement, IAbacResource>
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
        IAbacResource resource)
    {
        var projectClaim = context.User.FindFirstValue(VaultClaimTypes.Project);

        if (context.User.GetClearanceOrNull() is not { } clearance || projectClaim is null)
        {
            _logger.LogWarning("ABAC denied secret {SecretId}: principal is missing vault attribute claims", resource.Id);
            context.Fail(new AuthorizationFailureReason(this,
                "Your session is missing the vault attribute claims needed to evaluate access. Sign out and back in."));
            return;
        }

        var subject = new SubjectAttributes(clearance, projectClaim);
        var resourceAttributes = new ResourceAttributes(resource.Environment, resource.Sensitivity, resource.ProjectKey);

        var ct = _httpContextAccessor.HttpContext?.RequestAborted ?? CancellationToken.None;

        // Shared with the "My access" page: network trust + production-window state.
        var accessContext = await _accessContext.CurrentAsync(ct);

        // Per-key scope (present only for scoped API keys; interactive users carry none).
        var scopeProject = context.User.FindFirstValue(VaultClaimTypes.ScopeProject);
        var metadataOnly = context.User.FindFirstValue(VaultClaimTypes.ScopeMetadataOnly) == "true";
        ApiKeyScope? scope = scopeProject is not null || metadataOnly
            ? new ApiKeyScope(scopeProject, metadataOnly)
            : null;

        var requestContext = new RequestContext(
            _clock.GetUtcNow(),
            accessContext.SourceIp?.ToString(),
            accessContext.IsWithinProductionWindow,
            accessContext.IsTrustedNetwork,
            IsExplicitlyGranted: false);

        // Decide without a grant first. An explicit grant only ever *relaxes* the project rule — it
        // can turn a deny into an allow, never the reverse — so when the ungranted decision already
        // allows, a grant cannot change it and the per-secret grant lookup is pure waste. On a list
        // page that lookup was the whole cost: every row a user could already see (their own project,
        // or any row at all for a TopSecret account) spent one database round-trip to ask about a
        // grant that could not have mattered — an N+1 across the entire visible list.
        var decision = SecretAccessPolicy.Evaluate(subject, resourceAttributes, requestContext, scope, requirement.Kind);

        // Denied ungranted, but a grant might rescue it. Rather than reproduce here *which* denials a
        // grant can lift — a second copy of rule 2 that would silently drift from the engine — ask the
        // engine itself: would the very same inputs allow if a grant were present? Only when they
        // would is the grant decisive, and only then is it worth the query. Grants are issued against
        // stored secrets only (a dynamic role has nothing to share), hence the IGrantableResource gate.
        if (!decision.IsAllowed
            && resource is IGrantableResource
            && context.User.GetUserIdOrNull() is { } userId
            && SecretAccessPolicy.Evaluate(
                    subject, resourceAttributes, requestContext with { IsExplicitlyGranted = true }, scope, requirement.Kind)
                .IsAllowed
            && await _grants.HasActiveGrantAsync(userId, resource.Id, ct))
        {
            decision = AccessDecision.Allow();
        }

        if (decision.IsAllowed)
        {
            context.Succeed(requirement);
            return;
        }

        // A denied read is someone reaching for a specific secret they cannot have, which is worth
        // knowing about. A denied enumeration is the list page doing its job once per hidden row —
        // logging those at Warning would bury the reads under routine noise.
        if (requirement.Kind == AccessKind.Read)
        {
            _logger.LogWarning(
                "ABAC denied access to secret {SecretId} ({SecretName}) for user {UserName} from {SourceIp}: {DenialReasons}",
                resource.Id, resource.Name, context.User.Identity?.Name, requestContext.SourceIp, decision.DenialReasons);
        }

        foreach (var reason in decision.DenialReasons)
        {
            context.Fail(new AuthorizationFailureReason(this, reason));
        }
    }
}
