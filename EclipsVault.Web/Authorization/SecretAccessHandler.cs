using System.Security.Claims;
using EclipsVault.Core.Domain.Enums;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace EclipsVault.Web.Authorization;

/// <summary>
/// Resource-based ABAC handler. Extracts subject attributes from claims, computes
/// the environmental context (time window, network trust from static configuration
/// plus the runtime-managed trusted networks), and delegates the actual decision to
/// the pure rule engine in Core.
/// </summary>
public sealed class SecretAccessHandler : AuthorizationHandler<SecretAccessRequirement, SecretDetailsDto>
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ITrustedNetworkService _trustedNetworks;
    private readonly ISecretGrantService _grants;
    private readonly AbacOptions _options;
    private readonly TimeZoneInfo? _windowZone;
    private readonly TimeProvider _clock;
    private readonly ILogger<SecretAccessHandler> _logger;

    public SecretAccessHandler(
        IHttpContextAccessor httpContextAccessor,
        ITrustedNetworkService trustedNetworks,
        ISecretGrantService grants,
        IOptions<AbacOptions> options,
        TimeProvider clock,
        ILogger<SecretAccessHandler> logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _trustedNetworks = trustedNetworks;
        _grants = grants;
        _options = options.Value;
        _windowZone = ResolveWindowZone(_options.TimeZoneId, logger);
        _clock = clock;
        _logger = logger;
    }

    private static TimeZoneInfo? ResolveWindowZone(string? timeZoneId, ILogger logger)
    {
        if (string.IsNullOrWhiteSpace(timeZoneId))
        {
            return null; // interpret the window in UTC (historical behaviour)
        }

        try
        {
            return TimeZoneInfo.FindSystemTimeZoneById(timeZoneId);
        }
        catch (Exception ex) when (ex is TimeZoneNotFoundException or InvalidTimeZoneException)
        {
            logger.LogWarning(ex, "Abac:TimeZoneId '{TimeZoneId}' could not be resolved; falling back to UTC for the production window", timeZoneId);
            return null;
        }
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

        var httpContext = _httpContextAccessor.HttpContext;
        var now = _clock.GetUtcNow();
        var sourceIp = httpContext?.Connection.RemoteIpAddress;

        var ct = httpContext?.RequestAborted ?? CancellationToken.None;

        var isTrusted = NetworkRules.IsInAnyCidr(sourceIp, _options.TrustedIpCidrs);
        if (!isTrusted && sourceIp is not null)
        {
            isTrusted = await _trustedNetworks.IsTrustedAsync(sourceIp, ct);
        }

        // An explicit grant lets a user outside the secret's project reach it.
        var isGranted = false;
        if (Guid.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
        {
            isGranted = await _grants.HasActiveGrantAsync(userId, resource.Id, ct);
        }

        var requestContext = new RequestContext(
            now,
            sourceIp?.ToString(),
            IsWithinProductionWindow(now),
            isTrusted,
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

    private bool IsWithinProductionWindow(DateTimeOffset nowUtc)
    {
        var hour = _windowZone is null
            ? nowUtc.UtcDateTime.Hour
            : TimeZoneInfo.ConvertTime(nowUtc, _windowZone).Hour;
        return hour >= _options.ProductionWindowStartUtcHour
               && hour < _options.ProductionWindowEndUtcHour;
    }
}
