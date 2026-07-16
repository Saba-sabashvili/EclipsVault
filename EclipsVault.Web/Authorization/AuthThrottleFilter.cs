using EclipsVault.Core.Application.Networks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace EclipsVault.Web.Authorization;

/// <summary>
/// Applies <see cref="IAuthThrottle"/> to every action on the controller it decorates.
///
/// This replaces ASP.NET's built-in rate limiter, whose partitions are per-process and therefore
/// grant each replica its own budget. It is a filter rather than middleware so the throttled
/// surface stays declared on the controller it protects, and async so the budget can live in Redis.
/// </summary>
public sealed class AuthThrottleFilter : IAsyncActionFilter
{
    private readonly IAuthThrottle _throttle;
    private readonly ILogger<AuthThrottleFilter> _logger;

    public AuthThrottleFilter(IAuthThrottle throttle, ILogger<AuthThrottleFilter> logger)
    {
        _throttle = throttle;
        _logger = logger;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        // Normalised so an IPv4-mapped IPv6 caller shares one budget with its plain IPv4 form
        // rather than getting a second one for free.
        var address = context.HttpContext.Connection.RemoteIpAddress;
        var partition = address is null ? "unknown" : NetworkRules.Normalize(address).ToString();

        if (await _throttle.TryAcquireAsync(partition, context.HttpContext.RequestAborted))
        {
            await next();
            return;
        }

        _logger.LogWarning(
            "Authentication request from {SourceIp} refused: over the rate budget for this window", partition);
        context.Result = new StatusCodeResult(StatusCodes.Status429TooManyRequests);
    }
}
