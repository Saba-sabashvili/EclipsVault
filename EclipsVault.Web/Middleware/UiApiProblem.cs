using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Middleware;

/// <summary>
/// The UI API's failure contract (ADR-0006). Under <c>/api/ui/</c> a failure is an RFC 9457
/// Problem Details response with a stable <c>code</c> the Angular UI acts on, never a redirect to
/// an HTML page. Callers pass fixed text, never an exception's message, so no exception detail can
/// reach the body.
/// </summary>
public static class UiApiProblem
{
    private static readonly PathString UiApiPath = new("/api/ui");

    /// <summary>Whether the request is for the UI API. The Legacy UI and the Public API keep their own answers.</summary>
    public static bool IsUiApi(HttpRequest request) => request.Path.StartsWithSegments(UiApiPath);

    public static Task WriteAsync(HttpContext context, int status, string code, string title, string? detail = null)
    {
        context.Response.StatusCode = status;
        var problem = new ProblemDetails { Status = status, Title = title, Detail = detail, Extensions = { ["code"] = code } };
        return context.Response.WriteAsJsonAsync(problem, options: null, contentType: "application/problem+json");
    }

    /// <summary>Nothing there, or nothing this session may know is there: the two answer alike.</summary>
    public static Task NotFoundAsync(HttpContext context)
        => WriteAsync(context, StatusCodes.Status404NotFound, NotFoundCode, NotFoundTitle);

    public const string NotFoundCode = "not_found";

    public const string NotFoundTitle = "Not found.";

    /// <summary>No session, or a revoked one: the Angular UI sends the browser to sign-in.</summary>
    public static Task UnauthenticatedAsync(HttpContext context)
        => WriteAsync(context, StatusCodes.Status401Unauthorized, "unauthenticated", "Sign in to continue.");

    /// <summary><see cref="UnauthenticatedAsync"/> as an action result, for a UI API action that finds the session unusable.</summary>
    public static ActionResult Unauthenticated() => new Result(UnauthenticatedAsync);

    /// <summary>A session that may not make this request.</summary>
    public static Task ForbiddenAsync(HttpContext context)
        => WriteAsync(context, StatusCodes.Status403Forbidden, "forbidden", "You are not allowed to do this.");

    private sealed class Result(Func<HttpContext, Task> write) : ActionResult
    {
        public override Task ExecuteResultAsync(ActionContext context) => write(context.HttpContext);
    }
}
