using EclipsVault.Web.Middleware;
using Microsoft.AspNetCore.Mvc.Core.Infrastructure;
using Microsoft.AspNetCore.Mvc.Filters;

namespace EclipsVault.Web.Authorization;

/// <summary>
/// Turns a failed antiforgery check on the UI API into its Problem Details answer (ADR-0006). MVC
/// otherwise answers a bare 400, which <c>[ApiController]</c> would dress as a generic problem with
/// no code. It always runs, because the check short-circuits as an authorization filter, and it runs
/// before <c>[ApiController]</c>'s own client-error filter. Every other path keeps the bare 400.
/// </summary>
public sealed class UiApiAntiforgeryFilter : IAlwaysRunResultFilter, IOrderedFilter
{
    // [ApiController]'s ClientErrorResultFilter runs at -2000 and would replace the result first.
    public int Order => -3000;

    public void OnResultExecuting(ResultExecutingContext context)
    {
        if (context.Result is IAntiforgeryValidationFailedResult && UiApiProblem.IsUiApi(context.HttpContext.Request))
        {
            context.Result = UiApiProblem.AntiforgeryRejected();
        }
    }

    public void OnResultExecuted(ResultExecutedContext context)
    {
    }
}
