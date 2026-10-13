using System.Security.Claims;
using EclipsVault.Core.Application.Sessions;
using EclipsVault.Infrastructure.Security;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Controllers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace EclipsVault.Tests.Sessions;

/// <summary>
/// Sign out must end the session on the server, not only forget the cookie in this browser. Before
/// this, a copy of the cookie taken before sign-out (a shared machine, a proxy log, malware) kept
/// working until it expired, and the session stayed on the Signed-in devices list. Revoking the
/// session id is the same tombstone "Sign out all other sessions" uses, so the cookie validator
/// rejects the copy on its next request.
/// </summary>
public class SignOutRevokesSessionTests
{
    private sealed class RecordingAuthentication : IAuthenticationService
    {
        public bool SignedOut { get; private set; }

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            SignedOut = true;
            return Task.CompletedTask;
        }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => throw new NotSupportedException();
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => throw new NotSupportedException();
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => throw new NotSupportedException();
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => throw new NotSupportedException();
    }

    private static (AccountController Controller, RecordingAuthentication Auth) SignedInController(
        InMemorySessionRegistry sessions, params Claim[] claims)
    {
        var auth = new RecordingAuthentication();
        var http = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddSingleton<IAuthenticationService>(auth).BuildServiceProvider(),
            User = new ClaimsPrincipal(new ClaimsIdentity(claims, "test"))
        };

        // Logout touches only the session registry and the authentication service; the other
        // collaborators belong to the sign-in flows and are never reached here.
        var controller = new AccountController(null!, null!, null!, sessions, null!, null!, null!,
            NullLogger<AccountController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = http }
        };
        // RedirectToAction only captures the helper; nothing is routed until the result executes.
        controller.Url = new UrlHelper(new ActionContext(http, new RouteData(), new ActionDescriptor()));
        return (controller, auth);
    }

    [Fact]
    public async Task Signing_out_revokes_the_session_so_a_copied_cookie_is_refused()
    {
        var sessions = new InMemorySessionRegistry(NullLogger<InMemorySessionRegistry>.Instance);
        var user = Guid.NewGuid();
        var sid = Guid.NewGuid();
        await sessions.RecordSeenAsync(new SessionObservation(
            user, sid, "Chrome on macOS", "203.0.113.5", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddHours(1)));
        var (controller, auth) = SignedInController(sessions,
            new Claim(ClaimTypes.NameIdentifier, user.ToString()),
            new Claim(VaultClaimTypes.SessionId, sid.ToString()));

        await controller.Logout(CancellationToken.None);

        Assert.True(auth.SignedOut);
        Assert.True(await sessions.IsRevokedAsync(user, sid));
        Assert.Empty(await sessions.ListAsync(user));
    }

    [Fact]
    public async Task A_principal_without_a_session_id_is_still_signed_out()
    {
        var sessions = new InMemorySessionRegistry(NullLogger<InMemorySessionRegistry>.Instance);
        var (controller, auth) = SignedInController(sessions,
            new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()));

        var result = await controller.Logout(CancellationToken.None);

        Assert.True(auth.SignedOut);
        Assert.IsType<RedirectToActionResult>(result);
    }
}
