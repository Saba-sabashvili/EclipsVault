using System.Reflection;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Controllers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Xunit;

namespace EclipsVault.Tests.Web;

/// <summary>
/// Every endpoint in this vault is either behind a session or deliberately open, and which one it is
/// must never be an accident.
///
/// <para>
/// Before these tests, twelve of the twenty controllers — including the ones serving secrets, the
/// audit trail, and the personal-data export — carried no authorization attribute at all. They were
/// protected, but only by the default-deny fallback policy configured in <c>Program.cs</c>: three
/// lines, in a different file, that no controller referenced. Deleting or reordering them during a
/// refactor would have exposed all twelve to anonymous callers, and every test in this suite would
/// still have passed, because nothing anywhere asserted the relationship.
/// </para>
///
/// <para>
/// So the protection is now stated twice — <c>[Authorize]</c> on the controllers themselves, plus
/// the fallback policy as a backstop for anything new that forgets — and the anonymous surface is
/// pinned below by name. <b>A new <c>[AllowAnonymous]</c> fails this test until someone adds it to
/// the list</b>, which is the point: opening an endpoint to the internet should cost a deliberate
/// edit to a file that says so, not a one-line attribute nobody reviews.
/// </para>
/// </summary>
public class AuthorizationSurfaceTests
{
    /// <summary>
    /// The complete set of actions reachable without a session, as <c>Controller.Action</c>.
    /// Every one of them by definition runs before a session exists: the password sign-in, the
    /// passkey ceremony's two legs, the SSO redirect and its callback from the identity provider,
    /// break-glass recovery for a locked-out administrator, the landing page, and the error page.
    /// Adding a name here is a decision that an unauthenticated stranger may reach it.
    /// </summary>
    private static readonly string[] IntentionallyAnonymous =
    [
        "AccountController.ExternalCallback",
        "AccountController.ExternalLogin",
        "AccountController.Login",
        "AccountController.PasskeyLoginBegin",
        "AccountController.PasskeyLoginComplete",
        "AccountController.Recover",
        "HomeController.Error",
        "HomeController.Index",
    ];

    /// <summary>
    /// The only actions allowed to accept a principal that has passed the password factor but not a
    /// second one — the three second-factor screens themselves, each a GET/POST pair.
    /// </summary>
    private static readonly string[] MayAcceptPendingMfa =
    [
        "AccountController.EnrollTotp",
        "AccountController.RecoveryCode",
        "AccountController.Totp",
    ];

    [Fact]
    public void EveryAction_IsEitherBehindAuthorizeOrDeliberatelyAnonymous()
    {
        var unprotected = Actions()
            .Where(action => !IsAnonymous(action) && !IsAuthorized(action))
            .Select(Name)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        Assert.True(unprotected.Count == 0,
            "These actions are reachable without [Authorize] and without being declared anonymous. " +
            "They would be relying entirely on the fallback policy in Program.cs:\n  " +
            string.Join("\n  ", unprotected));
    }

    [Fact]
    public void AnonymousSurface_IsExactlyTheSetWeIntended()
    {
        var actual = Actions()
            .Where(IsAnonymous)
            .Select(Name)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        var expected = IntentionallyAnonymous.OrderBy(name => name, StringComparer.Ordinal).ToList();

        var added = actual.Except(expected, StringComparer.Ordinal).ToList();
        var removed = expected.Except(actual, StringComparer.Ordinal).ToList();

        Assert.True(added.Count == 0,
            "These actions were opened to anonymous callers without being listed as intentional:\n  " +
            string.Join("\n  ", added) +
            "\n\nIf that is deliberate, add them to IntentionallyAnonymous and say why in review.");

        Assert.True(removed.Count == 0,
            "These actions are listed as intentionally anonymous but no longer are. Remove them from " +
            "IntentionallyAnonymous so the list keeps meaning something:\n  " + string.Join("\n  ", removed));
    }

    /// <summary>
    /// The tests above pin that every action carries <c>[Authorize]</c>, but not <em>which</em>
    /// authorization — and they pass just as happily for a weak one. Moving a protected action to
    /// <c>[Authorize(AuthenticationSchemes = AuthSchemes.MfaPending)]</c> would look like hardening in
    /// a diff while actually admitting a half-authenticated caller: someone who has typed a correct
    /// password and nothing else. That principal carries only a name and an id
    /// (<c>VaultClaimsFactory.CreatePendingMfaPrincipal</c>), so it holds no clearance and no project,
    /// and the six-minute pending cookie is a separate scheme from the session precisely so it cannot
    /// reach the vault. This pins the boundary by name: the second-factor screens may accept it, and
    /// nothing else may.
    /// </summary>
    [Fact]
    public void OnlyTheSecondFactorScreens_AcceptAHalfAuthenticatedPrincipal()
    {
        var actual = Actions()
            .Where(DeclaresPendingMfaScheme)
            .Select(Name)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToList();

        var expected = MayAcceptPendingMfa.OrderBy(name => name, StringComparer.Ordinal).ToList();

        var added = actual.Except(expected, StringComparer.Ordinal).ToList();
        var removed = expected.Except(actual, StringComparer.Ordinal).ToList();

        Assert.True(added.Count == 0,
            "These actions accept the pre-MFA scheme, so a caller who has only typed a password can " +
            "reach them:\n  " + string.Join("\n  ", added) +
            "\n\nIf that is genuinely intended, add them to MayAcceptPendingMfa and justify it in review.");

        Assert.True(removed.Count == 0,
            "These are listed as accepting the pre-MFA scheme but no longer do. Remove them from " +
            "MayAcceptPendingMfa so the list keeps meaning something:\n  " + string.Join("\n  ", removed));
    }

    /// <summary>
    /// The backstop itself: <c>VaultController</c> carries the requirement that ten controllers
    /// inherit, so losing it would quietly unprotect all of them at once.
    /// </summary>
    [Fact]
    public void VaultControllerBase_CarriesAuthorize()
    {
        var baseController = ControllerTypes()
            .Single(type => type.Name == "VaultController");

        Assert.NotEmpty(baseController.GetCustomAttributes<AuthorizeAttribute>(inherit: true));
    }

    private static string Name(MethodInfo action)
        => $"{action.DeclaringType!.Name}.{action.Name}";

    private static bool IsAnonymous(MethodInfo action)
        => action.GetCustomAttributes<AllowAnonymousAttribute>(inherit: true).Any()
           || action.DeclaringType!.GetCustomAttributes<AllowAnonymousAttribute>(inherit: true).Any();

    /// <summary>
    /// Whether any <c>[Authorize]</c> on the action or its controller names the pre-MFA scheme.
    /// <c>AuthenticationSchemes</c> is a comma-separated string, so it is split rather than compared.
    /// </summary>
    private static bool DeclaresPendingMfaScheme(MethodInfo action)
        => action.GetCustomAttributes<AuthorizeAttribute>(inherit: true)
            .Concat(action.DeclaringType!.GetCustomAttributes<AuthorizeAttribute>(inherit: true))
            .Select(attribute => attribute.AuthenticationSchemes)
            .Where(schemes => !string.IsNullOrWhiteSpace(schemes))
            .SelectMany(schemes => schemes!.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Any(scheme => string.Equals(scheme, AuthSchemes.MfaPending, StringComparison.Ordinal));

    private static bool IsAuthorized(MethodInfo action)
        => action.GetCustomAttributes<AuthorizeAttribute>(inherit: true).Any()
           || action.DeclaringType!.GetCustomAttributes<AuthorizeAttribute>(inherit: true).Any();

    private static IEnumerable<MethodInfo> Actions()
        => ControllerTypes()
            .Where(type => !type.IsAbstract)
            .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
            .Where(method => !method.IsSpecialName)
            .Where(method => !method.GetCustomAttributes<NonActionAttribute>(inherit: true).Any());

    private static IEnumerable<Type> ControllerTypes()
        => typeof(VaultController).Assembly.GetTypes()
            .Where(type => typeof(ControllerBase).IsAssignableFrom(type))
            .Where(type => type != typeof(Controller) && type != typeof(ControllerBase));
}
