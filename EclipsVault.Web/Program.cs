using System.Security.Claims;
using System.Threading.RateLimiting;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Infrastructure;
using EclipsVault.Infrastructure.Logging;
using EclipsVault.Infrastructure.Persistence;
using EclipsVault.Infrastructure.Workers;
using EclipsVault.Web.Authentication;
using EclipsVault.Web.Authorization;
using EclipsVault.Web.Middleware;
using EclipsVault.Web.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Mvc;
using Serilog;

Log.Logger = SerilogSetup.CreateBootstrapLogger();

try
{
    Log.Information("Starting EclipsVault");

    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseEclipsVaultSerilog();
    builder.WebHost.ConfigureKestrel(kestrel => kestrel.AddServerHeader = false);

    // ---- Composition root -------------------------------------------------------

    builder.Services.AddEclipsVaultInfrastructure(builder.Configuration);
    builder.Services.AddHostedService<SecretLifecycleWorker>();

    builder.Services.AddHttpContextAccessor();
    builder.Services.AddScoped<IAuditContext, HttpAuditContext>();

    // ABAC: policy-based authorization with a resource-aware handler.
    builder.Services.Configure<AbacOptions>(builder.Configuration.GetSection(AbacOptions.SectionName));
    builder.Services.AddScoped<IAccessContextProvider, AccessContextProvider>();
    builder.Services.AddScoped<IAuthorizationHandler, SecretAccessHandler>();

    builder.Services
        .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.Cookie.Name = "EclipsVault.Session";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.LoginPath = "/Account/Login";
            options.AccessDeniedPath = "/Account/Denied";
            options.ExpireTimeSpan = SessionDefaults.InteractiveLifetime;
            options.SlidingExpiration = true;
            options.Events = new CookieAuthenticationEvents
            {
                // Server-side kill switch: sessions revoked by the intrusion response
                // die on their next request, regardless of cookie lifetime.
                OnValidatePrincipal = async context =>
                {
                    var revocation = context.HttpContext.RequestServices.GetRequiredService<ISessionRevocationService>();

                    var userIdClaim = context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
                    var authTimeClaim = context.Principal?.FindFirstValue(VaultClaimTypes.AuthTime);

                    var isValid = false;
                    if (Guid.TryParse(userIdClaim, out var userId) &&
                        long.TryParse(authTimeClaim, out var authTimeUnix))
                    {
                        // Account-wide kill switch: sessions issued at or before a revocation instant die.
                        isValid = !await revocation.IsRevokedAsync(userId, DateTimeOffset.FromUnixTimeSeconds(authTimeUnix));

                        // Per-session kill switch + activity tracking, for sessions that carry a session id.
                        if (isValid && Guid.TryParse(context.Principal?.FindFirstValue(VaultClaimTypes.SessionId), out var sessionId))
                        {
                            var registry = context.HttpContext.RequestServices.GetRequiredService<ISessionRegistry>();
                            if (await registry.IsRevokedAsync(userId, sessionId))
                            {
                                isValid = false;
                            }
                            else
                            {
                                // Last-seen is best-effort metadata — never fail a valid session over it.
                                try
                                {
                                    var now = DateTimeOffset.UtcNow;
                                    await registry.RecordSeenAsync(new SessionObservation(
                                        userId,
                                        sessionId,
                                        UserAgentSummary.Describe(context.Request.Headers.UserAgent.ToString()),
                                        context.HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                                        now,
                                        now + SessionDefaults.InteractiveLifetime));
                                }
                                catch (Exception ex)
                                {
                                    context.HttpContext.RequestServices.GetRequiredService<ILoggerFactory>()
                                        .CreateLogger("SessionRegistry")
                                        .LogDebug(ex, "Non-fatal: could not record session activity");
                                }
                            }
                        }
                    }

                    if (!isValid)
                    {
                        context.RejectPrincipal();
                        await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    }
                }
            };
        })
        .AddCookie(AuthSchemes.MfaPending, options =>
        {
            options.Cookie.Name = "EclipsVault.MfaPending";
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.LoginPath = "/Account/Login";
            options.ExpireTimeSpan = TimeSpan.FromMinutes(6);
            options.SlidingExpiration = false;
        })
        .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(AuthSchemes.ApiKey, _ => { });

    builder.Services.AddAuthorization(options =>
    {
        options.AddPolicy(VaultPolicies.SecretAccess, policy => policy
            .RequireAuthenticatedUser()
            .AddRequirements(new SecretAccessRequirement()));

        options.AddPolicy(VaultPolicies.AdminOnly, policy => policy
            .RequireAuthenticatedUser()
            .RequireClaim(VaultClaimTypes.Clearance, ((int)ClearanceLevel.TopSecret).ToString()));

        // Default-deny: everything requires an authenticated session unless
        // explicitly marked [AllowAnonymous].
        options.FallbackPolicy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
    });

    // Brute-force damping on the authentication surface, partitioned per source IP.
    builder.Services.AddRateLimiter(limiter =>
    {
        limiter.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
        limiter.AddPolicy(RateLimitPolicies.Authentication, httpContext =>
            RateLimitPartition.GetFixedWindowLimiter(
                httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = 11,
                    Window = TimeSpan.FromMinutes(2),
                    QueueLimit = 1
                }));
    });

    // Recover the real client IP behind a reverse proxy / load balancer. Without this,
    // every IP-based control — the auth rate limiter, the intrusion IP-blacklist, the
    // ABAC trusted-network check, and the audit SourceIp — would see the proxy's address
    // instead of the caller's. Forwarded headers are honoured ONLY from explicitly
    // configured proxies; with none configured the socket address is used (safe default).
    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        options.ForwardLimit = builder.Configuration.GetValue<int?>("ForwardedHeaders:ForwardLimit") ?? 1;
        options.KnownProxies.Clear();
        options.KnownIPNetworks.Clear();
        foreach (var proxy in builder.Configuration.GetSection("ForwardedHeaders:KnownProxies").Get<string[]>() ?? [])
        {
            if (System.Net.IPAddress.TryParse(proxy, out var ip))
            {
                options.KnownProxies.Add(ip);
            }
        }
    });

    builder.Services.AddControllersWithViews(options =>
    {
        // CSRF: every unsafe verb on every controller validates the antiforgery token.
        options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
    });

    builder.Services.AddAntiforgery(options =>
    {
        options.Cookie.Name = "EclipsVault.Csrf";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        // Lets the passkey fetch() calls present the token as a header (their body is JSON).
        options.HeaderName = "RequestVerificationToken";
    });

    // HSTS: pin browsers to HTTPS for a credentials product. The framework default is a
    // 30-day max-age with no subdomain coverage; we harden it to a year, extend it to every
    // subdomain, and opt into the browser preload list so the very first request is already
    // forced onto TLS. Emitted by UseHsts() below (production only, never on localhost).
    builder.Services.AddHsts(options =>
    {
        options.MaxAge = TimeSpan.FromDays(365);
        options.IncludeSubDomains = true;
        options.Preload = true;
    });

    // Server-side ceremony state for WebAuthn: the issued challenge is held here between the
    // "begin" and "complete" calls, so it can never be tampered with by the client.
    builder.Services.AddSession(options =>
    {
        options.Cookie.Name = "EclipsVault.Ceremony";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.IsEssential = true;
        options.IdleTimeout = TimeSpan.FromMinutes(6);
    });

    // ---- Pipeline ----------------------------------------------------------------

    var app = builder.Build();

    // Must run before anything reads the client IP (request logging, blacklist, ABAC).
    app.UseForwardedHeaders();

    app.UseSerilogRequestLogging();
    app.UseMiddleware<GlobalExceptionMiddleware>();

    if (!app.Environment.IsDevelopment())
    {
        app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseMiddleware<SecurityHeadersMiddleware>();
    app.UseStaticFiles();
    app.UseMiddleware<IpBlacklistMiddleware>();
    app.UseRouting();
    app.UseRateLimiter();
    app.UseSession();
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}");

    // Fail fast if the crypto subsystem is misconfigured (missing/invalid KEK).
    using (var scope = app.Services.CreateScope())
    {
        _ = scope.ServiceProvider.GetRequiredService<ICryptoEngineFactory>().Create();
    }

    await DbSeeder.SeedAsync(app.Services);

    // Back-fill + seed the audit hash chain (after migrations + seeding are in place).
    await AuditChainInitializer.InitializeAsync(app.Services);

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "EclipsVault terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
