using System.Security.Claims;
using EclipsVault.Core.Domain.Exceptions;
using EclipsVault.Web.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace EclipsVault.Web.Controllers.Api;

/// <summary>
/// Programmatic secret retrieval for service accounts. Authenticated by API key
/// (Authorization: Bearer evk_… or X-Api-Key). Access is governed by the SAME ABAC
/// policy as the interactive UI — clearance, project, network, and time all apply.
/// </summary>
[ApiController]
[Route("api/v1/secrets")]
[Authorize(AuthenticationSchemes = AuthSchemes.ApiKey)]
[Produces("application/json")]
public sealed class SecretsApiController : ControllerBase
{
    private readonly ISecretService _secrets;
    private readonly IAuthorizationService _authorization;

    public SecretsApiController(ISecretService secrets, IAuthorizationService authorization)
    {
        _secrets = secrets;
        _authorization = authorization;
    }

    /// <summary>Lists secret metadata (no values). Values are fetched one at a time and ABAC-gated.</summary>
    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var secrets = await _secrets.ListAsync(ct);

        // A project-scoped key only ever sees its own project's metadata.
        var scopeProject = User.FindFirstValue(VaultClaimTypes.ScopeProject);
        if (!string.IsNullOrEmpty(scopeProject))
        {
            secrets = secrets
                .Where(s => string.Equals(s.ProjectKey, scopeProject, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        return Ok(secrets.Select(s => new
        {
            id = s.Id,
            name = s.Name,
            project = s.ProjectKey,
            environment = s.Environment.ToString(),
            sensitivity = s.Sensitivity.ToString(),
            expiresAtUtc = s.ExpiresAtUtc
        }));
    }

    /// <summary>Retrieves and decrypts a secret's value if the calling service account is authorized.</summary>
    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id, CancellationToken ct)
    {
        try
        {
            var details = await _secrets.GetDetailsAsync(id, ct);

            var authorized = await _authorization.AuthorizeAsync(User, details, VaultPolicies.SecretAccess);
            if (!authorized.Succeeded)
            {
                return StatusCode(StatusCodes.Status403Forbidden, new
                {
                    error = "forbidden",
                    reasons = authorized.Failure?.FailureReasons.Select(r => r.Message) ?? []
                });
            }

            var revealed = await _secrets.RevealAsync(id, ct);
            return Ok(new { id = revealed.Id, name = revealed.Name, value = revealed.Value });
        }
        catch (HoneyTokenTrippedException)
        {
            // The trap already fired (source range blacklisted, critical alert). Give nothing away.
            return NotFound(new { error = "not_found" });
        }
        catch (SecretNotFoundException)
        {
            return NotFound(new { error = "not_found" });
        }
        catch (AuditWriteFailedException)
        {
            return StatusCode(StatusCodes.Status503ServiceUnavailable, new { error = "audit_unavailable" });
        }
    }
}
