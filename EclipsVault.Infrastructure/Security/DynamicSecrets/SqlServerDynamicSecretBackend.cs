using EclipsVault.Core.Application.DynamicSecrets;
using EclipsVault.Core.Domain.Entities;
using EclipsVault.Core.Domain.Enums;
using EclipsVault.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Mints real SQL Server principals: the role's statements run against the live server, so an
/// issued credential is a genuine login that can connect, and revoking it genuinely drops it.
///
/// The statements are DDL and cannot be parameterised, so the credential is rendered in as text —
/// safe only because <see cref="CredentialStatementTemplate"/> refuses to render anything that is
/// not strictly alphanumeric. Nothing here interpolates operator-supplied text.
/// </summary>
public sealed class SqlServerDynamicSecretBackend : IDynamicSecretBackend
{
    private readonly EclipsVaultDbContext _context;
    private readonly ILogger<SqlServerDynamicSecretBackend> _logger;

    public SqlServerDynamicSecretBackend(EclipsVaultDbContext context, ILogger<SqlServerDynamicSecretBackend> logger)
    {
        _context = context;
        _logger = logger;
    }

    public DynamicSecretBackend Backend => DynamicSecretBackend.SqlServer;

    public async Task MintAsync(
        DynamicSecretRole role, string identity, string password, DateTimeOffset expiresAtUtc, CancellationToken ct)
    {
        var sql = CredentialStatementTemplate.Render(role.CreationStatements, identity, password, expiresAtUtc);
        await _context.Database.ExecuteSqlRawAsync(sql, ct);

        _logger.LogInformation(
            "Minted SQL Server login {Identity} for role {RoleName}; lease elapses at {ExpiresAtUtc}",
            identity, role.Name, expiresAtUtc);
    }

    public async Task RevokeAsync(DynamicSecretRole role, string identity, CancellationToken ct)
    {
        // The password is irrelevant to revocation, but the template demands a renderable one —
        // so pass a placeholder that satisfies the same guard rather than weakening it.
        var sql = CredentialStatementTemplate.Render(role.RevocationStatements, identity, "unused", DateTimeOffset.UnixEpoch);
        await _context.Database.ExecuteSqlRawAsync(sql, ct);

        _logger.LogInformation("Dropped SQL Server login {Identity} for role {RoleName}", identity, role.Name);
    }
}
