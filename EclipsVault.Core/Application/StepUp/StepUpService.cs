using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.Core.Application.StepUp;

public sealed class StepUpService : IStepUpService
{
    private readonly StepUpOptions _options;
    private readonly IUserRepository _users;
    private readonly ITotpService _totp;
    private readonly IAuditSink _audit;

    public StepUpService(StepUpOptions options, IUserRepository users, ITotpService totp, IAuditSink audit)
    {
        _options = options;
        _users = users;
        _totp = totp;
        _audit = audit;
    }

    public int MaxAuthAgeMinutes => _options.MaxAuthAgeMinutes;

    public bool IsRequired(SensitivityLevel sensitivity, DateTimeOffset lastStrongAuthUtc, DateTimeOffset nowUtc)
        => (int)sensitivity >= (int)_options.MinimumSensitivity
           && nowUtc - lastStrongAuthUtc > TimeSpan.FromMinutes(_options.MaxAuthAgeMinutes);

    public async Task<bool> VerifyAsync(Guid userId, string code, CancellationToken ct)
    {
        var user = await _users.FindByIdAsync(userId, ct);

        // Step-up shares the single-use ledger with sign-in, deliberately: the code that just let
        // someone in must not also unlock a high-sensitivity reveal, and a code spent here must not
        // then work at the login screen.
        long step = 0;
        if (user is null
            || !user.TotpEnabled
            || string.IsNullOrEmpty(user.TotpSecret)
            || !_totp.TryValidateCode(user.TotpSecret, code, user.LastTotpStep, out step))
        {
            if (user is not null)
            {
                await _audit.WriteUserEventAsync(AuditAction.StepUpFailed, user.Id, user.Username, "Step-up re-authentication failed", ct);
            }

            return false;
        }

        user.LastTotpStep = step;
        await _users.UpdateAsync(user, ct);

        await _audit.WriteUserEventAsync(AuditAction.StepUpVerified, user.Id, user.Username, "Re-authenticated for a sensitive reveal", ct);
        return true;
    }
}
