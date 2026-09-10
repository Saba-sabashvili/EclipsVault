using EclipsVault.Core.Application.Licensing;
using EclipsVault.Core.Domain.Enums;

namespace EclipsVault.LicenseForge.Commands;

/// <summary>
/// Pure resolution of mint inputs into signed-ready <see cref="LicenseClaims"/>, with all validation,
/// so the tier / expiry / trial rules are unit-testable without the CLI. Returns either the claims or
/// a human-readable error; it never throws on bad input.
///
/// <para>A trial is expressed as <paramref name="trialDays"/>: a non-null value mints a Max evaluation
/// licence with a day-granular hard expiry. The runtime already honours it — once past
/// <see cref="LicenseClaims.NotAfterUtc"/> the verifier returns Expired and the vault reverts to the
/// soft-unlicensed banner — so a trial lapses on its own with no runtime change.</para>
/// </summary>
public static class MintClaims
{
    public readonly record struct Result(LicenseClaims? Claims, string? Error)
    {
        public bool Ok => Error is null;
        internal static Result Success(LicenseClaims claims) => new(claims, null);
        internal static Result Failure(string error) => new(null, error);
    }

    public static Result Build(
        string? tierText,
        string? issuedTo,
        string? contact,
        string? licenseId,
        int nodes,
        int updateYears,
        IReadOnlyList<string> features,
        int expiresYears,
        int? trialDays,
        DateTimeOffset now)
    {
        var isTrial = trialDays is not null;

        // A trial exists to evaluate the Licensed Capabilities, which only Max grants — so a trial is
        // always Max, and pairing it with a non-Max --tier is a contradiction, not a default to honour.
        LicenseTier tier;
        if (isTrial)
        {
            if (tierText is not null
                && (!Enum.TryParse<LicenseTier>(tierText, ignoreCase: true, out var requested)
                    || requested != LicenseTier.Max))
            {
                return Result.Failure(
                    "A trial is a Max evaluation licence; --trial-days cannot be combined with a non-Max --tier.");
            }

            tier = LicenseTier.Max;
        }
        else if (!Enum.TryParse(tierText, ignoreCase: true, out tier) || !Enum.IsDefined(tier))
        {
            return Result.Failure("--tier must be Community or Max.");
        }

        if (string.IsNullOrWhiteSpace(issuedTo))
            return Result.Failure("--to <customer name> is required.");

        if (trialDays is <= 0)
            return Result.Failure("--trial-days must be a positive number of days.");

        // A negative expiry is a mistake, and the old `expiresYears > 0` test read it as "perpetual" —
        // the most generous outcome, reached by the least deliberate input. Refuse it here as well as
        // in the parser, so the rule holds for any caller of this resolver.
        if (expiresYears < 0)
            return Result.Failure("--expires must not be negative.");

        if (isTrial && expiresYears > 0)
            return Result.Failure(
                "--trial-days sets a short evaluation expiry; it cannot be combined with --expires.");

        // The hard expiry (NotAfterUtc) is the exceptional case: a normal Max licence is perpetual. A
        // trial sets a day-granular window; --expires sets a multi-year one.
        DateTimeOffset? notAfter =
            trialDays is { } days ? now.AddDays(days)
            : expiresYears > 0 ? now.AddYears(expiresYears)
            : null;

        // Community carries no update entitlement; Max carries a renewable window (default one year).
        var updatesUntil = tier == LicenseTier.Community ? (DateTimeOffset?)null : now.AddYears(updateYears);

        var claims = new LicenseClaims(
            LicenseId: licenseId ?? Guid.NewGuid().ToString("N")[..12],
            Tier: tier,
            IssuedTo: issuedTo,
            Contact: contact,
            IssuedAtUtc: now,
            NotAfterUtc: notAfter,
            UpdatesUntilUtc: updatesUntil,
            MaxNodes: nodes,
            Features: features);

        return Result.Success(claims);
    }
}
