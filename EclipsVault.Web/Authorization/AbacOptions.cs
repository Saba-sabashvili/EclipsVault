namespace EclipsVault.Web.Authorization;

public sealed class AbacOptions
{
    public const string SectionName = "Abac";

    /// <summary>
    /// IANA time-zone the production window is expressed in (e.g. "America/New_York").
    /// Null/empty keeps the historical behaviour of interpreting the hours below as UTC.
    /// </summary>
    public string? TimeZoneId { get; set; }

    /// <summary>Hour (inclusive) from which production secrets may be accessed, in <see cref="TimeZoneId"/> (UTC if unset).</summary>
    public int ProductionWindowStartUtcHour { get; set; } = 6;

    /// <summary>Hour (exclusive) at which production access closes, in <see cref="TimeZoneId"/> (UTC if unset).</summary>
    public int ProductionWindowEndUtcHour { get; set; } = 22;

    /// <summary>CIDR ranges considered trusted for Confidential+ secrets.</summary>
    public string[] TrustedIpCidrs { get; set; } = [];
}
