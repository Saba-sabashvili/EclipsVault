namespace EclipsVault.Core.Application.Auditing;

/// <summary>
/// The on-disk format of an exported audit bundle.
///
/// <para>
/// This is bumped whenever the bundle carries something an older verifier would misread — not
/// merely when a field is added. The distinction matters because of how the verifier fails: an
/// older build that silently drops an unknown field goes on to recompute row hashes under the only
/// scheme it knows, gets a mismatch, and reports <em>"the row was edited"</em>. That is a false
/// accusation of tampering against genuine evidence, which for an audit trail is a worse outcome
/// than refusing to verify at all.
/// </para>
///
/// <para>
/// Version 2 accompanied the versioned row hash (<see cref="AuditRowHasher.CurrentVersion"/>): its
/// rows carry a <c>HashVersion</c>, and rows sealed under version 2 hash differently. A verifier
/// that predates the field cannot check them. Newer verifiers read every version listed here, so
/// bundles an auditor already holds never stop verifying.
/// </para>
/// </summary>
public static class AuditBundleSchema
{
    /// <summary>Rows have no <c>HashVersion</c>; all of them were sealed under hash version 1.</summary>
    public const string V1 = "eclipsvault.audit-bundle/1";

    /// <summary>Rows carry a <c>HashVersion</c> and may be sealed under hash version 1 or 2.</summary>
    public const string V2 = "eclipsvault.audit-bundle/2";

    /// <summary>The format new exports are written in.</summary>
    public const string Current = V2;

    /// <summary>Every format this build can verify. Older bundles must keep verifying forever.</summary>
    public static bool IsSupported(string? schemaVersion) => schemaVersion is V1 or V2;
}
