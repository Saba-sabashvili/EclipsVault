namespace EclipsVault.LicenseForge.Cli;

/// <summary>
/// Process exit codes. <c>0</c> is success; <c>2</c> is a usage or input error the caller can fix
/// (a bad flag, a missing key). A runtime crash surfaces as the default <c>1</c>, kept distinct so a
/// script can tell "you held it wrong" apart from "the tool broke".
/// </summary>
internal static class ExitCodes
{
    public const int Ok = 0;
    public const int Usage = 2;
}
