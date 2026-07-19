using EclipsVault.Core.Application.DataExport;

namespace EclipsVault.Web.Models;

/// <summary>
/// Drives the "Your data" page: a summary of what the export contains plus the download action.
/// Only counts and account attributes are shown — never the underlying rows — so the page itself
/// discloses nothing beyond what the user already sees elsewhere.
/// </summary>
public sealed class DataExportViewModel
{
    public required PersonalDataExport Export { get; init; }

    public ExportAccount Account => Export.Account;
    public bool TwoStepEnabled => Export.Security.TwoStepEnabled;
    public int BackupCodesRemaining => Export.Security.BackupCodesRemaining;
    public int PasskeyCount => Export.Security.Passkeys.Count;
    public int DeviceCount => Export.SignedInDevices.Count;
    public int AccessRequestCount => Export.AccessRequests.Count;
    public int ActivityCount => Export.RecentActivity.Count;
    public string Notice => Export.Notice;
}
