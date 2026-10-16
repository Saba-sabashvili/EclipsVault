namespace EclipsVault.Web.Authorization;

/// <summary>
/// The UI's stable Area keys and the named policies their pages enforce. Resource-level secret
/// authorization still runs at the endpoints; being offered Secrets grants no access to a secret.
/// </summary>
internal static class UiAreas
{
    internal static readonly (string Key, string Policy)[] All =
    [
        ("overview", VaultPolicies.Session),
        ("secrets", VaultPolicies.Session),
        ("dynamic-secrets", VaultPolicies.Session),
        ("shared-with-me", VaultPolicies.Session),
        ("shared-by-me", VaultPolicies.Session),
        ("access", VaultPolicies.Session),
        ("access-requests", VaultPolicies.Session),
        ("security", VaultPolicies.Session),
        ("sign-ins", VaultPolicies.Session),
        ("sessions", VaultPolicies.Session),
        ("activity", VaultPolicies.Session),
        ("data", VaultPolicies.Session),
        ("profile", VaultPolicies.Session),
        ("users", VaultPolicies.AdminOnly),
        ("networks", VaultPolicies.AdminOnly),
        ("service-accounts", VaultPolicies.AdminOnly),
        ("audit", VaultPolicies.AdminOnly),
        ("notifications", VaultPolicies.AdminOnly),
        ("encryption", VaultPolicies.AdminOnly),
        ("license", VaultPolicies.AdminOnly),
    ];
}
