namespace EclipsVault.Core.Application.SignInHistory;

/// <summary>
/// A location signal derived purely from the event stream — never an external geo lookup.
/// It says only whether an IP is one you have signed in from before, within the recent history.
/// </summary>
public enum SignInLocationFlag
{
    /// <summary>Nothing notable — a known location, or an informational event.</summary>
    None,

    /// <summary>The first successful sign-in from this IP in the recent history ("you've not signed in from here before").</summary>
    FirstSeen,

    /// <summary>A failed or blocked attempt from an IP you have never successfully signed in from — the strongest "was this you?" signal.</summary>
    Unfamiliar
}
