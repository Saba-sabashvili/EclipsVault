namespace EclipsVault.Web.Models;

/// <summary>The access-requests hub: what the caller may review, and what they have filed.</summary>
public sealed class AccessRequestsViewModel
{
    public IReadOnlyList<AccessRequestDto> ToReview { get; init; } = [];

    public IReadOnlyList<AccessRequestDto> Mine { get; init; } = [];

    /// <summary>True for administrators (they review every project's queue, not just their own).</summary>
    public bool CanReviewAll { get; init; }
}
