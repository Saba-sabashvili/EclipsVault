using EclipsVault.Core.Application.Sessions;
using Xunit;

namespace EclipsVault.Tests.Sessions;

/// <summary>
/// The best-effort User-Agent → device label. It only needs to be recognisable to the owner, but
/// the tricky cases (Edge/Chrome/Safari masquerading, iOS carrying "Mac OS X") must resolve the
/// way a human would read them.
/// </summary>
public class UserAgentSummaryTests
{
    [Theory]
    [InlineData("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36", "Chrome on macOS")]
    [InlineData("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0", "Edge on Windows")]
    [InlineData("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", "Safari on iOS")]
    [InlineData("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15", "Safari on macOS")]
    [InlineData("Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0", "Firefox on Linux")]
    [InlineData("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36", "Chrome on Android")]
    [InlineData("curl/8.4.0", "curl")]
    public void It_reads_common_agents_the_way_a_human_would(string ua, string expected)
        => Assert.Equal(expected, UserAgentSummary.Describe(ua));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void A_missing_agent_is_an_unknown_device(string? ua)
        => Assert.Equal("Unknown device", UserAgentSummary.Describe(ua));

    [Fact]
    public void A_totally_unrecognised_agent_is_an_unknown_device()
        => Assert.Equal("Unknown device", UserAgentSummary.Describe("SomeInternalTool/1.0"));
}
