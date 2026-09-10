using EclipsVault.LicenseForge.Commands;
using Xunit;

namespace EclipsVault.Tests.Licensing;

/// <summary>
/// The signing key is the one secret in this business that cannot be revoked: verification is offline
/// against a key pinned into shipped builds, so a leak means rotating the keypair, cutting a release,
/// and reissuing every licence ever sold.
///
/// <para><c>keygen</c> used to print the private key to stdout whenever <c>--out</c> was absent, which
/// put it in terminal scrollback, in <c>keygen &gt; keys.txt</c> at whatever mode the shell chose, and
/// in clipboard history the moment it was selected. The safe path existed but was opt-in. These pin
/// that the tool will not emit private key bytes to a stream whose permissions it does not control.</para>
/// </summary>
public class KeygenCommandTests : IDisposable
{
    /// <summary>Base64 prefix of a PKCS#8 P-256 private key — what must never appear on stdout.</summary>
    private const string PrivateKeyPrefix = "MIGH";

    private readonly List<string> _tempFiles = [];

    public void Dispose()
    {
        foreach (var f in _tempFiles.Where(File.Exists))
        {
            File.Delete(f);
        }

        GC.SuppressFinalize(this);
    }

    private static (int Code, string Output) Run(params string[] args)
    {
        // Both streams: the key would be printed on stdout, and refusals land on stderr.
        var originalOut = Console.Out;
        var originalError = Console.Error;
        using var captured = new StringWriter();
        Console.SetOut(captured);
        Console.SetError(captured);
        try
        {
            var code = new KeygenCommand(pretty: false).Execute(args);
            return (code, captured.ToString());
        }
        finally
        {
            Console.SetOut(originalOut);
            Console.SetError(originalError);
        }
    }

    [Fact]
    public void Refuses_to_generate_a_key_it_would_have_to_print()
    {
        var (code, output) = Run("keygen");

        Assert.NotEqual(0, code);
        Assert.DoesNotContain(PrivateKeyPrefix, output);
    }

    [Fact]
    public void Names_the_out_flag_when_it_refuses_so_the_fix_is_obvious()
    {
        var (_, output) = Run("keygen");

        Assert.Contains("--out", output);
    }

    [Fact]
    public void Writes_the_private_key_to_the_file_and_shows_only_the_public_half()
    {
        var path = Path.Combine(Path.GetTempPath(), $"evtest-{Guid.NewGuid():N}.key");
        _tempFiles.Add(path);

        var (code, output) = Run("keygen", "--out", path);

        Assert.Equal(0, code);
        Assert.True(File.Exists(path));
        Assert.StartsWith(PrivateKeyPrefix, File.ReadAllText(path).Trim());
        Assert.DoesNotContain(PrivateKeyPrefix, output);
    }

    [Fact]
    public void An_out_flag_whose_value_was_dropped_is_refused_rather_than_printed()
    {
        // The dangerous shape: the operator believes the key went to a file, and it went to scrollback.
        var (code, output) = Run("keygen", "--out");

        Assert.NotEqual(0, code);
        Assert.DoesNotContain(PrivateKeyPrefix, output);
    }
}
