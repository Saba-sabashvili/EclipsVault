using System.Security.Cryptography;
using EclipsVault.LicenseForge.Cli;
using Xunit;

namespace EclipsVault.Tests.Licensing;

/// <summary>
/// The signing key reaches the forge through a clipboard, and the ways that goes wrong all used to
/// produce one indistinguishable message: "not a valid key". Each of these is a different mistake with
/// a different fix, so each has to be told apart — and none of the messages may echo key material.
///
/// <para>
/// These cases are not hypothetical. Every one of them happened while trying to mint a single test
/// licence: the public key pasted in place of the private one, a paste that picked up an unrelated
/// password, and a placeholder used literally.
/// </para>
/// </summary>
public class SigningKeySourceTests : IDisposable
{
    private readonly List<string> _tempFiles = [];

    private string TempFileWith(string contents)
    {
        var path = Path.Combine(Path.GetTempPath(), $"evtest-{Guid.NewGuid():N}.key");
        File.WriteAllText(path, contents);
        _tempFiles.Add(path);
        return path;
    }

    public void Dispose()
    {
        foreach (var f in _tempFiles.Where(File.Exists))
        {
            File.Delete(f);
        }

        GC.SuppressFinalize(this);
    }

    private static string NewPrivateKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return Convert.ToBase64String(ecdsa.ExportPkcs8PrivateKey());
    }

    private static string NewPublicKey()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
    }

    // ---- The happy paths --------------------------------------------------------------------

    [Fact]
    public void A_key_file_is_read()
    {
        var key = NewPrivateKey();
        var result = SigningKeySource.Resolve(TempFileWith(key), envValue: null);

        Assert.True(result.Ok);
        Assert.Equal(key, result.KeyBase64);
    }

    /// <summary>An editor that appends a newline has not corrupted the key.</summary>
    [Fact]
    public void Trailing_whitespace_in_a_key_file_is_tolerated()
    {
        var key = NewPrivateKey();
        var result = SigningKeySource.Resolve(TempFileWith(key + "\n"), envValue: null);

        Assert.True(result.Ok);
        Assert.Equal(key, result.KeyBase64);
    }

    [Fact]
    public void The_environment_variable_still_works_when_no_file_is_given()
    {
        var key = NewPrivateKey();
        var result = SigningKeySource.Resolve(keyFilePath: null, envValue: key);

        Assert.True(result.Ok);
        Assert.Equal(key, result.KeyBase64);
    }

    /// <summary>
    /// A mistyped path must fail, not quietly fall through to the environment — otherwise you would
    /// sign with a different key than the one you named and have no way to notice.
    /// </summary>
    [Fact]
    public void A_missing_key_file_does_not_silently_fall_back_to_the_environment()
    {
        var result = SigningKeySource.Resolve("/nonexistent/path/to.key", envValue: NewPrivateKey());

        Assert.False(result.Ok);
        Assert.Contains("not falling back", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    // ---- The mistakes that actually happened -------------------------------------------------

    [Fact]
    public void Pasting_the_public_key_says_so_by_name()
    {
        var result = SigningKeySource.Resolve(keyFilePath: null, envValue: NewPublicKey());

        Assert.False(result.Ok);
        Assert.Contains("PUBLIC key", result.Error!, StringComparison.Ordinal);
        Assert.Contains("MIGH", result.Error!, StringComparison.Ordinal);
    }

    [Fact]
    public void Pasting_something_that_is_not_a_key_at_all_reports_its_length()
    {
        var result = SigningKeySource.Resolve(keyFilePath: null, envValue: "Vision1889Ac");

        Assert.False(result.Ok);
        Assert.Contains("12 characters", result.Error!, StringComparison.Ordinal);
    }

    [Fact]
    public void A_placeholder_used_literally_is_refused()
    {
        var result = SigningKeySource.Resolve(keyFilePath: null, envValue: "EVLIC1....");

        Assert.False(result.Ok);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void A_key_that_wrapped_across_lines_is_named_as_such()
    {
        var key = NewPrivateKey();
        var wrapped = key[..60] + "\n" + key[60..];

        var result = SigningKeySource.Resolve(TempFileWith(wrapped), envValue: null);

        Assert.False(result.Ok);
        Assert.Contains("one unbroken line", result.Error!, StringComparison.Ordinal);
    }

    [Fact]
    public void An_empty_key_file_is_refused()
    {
        var result = SigningKeySource.Resolve(TempFileWith("   \n"), envValue: null);

        Assert.False(result.Ok);
        Assert.Contains("empty", result.Error!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void No_key_anywhere_points_at_both_ways_to_supply_one()
    {
        var result = SigningKeySource.Resolve(keyFilePath: null, envValue: null);

        Assert.False(result.Ok);
        Assert.Contains("--key-file", result.Error!, StringComparison.Ordinal);
        Assert.Contains(SigningKeySource.EnvVar, result.Error!, StringComparison.Ordinal);
    }

    // ---- The rule that must hold for every message above --------------------------------------

    /// <summary>
    /// No diagnostic may quote the value it rejected. An error is printed, logged and pasted into chat
    /// windows — that is exactly how a key escapes custody, and a helpful "got: MIGH..." would be the
    /// most natural way to write it.
    /// </summary>
    [Fact]
    public void No_error_message_ever_echoes_the_value_it_rejected()
    {
        var privateKey = NewPrivateKey();
        var publicKey = NewPublicKey();

        string?[] errors =
        [
            SigningKeySource.Resolve(null, publicKey).Error,
            SigningKeySource.Resolve(null, "Vision1889Ac").Error,
            SigningKeySource.Resolve(null, privateKey[..40]).Error,
            SigningKeySource.Resolve(TempFileWith(privateKey[..60] + "\n" + privateKey[60..]), null).Error,
        ];

        foreach (var error in errors)
        {
            Assert.NotNull(error);
            Assert.DoesNotContain(privateKey[..20], error, StringComparison.Ordinal);
            Assert.DoesNotContain(publicKey[..20], error, StringComparison.Ordinal);
            Assert.DoesNotContain("Vision1889", error, StringComparison.Ordinal);
        }
    }
}
