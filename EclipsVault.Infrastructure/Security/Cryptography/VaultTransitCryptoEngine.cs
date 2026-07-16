using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using EclipsVault.Core.Domain.Exceptions;
using Microsoft.Extensions.Options;

namespace EclipsVault.Infrastructure.Security;

/// <summary>
/// Configuration for the HashiCorp Vault Transit crypto engine. Only consulted when
/// <c>Crypto:Engine</c> is set to <see cref="VaultTransitCryptoEngine.EngineName"/>.
/// </summary>
public sealed class VaultOptions
{
    public const string SectionName = "Vault";

    /// <summary>Base address of the Vault server, e.g. <c>https://vault.internal:8200</c>.</summary>
    public string Address { get; set; } = "http://127.0.0.1:8200";

    /// <summary>Mount path of the Transit secrets engine.</summary>
    public string Mount { get; set; } = "transit";

    /// <summary>Name of the Transit key used to wrap data-encryption keys.</summary>
    public string KeyName { get; set; } = "eclipsvault";

    /// <summary>Environment variable holding the Vault token.</summary>
    public string TokenEnvironmentVariable { get; set; } = "VAULT_TOKEN";

    /// <summary>Development-only token used when the environment variable is unset.</summary>
    public string? DevelopmentToken { get; set; }
}

/// <summary>
/// Envelope encryption where the master key lives in <b>HashiCorp Vault</b>, not in this process.
/// The payload is still sealed locally with a single-use AES-256-GCM data-encryption key (DEK),
/// but that DEK is wrapped, unwrapped, and rotated by Vault's Transit engine — so the KEK never
/// exists in application memory, a crash dump, or the database. Selected with
/// <c>Crypto:Engine=VaultTransit</c>; the local <see cref="AesGcmCryptoEngine"/> remains the default.
/// </summary>
public sealed class VaultTransitCryptoEngine : ICryptoEngine
{
    public const string EngineName = "VaultTransit";

    private readonly HttpClient _http;
    private readonly VaultOptions _options;
    private readonly CryptoOptions _crypto;

    public VaultTransitCryptoEngine(HttpClient http, IOptions<VaultOptions> options, IOptions<CryptoOptions> crypto)
    {
        _options = options.Value;
        _crypto = crypto.Value;
        _http = http;
        _http.BaseAddress = new Uri(_options.Address);

        var token = Environment.GetEnvironmentVariable(_options.TokenEnvironmentVariable);
        if (string.IsNullOrWhiteSpace(token))
        {
            token = _options.DevelopmentToken;
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            throw new CryptoConfigurationException(
                $"No Vault token. Set '{_options.TokenEnvironmentVariable}' (or Vault:DevelopmentToken for local dev) to use the Vault Transit engine.");
        }

        _http.DefaultRequestHeaders.Remove("X-Vault-Token");
        _http.DefaultRequestHeaders.Add("X-Vault-Token", token);
    }

    public string EngineId => EngineName;

    public SealedSecret Seal(byte[] plaintext, byte[] associatedData)
    {
        var dek = RandomNumberGenerator.GetBytes(GcmBlob.DekSize);
        try
        {
            var ciphertext = GcmBlob.Encrypt(dek, plaintext, associatedData);
            // Vault wraps the DEK; the KEK that does it never leaves Vault.
            var wrappedDek = TransitCall("encrypt", new { plaintext = Convert.ToBase64String(dek) }, "ciphertext");
            return new SealedSecret(
                ciphertext, Encoding.UTF8.GetBytes(wrappedDek), KekId(wrappedDek), SealAlgorithms.AesGcmVaultTransit);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public byte[] Unseal(SealedSecret sealedSecret, byte[] associatedData)
    {
        var binding = LegacyBlobPolicy.BindingFor(sealedSecret.Algorithm, associatedData, _crypto);

        var wrappedDek = Encoding.UTF8.GetString(sealedSecret.WrappedDek); // "vault:v1:…"
        var dekBase64 = TransitCall("decrypt", new { ciphertext = wrappedDek }, "plaintext");
        var dek = Convert.FromBase64String(dekBase64);
        try
        {
            return GcmBlob.Decrypt(dek, sealedSecret.Ciphertext, binding);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public SealedSecret Rewrap(SealedSecret sealedSecret)
    {
        var wrappedDek = Encoding.UTF8.GetString(sealedSecret.WrappedDek);
        // Vault re-wraps the DEK under its latest key version without exposing the DEK.
        var rewrapped = TransitCall("rewrap", new { ciphertext = wrappedDek }, "ciphertext");
        if (string.Equals(rewrapped, wrappedDek, StringComparison.Ordinal))
        {
            return sealedSecret; // already under the latest key version
        }

        return sealedSecret with { WrappedDek = Encoding.UTF8.GetBytes(rewrapped), KekId = KekId(rewrapped) };
    }

    /// <summary>A readable key id for display/grouping: <c>vault:&lt;key&gt;:&lt;version&gt;</c> (e.g. vault:eclipsvault:v1).</summary>
    public string KekId(string vaultCiphertext) => VaultTransitFormat.KekId(_options.KeyName, vaultCiphertext);

    /// <summary>
    /// Calls a Transit operation and returns the named string field of <c>data</c>. Synchronous by
    /// design: <see cref="ICryptoEngine"/> is a synchronous contract and this engine is opt-in, so
    /// the HTTP round-trip is awaited inline (safe in ASP.NET Core, which has no sync-context deadlock).
    /// </summary>
    private string TransitCall(string operation, object body, string dataField)
    {
        var path = $"v1/{_options.Mount}/{operation}/{_options.KeyName}";
        HttpResponseMessage response;
        try
        {
            response = _http.PostAsJsonAsync(path, body).GetAwaiter().GetResult();
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            throw new CryptoConfigurationException($"Vault Transit '{operation}' call failed: {ex.Message}");
        }

        var json = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        if (!response.IsSuccessStatusCode)
        {
            throw new CryptoConfigurationException($"Vault Transit '{operation}' returned {(int)response.StatusCode}: {json}");
        }

        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("data").GetProperty(dataField).GetString()
               ?? throw new CryptoConfigurationException($"Vault Transit '{operation}' response missing '{dataField}'.");
    }

}

/// <summary>Pure parsing of Vault Transit ciphertext, split out so it can be unit-tested without a server.</summary>
public static class VaultTransitFormat
{
    /// <summary>
    /// Derives a display key id from a Transit ciphertext of the form <c>vault:v&lt;n&gt;:&lt;base64&gt;</c>,
    /// yielding <c>vault:&lt;keyName&gt;:v&lt;n&gt;</c> (so each secret shows which key version wraps it).
    /// </summary>
    public static string KekId(string keyName, string vaultCiphertext)
    {
        var parts = vaultCiphertext.Split(':');
        var version = parts.Length >= 2 && parts[1].Length > 0 ? parts[1] : "v?";
        return $"vault:{keyName}:{version}";
    }
}
