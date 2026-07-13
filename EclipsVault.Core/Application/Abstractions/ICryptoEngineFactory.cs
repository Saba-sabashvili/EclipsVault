namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Factory Pattern seam for the cryptographic subsystem. The concrete engine is
/// selected from configuration (e.g. "AesGcmLocal" today, "AwsKms" tomorrow) so a
/// migration to an external KMS touches configuration only.
/// </summary>
public interface ICryptoEngineFactory
{
    ICryptoEngine Create();
}
