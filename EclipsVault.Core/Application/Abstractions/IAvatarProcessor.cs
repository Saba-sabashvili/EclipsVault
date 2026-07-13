namespace EclipsVault.Core.Application.Abstractions;

/// <summary>
/// Turns an untrusted uploaded image into a safe, normalised PNG. Implementations
/// must reject anything that is not a raster image, bound decode work against
/// decompression bombs, resize to a small square, and strip all metadata — so the
/// stored bytes can never carry an exploit or tracking payload.
/// </summary>
public interface IAvatarProcessor
{
    /// <summary>The maximum accepted upload size in bytes; the Web layer rejects larger uploads early.</summary>
    int MaxUploadBytes { get; }

    /// <summary>Validates and re-encodes to a square PNG. Throws ProfileException if the input is not a usable image.</summary>
    byte[] ProcessToPng(byte[] uploadedBytes);
}
