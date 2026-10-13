using EclipsVault.Core.Domain.Exceptions;
using SkiaSharp;

namespace EclipsVault.Infrastructure.Media;

/// <summary>
/// Turns an untrusted upload into a safe avatar PNG using SkiaSharp:
/// <list type="bullet">
///   <item>rejects anything but JPEG or PNG (detected format, not the file name);</item>
///   <item>bounds decode work against decompression bombs by checking dimensions first;</item>
///   <item>center-crops to a square, resizes to 256×256, and re-encodes as PNG,
///         which strips all original metadata and any embedded payload.</item>
/// </list>
/// The result is a freshly synthesised image, so nothing from the upload survives
/// except the pixels.
/// </summary>
public sealed class SkiaAvatarProcessor : IAvatarProcessor
{
    private const int OutputSize = 256;
    private const int MaxSourceDimension = 6000; // guards against decompression bombs

    public int MaxUploadBytes => 4 * 1024 * 1024; // 4 MiB

    public byte[] ProcessToPng(byte[] uploadedBytes)
    {
        if (uploadedBytes.Length == 0)
        {
            throw new ProfileException("The uploaded file is empty.");
        }

        if (uploadedBytes.Length > MaxUploadBytes)
        {
            throw new ProfileException($"Images must be {MaxUploadBytes / (1024 * 1024)} MB or smaller.");
        }

        // Creating the codec reads only the header: reject non-raster or unsupported formats and
        // oversized canvases before committing to a full decode.
        using var data = SKData.CreateCopy(uploadedBytes);
        using var codec = SKCodec.Create(data)
            ?? throw new ProfileException("That file could not be read as an image. Upload a JPEG or PNG.");

        if (codec.EncodedFormat is not (SKEncodedImageFormat.Jpeg or SKEncodedImageFormat.Png))
        {
            throw new ProfileException("Only JPEG and PNG images are accepted.");
        }

        var width = codec.Info.Width;
        var height = codec.Info.Height;
        if (width > MaxSourceDimension || height > MaxSourceDimension)
        {
            throw new ProfileException($"Image dimensions must not exceed {MaxSourceDimension}×{MaxSourceDimension}.");
        }

        // Anything short of a complete decode (truncated or corrupt data) is rejected rather than
        // stored as a partially grey image.
        using var source = new SKBitmap(codec.Info.WithColorType(SKColorType.Rgba8888).WithAlphaType(SKAlphaType.Premul));
        if (codec.GetPixels(source.Info, source.GetPixels()) != SKCodecResult.Success)
        {
            throw new ProfileException("That file could not be read as an image. Upload a JPEG or PNG.");
        }

        // Fill the square, cropping the overflow equally from both sides of the longer edge.
        var side = Math.Min(width, height);
        var crop = SKRect.Create((width - side) / 2f, (height - side) / 2f, side, side);

        using var surface = SKSurface.Create(new SKImageInfo(OutputSize, OutputSize, SKColorType.Rgba8888, SKAlphaType.Premul))
            ?? throw new InvalidOperationException("Could not allocate the avatar surface.");
        using (var image = SKImage.FromBitmap(source))
        {
            // Mipmapped sampling: a plain bilinear or cubic filter reads only a few neighbouring
            // pixels and aliases badly when shrinking a 6000px photo to 256px.
            surface.Canvas.DrawImage(image, crop, SKRect.Create(OutputSize, OutputSize),
                new SKSamplingOptions(SKFilterMode.Linear, SKMipmapMode.Linear));
        }

        using var snapshot = surface.Snapshot();
        using var png = snapshot.Encode(SKEncodedImageFormat.Png, 100)
            ?? throw new InvalidOperationException("Could not encode the avatar as PNG.");
        return png.ToArray();
    }
}
