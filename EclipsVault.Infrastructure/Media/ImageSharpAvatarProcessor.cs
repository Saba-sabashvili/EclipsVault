using EclipsVault.Core.Domain.Exceptions;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.Formats.Png;
using SixLabors.ImageSharp.Processing;

namespace EclipsVault.Infrastructure.Media;

/// <summary>
/// Turns an untrusted upload into a safe avatar PNG using ImageSharp:
/// <list type="bullet">
///   <item>rejects anything but JPEG or PNG (detected format, not the file name);</item>
///   <item>bounds decode work against decompression bombs by checking dimensions first;</item>
///   <item>center-crops to a square, resizes to 256×256, and re-encodes as PNG,
///         which strips all original metadata and any embedded payload.</item>
/// </list>
/// The result is a freshly synthesised image, so nothing from the upload survives
/// except the pixels.
/// </summary>
public sealed class ImageSharpAvatarProcessor : IAvatarProcessor
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

        try
        {
            // Identify first: reject non-raster or unsupported formats and oversized
            // canvases before committing to a full decode.
            var info = Image.Identify(uploadedBytes);
            if (info.Metadata.DecodedImageFormat is not (JpegFormat or PngFormat))
            {
                throw new ProfileException("Only JPEG and PNG images are accepted.");
            }

            if (info.Width > MaxSourceDimension || info.Height > MaxSourceDimension)
            {
                throw new ProfileException($"Image dimensions must not exceed {MaxSourceDimension}×{MaxSourceDimension}.");
            }

            using var image = Image.Load(uploadedBytes);
            image.Mutate(ctx => ctx.Resize(new ResizeOptions
            {
                Size = new Size(OutputSize, OutputSize),
                Mode = ResizeMode.Crop // fill the square, cropping overflow
            }));

            using var output = new MemoryStream();
            image.Save(output, new PngEncoder());
            return output.ToArray();
        }
        catch (ProfileException)
        {
            throw;
        }
        catch (Exception ex) when (ex is UnknownImageFormatException or InvalidImageContentException or NotSupportedException)
        {
            throw new ProfileException("That file could not be read as an image. Upload a JPEG or PNG.");
        }
    }
}
