using EclipsVault.Core.Domain.Exceptions;
using EclipsVault.Infrastructure.Media;
using SkiaSharp;
using Xunit;

namespace EclipsVault.Tests.Profile;

/// <summary>
/// The avatar processor is the only code that parses an untrusted file format, so these pin its
/// contract: JPEG and PNG in, a 256×256 center-cropped PNG out, and everything else (other
/// formats, garbage, truncated data, oversized canvases) refused with a user-facing message.
/// </summary>
public class SkiaAvatarProcessorTests
{
    private readonly SkiaAvatarProcessor _processor = new();

    // Three equal vertical bands: red | green | blue. A center square crop keeps only green.
    private static byte[] Bands(int width, int height, SKEncodedImageFormat format)
    {
        using var bitmap = new SKBitmap(width, height);
        using (var canvas = new SKCanvas(bitmap))
        {
            var band = width / 3f;
            using var paint = new SKPaint();
            paint.Color = SKColors.Red;
            canvas.DrawRect(0, 0, band, height, paint);
            paint.Color = SKColors.Lime;
            canvas.DrawRect(band, 0, band, height, paint);
            paint.Color = SKColors.Blue;
            canvas.DrawRect(2 * band, 0, band, height, paint);
        }

        using var data = bitmap.Encode(format, 95);
        return data.ToArray();
    }

    [Theory]
    [InlineData(SKEncodedImageFormat.Png)]
    [InlineData(SKEncodedImageFormat.Jpeg)]
    public void Accepted_formats_come_out_as_a_center_cropped_256_png(SKEncodedImageFormat format)
    {
        var output = _processor.ProcessToPng(Bands(600, 200, format));

        using var codec = SKCodec.Create(SKData.CreateCopy(output));
        Assert.Equal(SKEncodedImageFormat.Png, codec.EncodedFormat);

        using var avatar = SKBitmap.Decode(output);
        Assert.Equal(256, avatar.Width);
        Assert.Equal(256, avatar.Height);

        // Only the green middle band survives the crop; the red and blue sides are cut away.
        var center = avatar.GetPixel(128, 128);
        Assert.True(center.Green > 200 && center.Red < 60 && center.Blue < 60, $"center pixel was {center}");
        var edge = avatar.GetPixel(4, 128);
        Assert.True(edge.Green > 200 && edge.Red < 60, $"edge pixel was {edge}");
    }

    [Fact]
    public void Other_image_formats_are_refused()
    {
        var webp = Bands(60, 60, SKEncodedImageFormat.Webp);

        var ex = Assert.Throws<ProfileException>(() => _processor.ProcessToPng(webp));
        Assert.Contains("Only JPEG and PNG", ex.Message);
    }

    [Fact]
    public void Bytes_that_are_not_an_image_are_refused()
    {
        var ex = Assert.Throws<ProfileException>(() => _processor.ProcessToPng("<svg onload=alert(1)>"u8.ToArray()));
        Assert.Contains("could not be read as an image", ex.Message);
    }

    [Fact]
    public void A_truncated_image_is_refused_rather_than_stored_half_decoded()
    {
        var png = Bands(300, 300, SKEncodedImageFormat.Png);

        var ex = Assert.Throws<ProfileException>(() => _processor.ProcessToPng(png[..(png.Length / 2)]));
        Assert.Contains("could not be read as an image", ex.Message);
    }

    [Fact]
    public void An_oversized_canvas_is_refused_before_decoding()
    {
        // A tiny file declaring a huge canvas is the decompression-bomb shape.
        var wide = Bands(6001, 3, SKEncodedImageFormat.Png);

        var ex = Assert.Throws<ProfileException>(() => _processor.ProcessToPng(wide));
        Assert.Contains("must not exceed", ex.Message);
    }

    [Fact]
    public void An_empty_upload_is_refused()
    {
        var ex = Assert.Throws<ProfileException>(() => _processor.ProcessToPng([]));
        Assert.Contains("empty", ex.Message);
    }
}
