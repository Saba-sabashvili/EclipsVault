using QRCoder;

namespace EclipsVault.Web.Services;

/// <summary>
/// Renders the otpauth:// enrollment URI as a self-contained PNG data URI.
/// Generated in-process: the URI embeds the TOTP secret, so it must never
/// be sent to a third-party QR rendering service.
/// </summary>
public static class TotpQrCode
{
    public static string PngDataUri(string otpAuthUri)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(otpAuthUri, QRCodeGenerator.ECCLevel.M);
        using var png = new PngByteQRCode(data);
        return "data:image/png;base64," + Convert.ToBase64String(png.GetGraphic(pixelsPerModule: 4));
    }
}
