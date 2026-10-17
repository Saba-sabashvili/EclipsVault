using System.Net;
using SkiaSharp;
using Xunit;

namespace EclipsVault.IntegrationTests;

[Collection(VaultCollection.Name)]
public sealed class AvatarUploadTests(VaultFixture vault)
{
    [Fact]
    public async Task Real_uploads_preserve_the_avatar_contract_and_refuse_invalid_inputs()
    {
        var admin = await vault.AdminClientAsync();
        byte[] stored = [];
        foreach (var format in new[] { SKEncodedImageFormat.Jpeg, SKEncodedImageFormat.Png })
        {
            await UploadAsync(admin, Image(60, 20, format));
            using var response = await admin.GetAsync("/Profile/Avatar");
            Assert.Equal("image/png", response.Content.Headers.ContentType?.MediaType);
            stored = await response.Content.ReadAsByteArrayAsync();
            using var avatar = SKBitmap.Decode(stored);
            Assert.Equal(256, avatar.Width);
            Assert.Equal(256, avatar.Height);
            var center = avatar.GetPixel(128, 128);
            Assert.True(center.Green > 200 && center.Red < 60 && center.Blue < 60);
        }

        var png = Image(60, 20, SKEncodedImageFormat.Png);
        foreach (var invalid in new[]
        {
            "not an image"u8.ToArray(),
            png[..(png.Length / 2)],
            Image(6001, 3, SKEncodedImageFormat.Png),
            new byte[4 * 1024 * 1024 + 1],
        })
        {
            await UploadAsync(admin, invalid);
            var retained = await admin.GetByteArrayAsync("/Profile/Avatar");
            Assert.True(stored.AsSpan().SequenceEqual(retained),
                "A refused upload must leave the valid avatar unchanged.");
        }
    }

    private static async Task UploadAsync(HttpClient client, byte[] bytes)
    {
        var token = VaultFixture.FormTokenOf(await client.GetStringAsync("/Profile"));
        using var form = new MultipartFormDataContent
        {
            { new StringContent(token), "__RequestVerificationToken" },
            { new ByteArrayContent(bytes), "avatar", "disposable-avatar.png" },
        };
        using var response = await client.PostAsync("/Profile/UploadAvatar", form);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/Profile", response.Headers.Location?.OriginalString);
    }

    private static byte[] Image(int width, int height, SKEncodedImageFormat format)
    {
        using var bitmap = new SKBitmap(width, height);
        bitmap.Erase(SKColors.Lime);
        using var data = bitmap.Encode(format, 95);
        return data.ToArray();
    }
}
