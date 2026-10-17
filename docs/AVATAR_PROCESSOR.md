# Avatar dependency repair for the supported-release backport

The v1.4.0 locked restore now fails its existing vulnerability gate on
`SixLabors.ImageSharp` 3.1.12 and the transitive `System.Security.Cryptography.Pkcs` 9.0.4.
No audit warning is suppressed. Patched ImageSharp packages introduce a license-key build task;
the narrowly scoped existing SkiaSharp adapter avoids adding that requirement to this release.

The replacement is **SkiaSharp 4.153.1**, with **SkiaSharp.NativeAssets.Linux.NoDependencies
4.153.1** for the Linux production image. Both NuGet package manifests declare **MIT** licenses;
native Skia includes its upstream third-party notices. Keep the package licenses and notices with
redistributed native assets. The PKCS dependency is centrally pinned to **10.0.13**. Lockfiles are
regenerated, and locked restore, release build and the transitive vulnerability audit remain gates.

Publishing copies the full upstream license and native notices from the locked packages into
`ThirdPartyNotices/SkiaSharp/LICENSE.txt` and `ThirdPartyNotices/SkiaSharp/THIRD-PARTY-NOTICES.txt`.
The root Dockerfile includes those files through its existing copy of the publish output. For the
pinned version, the MIT license and native notices are identical across the Linux, Windows and
macOS packages; one complete copy of each text covers the bundled Skia assets.

The complete ImageSharp surface at v1.4.0 was:

- `Media/ImageSharpAvatarProcessor.cs`: format identification, bounded decode, center crop, resize
  and PNG encoding. Replaced by `SkiaAvatarProcessor` behind the existing `IAvatarProcessor` port.
- `DependencyInjection.cs`: the single adapter registration, changed to the replacement.
- `EclipsVault.Infrastructure.csproj`, `Directory.Packages.props` and four consuming lockfiles:
  package references and resolved dependencies, changed to the pinned replacement.
- `README.md`: the architecture tree's adapter description, updated.

There were no other ImageSharp call sites. The profile service and controller still use the same
port, request validation, authorization and audit path.

The adapter still accepts detected JPEG/PNG only, caps uploads at 4 MiB and each source dimension
at 6000 pixels before pixel decode, produces a 256×256 center-cropped PNG, preserves transparency,
and re-encodes pixels without source metadata. Complete decode is required; malformed/truncated
inputs are refused. Disposable buffers and native resources are scoped with `using`.

`SkiaAvatarProcessorTests` covers valid JPEG/PNG and center cropping, transparency, unsupported
formats, non-images, truncated PNG, both dimension limits, the 6000-pixel boundary, empty input,
and input above 4 MiB. The replacement is included in the independent backport security review.
Image resampling may differ slightly between libraries; byte-identical avatar output is not promised.

Primary package metadata: [SkiaSharp](https://www.nuget.org/packages/SkiaSharp/4.153.1),
[Linux native assets](https://www.nuget.org/packages/SkiaSharp.NativeAssets.Linux.NoDependencies/4.153.1).
The local verification report retains the original failed restore and restored build/audit evidence.
