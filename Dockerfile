# Multi-stage production image for EclipsVault.Web. TLS is expected to terminate at a reverse
# proxy / ingress (see docs/INSTALL.md); the app listens on plain HTTP inside the network.
#
# Supply-chain note: both base images are pinned to a digest (the human-readable tag is kept
# alongside for clarity). A floating tag means the image that builds tomorrow is not the one you
# tested, and a supply-chain compromise would arrive with nothing in the diff — the same reasoning
# docker-compose.yml applies to its own images. To move to a newer .NET patch, re-resolve and
# replace both digests:
#   docker buildx imagetools inspect mcr.microsoft.com/dotnet/sdk:10.0     # copy the Digest: line
#   docker buildx imagetools inspect mcr.microsoft.com/dotnet/aspnet:10.0
# Digests below pinned 2026-07-19.
FROM mcr.microsoft.com/dotnet/sdk:10.0@sha256:ed034a8bf0b24ded0cbbac07e17825d8e9ebfe21e308191d0f7421eaf5ad4664 AS build
WORKDIR /src
COPY . .
RUN dotnet restore EclipsVault.Web/EclipsVault.Web.csproj --locked-mode
RUN dotnet publish EclipsVault.Web/EclipsVault.Web.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0@sha256:1fa23fc4872d95fd71c2833ebe65d7e84a43b2d51a31d119516852f13d9505a7 AS runtime
WORKDIR /app

# Run as a non-root user. Use the `app` account the base image already ships (its UID is published
# as $APP_UID, currently 1654) rather than creating one: this image carries a shell but no `adduser`
# binary, so the previous `adduser ... --uid 10001 vault` failed with exit 127 and no image could be
# built at all. The image's own User field is unset, so declaring USER here is what actually drops
# root — without it the vault runs as root.
#
# Ownership is set during the copy instead of by a later `chown -R`, which would duplicate the whole
# publish output into a second layer for nothing.
COPY --from=build --chown=$APP_UID:$APP_UID /app .
USER $APP_UID

ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "EclipsVault.Web.dll"]
