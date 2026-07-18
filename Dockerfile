# Multi-stage production image for EclipsVault.Web. TLS is expected to terminate at a reverse
# proxy / ingress (see docs/INSTALL.md); the app listens on plain HTTP inside the network.
#
# Supply-chain note: the docker-compose file pins every image to a digest, and this image should too.
# The tags below are a starting point — pin them once, in your registry, with:
#   docker pull mcr.microsoft.com/dotnet/sdk:10.0
#   docker inspect --format='{{index .RepoDigests 0}}' mcr.microsoft.com/dotnet/sdk:10.0
#   docker pull mcr.microsoft.com/dotnet/aspnet:10.0
#   docker inspect --format='{{index .RepoDigests 0}}' mcr.microsoft.com/dotnet/aspnet:10.0
# then rewrite each FROM as `...:10.0@sha256:<resolved>`.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet restore EclipsVault.Web/EclipsVault.Web.csproj --locked-mode
RUN dotnet publish EclipsVault.Web/EclipsVault.Web.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app .

# Run as a non-root user.
RUN adduser --disabled-password --gecos "" --uid 10001 vault \
    && chown -R vault /app
USER vault

ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "EclipsVault.Web.dll"]
