# syntax=docker/dockerfile:1
#
# SDK init image for .NET 8+. The pod webhook (tt injector) runs it as an init container: it copies /sdk
# into the shared emptyDir (/tt/sdk) and exits. Layout, copied into /tt/sdk/dotnet:
#   TrafficTwin.StartupHook.dll        DOTNET_STARTUP_HOOKS entry point
#   TrafficTwin.Sdk.dll                the SDK (no dependencies beyond the BCL)
#   TrafficTwin.Sdk.AspNetCore.dll     hosting startup: middleware + IHttpClientFactory handler
# The application starts with
#   DOTNET_STARTUP_HOOKS=/tt/sdk/dotnet/TrafficTwin.StartupHook.dll
#   ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=TrafficTwin.Sdk.AspNetCore
# and needs no reference to any of these assemblies.
#
# Build from the repository root:
#   docker build -f deploy/images/sdk-dotnet/Dockerfile -t ghcr.io/ivseb/traffic-twin/sdk-dotnet:0.1.0 .
#
# Base images are pinned by digest; bump tag and digest together.

FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:8.0@sha256:738f72aff955d5c5690e06b6fc8ecd1b90ead564099a257ac528ff720b8da85f AS build
WORKDIR /src/sdk/dotnet
COPY sdk/dotnet/Directory.Build.props ./
COPY sdk/dotnet/src src
RUN dotnet publish src/TrafficTwin.StartupHook/TrafficTwin.StartupHook.csproj -c Release -o /out \
      -p:DebugType=none -p:DebugSymbols=false -p:GenerateDocumentationFile=false --nologo \
 && rm -f /out/*.deps.json /out/*.pdb

FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092
LABEL org.opencontainers.image.title="traffic-twin sdk-dotnet (init image)" \
      org.opencontainers.image.source="https://github.com/ivseb/traffic-twin" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/ /sdk/dotnet/
USER 65532:65532
ENTRYPOINT ["cp", "-R", "/sdk/.", "/tt/sdk/"]
