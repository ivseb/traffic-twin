# Red team round 3: ASP.NET Core 8 minimal API + traffic-twin .NET startup hook
# (init image deploy/images/sdk-dotnet; DOTNET_STARTUP_HOOKS +
# ASPNETCORE_HOSTINGSTARTUPASSEMBLIES as the injector sets them).
# Build: test/redteam/frameworks/build_images.sh dotnet
FROM mcr.microsoft.com/dotnet/sdk:8.0@sha256:738f72aff955d5c5690e06b6fc8ecd1b90ead564099a257ac528ff720b8da85f AS build
WORKDIR /src
COPY test/redteam/frameworks/dotnet/app.csproj ./
RUN dotnet restore --nologo
COPY test/redteam/frameworks/dotnet/Program.cs ./
RUN dotnet publish -c Release -o /out --no-restore --nologo

FROM mcr.microsoft.com/dotnet/aspnet:8.0
COPY --from=rt3fw-sdk-dotnet:local /sdk/dotnet /tt/sdk/dotnet
COPY --from=build /out /app
# The aspnet image already has the non-root user "app".
RUN install -d -o app -g app -m 0700 /var/lib/tt-state
USER app
WORKDIR /app
ENV DOTNET_STARTUP_HOOKS=/tt/sdk/dotnet/TrafficTwin.StartupHook.dll \
    ASPNETCORE_HOSTINGSTARTUPASSEMBLIES=TrafficTwin.Sdk.AspNetCore \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    Logging__LogLevel__Default=Information \
    Logging__LogLevel__Microsoft.AspNetCore=Warning
# Microsoft.AspNetCore at Warning, as in the default appsettings.json of the
# templates: at Information the hosting diagnostics log the full URL (the
# framework's own access log, not the SDK's), which here carries canaries.
EXPOSE 8080
CMD ["dotnet", "app.dll"]
