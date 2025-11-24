FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["MockIdentityProvider.csproj", "."]
RUN dotnet restore "MockIdentityProvider.csproj"
COPY . .
WORKDIR "/src"
RUN dotnet build "MockIdentityProvider.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "MockIdentityProvider.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
ENV ASPNETCORE_URLS=http://0.0.0.0:8080
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "MockIdentityProvider.dll"]