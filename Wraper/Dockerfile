FROM mcr.microsoft.com/dotnet/runtime:6.0 AS base
WORKDIR /app

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["Wraper/Wraper.csproj", "Wraper/"]
RUN dotnet restore "Wraper/Wraper.csproj"
COPY . .
WORKDIR "/src/Wraper"
RUN dotnet build "Wraper.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Wraper.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Wraper.dll"]
