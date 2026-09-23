# Rebuild the two broken producers without changing the other thirteen SDKs.
# All network inputs have reviewed content identities. Restore and compilation
# run offline; the runtime packs are included in the archive closure as well.
FROM docker.io/minio/mint@sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200 AS sources
ADD --checksum=sha256:af08d0a1ffa13ea9a81023973994520f44b25ebc05176a8c4f6bede2a78a0326 https://codeload.github.com/minio/minio-dotnet/tar.gz/ac5dc79dfdd35b425f98233f55f8227aa705afb9 /source.tar.gz
COPY patch_producers.py fetch_packages.py dotnet-packages.json /recipe/
RUN mkdir /src && tar -xzf /source.tar.gz --strip-components=1 -C /src \
    && python3 /recipe/patch_producers.py logger /src/Minio.Functional.Tests/MintLogger.cs --sha256 05a923779553cc1850f30b6435718e984ff965c3ed7b03f1d595f60821c7378f \
    && python3 /recipe/patch_producers.py dotnet-runner /mint/run/core/.minio-dotnet/run.sh --sha256 850b06eee70ff4dfb551bb08c7db0406745d54e4990ec5fb37178d92927ead30 \
    && python3 /recipe/patch_producers.py mc /mint/run/core/mc/functional-tests.sh --sha256 9b98c8152b294d567b9bc732869226dd4f65d0f4d84092dc066a900a66a9e22c
RUN python3 /recipe/fetch_packages.py /recipe/dotnet-packages.json /feed

FROM mcr.microsoft.com/dotnet/sdk@sha256:79078151f7890e75b9015db9242d2c0a09c17794139fe841463fe6e6ab6d9a2d AS build
ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 NUGET_PACKAGES=/packages
WORKDIR /src
COPY --from=sources /src/ /src/
COPY --from=sources /feed/ /feed/
COPY dotnet-locks/Minio.json /src/Minio/packages.lock.json
COPY dotnet-locks/Minio.Functional.Tests.json /src/Minio.Functional.Tests/packages.lock.json
RUN --network=none dotnet restore Minio.Functional.Tests/Minio.Functional.Tests.csproj \
    --locked-mode --source /feed --runtime linux-x64 \
    -p:TargetFramework=net8.0 -p:TargetFrameworks=net8.0 -p:SelfContained=true
RUN --network=none dotnet publish Minio.Functional.Tests/Minio.Functional.Tests.csproj \
    --configuration Mint --framework net8.0 --runtime linux-x64 --self-contained true \
    --no-restore --output /out -p:TargetFrameworks=net8.0 -p:RestoreLockedMode=true

# The pinned Mint stage already supplies Python; the SDK stage does not.
FROM sources AS notices
COPY --from=build /out/ /out/
COPY collect_notices.py /recipe/collect_notices.py
COPY licenses/ /recipe/licenses/
RUN --network=none python3 /recipe/collect_notices.py /out /feed \
    /recipe/dotnet-packages.json /recipe/licenses /notices

FROM docker.io/minio/mint@sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200
COPY --from=build /out/ /opt/mint-dotnet/
COPY --from=sources /src/LICENSE /opt/mint-dotnet/LICENSE
COPY --from=notices /notices/ /opt/mint-dotnet/notices/
COPY --from=sources --chmod=755 /mint/run/core/.minio-dotnet/run.sh /mint/run/core/.minio-dotnet/run.sh
COPY --from=sources --chmod=755 /mint/run/core/mc/functional-tests.sh /mint/run/core/mc/functional-tests.sh
