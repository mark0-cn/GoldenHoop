# Disposable interoperability fixture, not a production sandbox image.
# CI can restore public Maven artifacts through this named build context.
FROM scratch AS maven_seed

FROM rust:1-bookworm AS toolchain
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=3 update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends maven openjdk-17-jdk-headless xz-utils \
    && rm -rf /var/lib/apt/lists/*

FROM toolchain AS java
WORKDIR /sources
ADD --checksum=sha256:9397823b098f50f091707cb787d148e0494c62dbf57bd09bcfc6620de35f26c7 https://codeload.github.com/zeromq/jeromq/tar.gz/3908fe3dabcba4d3de98ed0a6b85553690a1e006 /tmp/jeromq.tar.gz
RUN mkdir jeromq && tar -xzf /tmp/jeromq.tar.gz -C jeromq --strip-components=1
WORKDIR /sources/jeromq
ARG MAVEN_OFFLINE=0
RUN --mount=type=bind,from=maven_seed,target=/maven-seed \
    test ! -e /root/.m2/repository \
    && mkdir -p /root/.m2/repository \
    && if [ -f /maven-seed/cache.tar ]; then \
        tar -xf /maven-seed/cache.tar -C /root/.m2/repository; \
       elif [ "$MAVEN_OFFLINE" = 1 ]; then \
        echo 'Offline fixture build requires the public Maven seed' >&2; exit 1; \
       fi \
    && case "$MAVEN_OFFLINE" in \
        0) mvn --batch-mode -DskipTests -Dmaven.javadoc.skip=true -Dcheckstyle.skip package ;; \
        1) mvn --offline --batch-mode -DskipTests -Dmaven.javadoc.skip=true -Dcheckstyle.skip package ;; \
        *) echo 'MAVEN_OFFLINE must be 0 or 1' >&2; exit 1 ;; \
       esac \
    && tar --exclude='*.lastUpdated' -cf /maven-cache.tar -C /root/.m2/repository .
WORKDIR /sources/ijava
ADD --checksum=sha256:484cc62579cb77510b0f0c78283f043794396d8ae9d76a8f2ab5d7368ec246b2 https://github.com/SpencerPark/IJava/releases/download/v1.3.0/ijava-1.3.0.zip /tmp/ijava.zip
RUN jar xf /tmp/ijava.zip

FROM scratch AS maven-cache-export
COPY --from=java /maven-cache.tar /cache.tar

FROM toolchain AS go
ADD --checksum=sha256:a21ae5633a269bcd7e90cf767e48225633795e99d831742cbf3397064fee7712 https://go.dev/dl/go1.25.14.linux-amd64.tar.gz /tmp/go.tar.gz
RUN tar -xzf /tmp/go.tar.gz -C /usr/local
ENV PATH="/usr/local/go/bin:${PATH}"
RUN --mount=type=cache,id=goldenhoop-fixture-go-mod,target=/go/pkg/mod \
    --mount=type=cache,id=goldenhoop-fixture-go-build,target=/root/.cache/go-build \
    GOBIN=/out go install github.com/gopherdata/gophernotes@v0.7.6

FROM toolchain AS node
ADD --checksum=sha256:4f2b175a6d53a5c617a80dba2676238a0688cef28c6da4eba35c7d844e66fcfb https://nodejs.org/dist/v24.22.3/node-v24.22.3-linux-x64.tar.xz /tmp/node.tar.xz
RUN tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1
RUN npm install --global --omit=dev --no-audit --no-fund tslab@1.0.19

FROM goldenhoop-agent:test AS agent

FROM debian:bookworm-slim
LABEL dev.goldenhoop.fixture="languages-interop"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Retries=3 update && apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
    python3-ipykernel python3-venv openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv --system-site-packages /opt/bash-kernel \
    && /opt/bash-kernel/bin/pip install --no-cache-dir --no-deps bash_kernel==0.10.0 filetype==1.2.0 \
    && groupadd --gid 1000 workload && useradd --uid 1000 --gid 1000 --no-create-home workload \
    && mkdir -p /workspace /run/goldenhoop && chown 1000:1000 /workspace && chmod 2770 /workspace
RUN apt-get -o Acquire::Retries=3 update \
    && apt-get -o Acquire::Retries=3 install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*
COPY --from=java /sources/ijava/java/ /opt/ijava/
# This pinned upstream multi-release build supplies real Java 16+ Unix IPC.
# Released older JeroMQ versions map ipc:// to TCP and cannot pass our gate.
COPY --from=java /sources/jeromq/jeromq/target/jeromq-0.7.0-SNAPSHOT.jar /opt/ijava/jeromq-ipc.jar
COPY --from=java /sources/jeromq/LICENSE /opt/ijava/JeroMQ-LICENSE
COPY --from=go /out/gophernotes /usr/local/bin/gophernotes
COPY --from=go /usr/local/go/ /usr/local/go/
RUN ln -s /usr/local/go/bin/go /usr/local/bin/go
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/tslab/ /opt/tslab/
COPY images/languages/kernels/ /usr/local/share/jupyter/kernels/
COPY --from=agent /usr/local/bin/goldenhoop-agent /usr/local/bin/goldenhoop-agent
ENV GOLDENHOOP_ISOLATED_AGENT=1
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/goldenhoop-agent", "serve"]
